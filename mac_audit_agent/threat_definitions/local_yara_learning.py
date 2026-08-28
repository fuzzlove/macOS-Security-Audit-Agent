"""Explainable, offline YARA candidate learning from an untrusted local corpus.

Samples are read as inert bytes. This module never imports, executes, mounts,
extracts, or launches corpus content, and generated candidates are never active
until an administrator separately reviews and promotes them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso

from .signing import canonical_json

SCHEMA_VERSION = "1.0"
MODEL_VERSION = "explainable-string-tfidf-jaccard-1.0"
_PRINTABLE = re.compile(rb"[\x20-\x7e]{8,160}")
_GENERIC = {
    "copyright", "version", "application", "framework", "library", "program",
    "foundation", "localhost", "true", "false", "null", "error", "warning",
    "usage", "help", "unknown", "system", "private", "public", "apple",
}


@dataclass(frozen=True)
class LocalYaraLearningPolicy:
    maximum_files: int = 2500
    maximum_total_file_bytes: int = 8 * 1024 * 1024 * 1024
    maximum_single_file_bytes: int = 1024 * 1024 * 1024
    sampled_bytes_per_file: int = 2 * 1024 * 1024
    minimum_string_length: int = 8
    maximum_strings_per_sample: int = 4000
    maximum_features_per_rule: int = 12
    minimum_family_samples_for_definition: int = 2
    minimum_family_prevalence: float = 0.60
    maximum_other_family_prevalence: float = 0.15
    cluster_similarity_threshold: float = 0.12

    def validated(self) -> LocalYaraLearningPolicy:
        if not 1 <= self.maximum_files <= 100_000:
            raise ValueError("maximum_files must be between 1 and 100000")
        if not 1024 <= self.sampled_bytes_per_file <= 16 * 1024 * 1024:
            raise ValueError("sampled_bytes_per_file must be between 1 KiB and 16 MiB")
        if not 2 <= self.maximum_features_per_rule <= 32:
            raise ValueError("maximum_features_per_rule must be between 2 and 32")
        if not 0 < self.minimum_family_prevalence <= 1:
            raise ValueError("minimum_family_prevalence must be between 0 and 1")
        if not 0 <= self.maximum_other_family_prevalence < 1:
            raise ValueError("maximum_other_family_prevalence must be between 0 and 1")
        return self


@dataclass(frozen=True)
class CorpusSample:
    sample_id: str
    family: str
    relative_path_hash: str
    sha256: str
    size: int
    format_hint: str
    strings: tuple[str, ...]


@dataclass(frozen=True)
class LearnedCandidate:
    candidate_id: str
    rule_name: str
    family: str
    classification: str
    confidence: float
    sample_count: int
    cluster_count: int
    format_hint: str
    features: tuple[str, ...]
    feature_scores: tuple[float, ...]
    source_sample_ids: tuple[str, ...]
    yara_source: str
    review_required: bool = True
    automatically_active: bool = False


def _safe_family(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_.-")[:80]
    return clean or "unclassified"


def _format_hint(prefix: bytes, suffix: str) -> str:
    if prefix.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
        return "mach-o"
    if prefix.startswith(b"PK\x03\x04"):
        return "zip-container"
    if prefix.startswith(b"\x1f\x8b"):
        return "gzip-container"
    if prefix.startswith(b"xar!"):
        return "xar-package"
    if prefix.startswith(b"koly") or suffix in {".dmg", ".pkg", ".ipa", ".jar", ".zip", ".gz", ".gzip", ".tar"}:
        return "opaque-container"
    if prefix.startswith(b"#!"):
        return "script"
    if prefix.lstrip().startswith((b"<?xml", b"<plist")):
        return "plist-or-xml"
    return "data"


def _sample_windows(path: Path, size: int, budget: int) -> bytes:
    chunk = max(512, budget // 3)
    offsets = (0, max(0, size // 2 - chunk // 2), max(0, size - chunk))
    output = bytearray()
    with path.open("rb", buffering=0) as handle:
        for offset in dict.fromkeys(offsets):
            handle.seek(offset)
            output.extend(handle.read(min(chunk, budget - len(output))))
            if len(output) >= budget:
                break
    return bytes(output[:budget])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_string(raw: bytes, *, minimum: int) -> str | None:
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if len(value) < minimum or len(value) > 160 or not any(character.isalpha() for character in value):
        return None
    lowered = value.lower()
    if lowered in _GENERIC or any(lowered == item or lowered.startswith(item + " ") for item in _GENERIC):
        return None
    if re.search(r"(?i)(password|passwd|token|secret|authorization|bearer|api[_ -]?key)\s*[:=]", value):
        return None
    if sum(character.isprintable() for character in value) / len(value) < 0.98:
        return None
    return value


def _extract_strings(data: bytes, policy: LocalYaraLearningPolicy) -> tuple[str, ...]:
    observed: dict[str, None] = {}
    for match in _PRINTABLE.finditer(data):
        value = _candidate_string(match.group(), minimum=policy.minimum_string_length)
        if value:
            observed.setdefault(value, None)
        if len(observed) >= policy.maximum_strings_per_sample:
            break
    return tuple(observed)


def inventory_corpus(root: Path, policy: LocalYaraLearningPolicy) -> tuple[list[CorpusSample], dict[str, Any]]:
    policy = policy.validated()
    corpus = Path(root).expanduser()
    if corpus.is_symlink() or not corpus.is_dir():
        raise ValueError("corpus root must be an existing non-symlink directory")
    corpus = corpus.resolve()
    paths: list[Path] = []
    skipped = Counter()
    total_bytes = 0
    for directory, names, filenames in os.walk(corpus, followlinks=False):
        names[:] = sorted(name for name in names if not (Path(directory) / name).is_symlink())
        for filename in sorted(filenames):
            path = Path(directory) / filename
            try:
                info = path.lstat()
            except OSError:
                skipped["stat_failed"] += 1
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                skipped["not_regular"] += 1
                continue
            if path.name.lower() in {"readme.txt", "readme.md", ".ds_store"}:
                skipped["documentation"] += 1
                continue
            if info.st_size <= 0 or info.st_size > policy.maximum_single_file_bytes:
                skipped["size_policy"] += 1
                continue
            if len(paths) >= policy.maximum_files or total_bytes + info.st_size > policy.maximum_total_file_bytes:
                skipped["budget"] += 1
                continue
            paths.append(path)
            total_bytes += info.st_size
    samples: list[CorpusSample] = []
    errors = Counter()
    seen_sha256: set[str] = set()
    for path in paths:
        try:
            relative = path.relative_to(corpus)
            info = path.stat()
            family = _safe_family(relative.parts[0] if len(relative.parts) > 1 else "unclassified")
            data = _sample_windows(path, info.st_size, policy.sampled_bytes_per_file)
            digest = _sha256(path)
            if digest in seen_sha256:
                skipped["duplicate_sha256"] += 1
                continue
            seen_sha256.add(digest)
            sample_id = "sample-" + digest[:16]
            samples.append(CorpusSample(
                sample_id=sample_id,
                family=family,
                relative_path_hash=hashlib.sha256(str(relative).encode("utf-8", "surrogateescape")).hexdigest(),
                sha256=digest,
                size=info.st_size,
                format_hint=_format_hint(data[:16], path.suffix.lower()),
                strings=_extract_strings(data, policy),
            ))
        except (OSError, ValueError):
            errors["read_failed"] += 1
    return samples, {
        "corpus_path_persisted": False,
        "files_selected": len(paths),
        "samples_read": len(samples),
        "unique_sha256": len(seen_sha256),
        "total_file_bytes": total_bytes,
        "sampled_byte_budget_per_file": policy.sampled_bytes_per_file,
        "skipped": dict(skipped),
        "errors": dict(errors),
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _clusters(samples: list[CorpusSample], threshold: float) -> list[list[CorpusSample]]:
    groups: list[list[CorpusSample]] = []
    for sample in samples:
        features = set(sample.strings)
        target = next((group for group in groups if _jaccard(features, set(group[0].strings)) >= threshold), None)
        if target is None:
            groups.append([sample])
        else:
            target.append(sample)
    return groups


def _feature_quality(value: str) -> bool:
    if len(value) < 8 or len(value) > 120:
        return False
    if value.count(" ") > 12 or value.count("/") > 8:
        return False
    lowered = value.lower()
    if lowered.startswith(("<key>", "<string>", "<?xml", "/system/library/frameworks/")):
        return False
    if "developer id certification authority" in lowered or "apple root ca" in lowered:
        return False
    if re.fullmatch(r"[0-9._-]+(?:class|dylib|framework|bundle|plist|nib|strings)", lowered):
        return False
    alphanumeric_ratio = sum(character.isalnum() for character in value) / len(value)
    alphabetic_ratio = sum(character.isalpha() for character in value) / len(value)
    if alphanumeric_ratio < 0.62 or alphabetic_ratio < 0.35:
        return False
    unique_ratio = len(set(value.lower())) / max(1, len(value))
    return 0.12 <= unique_ratio <= 0.95


def _escape_yara(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _format_condition(format_hint: str) -> str:
    return {
        "mach-o": "(uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32be(0) == 0xcafebabe)",
        "zip-container": "uint32be(0) == 0x504b0304",
        "gzip-container": "uint16be(0) == 0x1f8b",
        "xar-package": "uint32be(0) == 0x78617221",
        "script": "uint16be(0) == 0x2321",
    }.get(format_hint, "true")


def _learn_candidates(
    samples: list[CorpusSample],
    policy: LocalYaraLearningPolicy,
    *,
    forbidden_features: frozenset[str] = frozenset(),
) -> list[LearnedCandidate]:
    if not samples:
        return []
    global_df: Counter[str] = Counter()
    family_samples: dict[str, list[CorpusSample]] = defaultdict(list)
    for sample in samples:
        family_samples[sample.family].append(sample)
        global_df.update(set(sample.strings))
    total = len(samples)
    learned: list[LearnedCandidate] = []
    for family, members in sorted(family_samples.items()):
        for cluster_index, cluster in enumerate(_clusters(members, policy.cluster_similarity_threshold), 1):
            local_df: Counter[str] = Counter()
            for sample in cluster:
                local_df.update(set(sample.strings))
            scored: list[tuple[float, str]] = []
            for feature, frequency in local_df.items():
                if feature in forbidden_features or not _feature_quality(feature):
                    continue
                family_prevalence = frequency / len(cluster)
                outside = max(0, global_df[feature] - frequency)
                outside_prevalence = outside / max(1, total - len(cluster))
                if family_prevalence < policy.minimum_family_prevalence or outside_prevalence > policy.maximum_other_family_prevalence:
                    continue
                inverse_document_frequency = math.log((total + 1) / (global_df[feature] + 1)) + 1
                score = family_prevalence * inverse_document_frequency * (1 - outside_prevalence)
                scored.append((score, feature))
            selected = sorted(scored, key=lambda item: (-item[0], item[1]))[: policy.maximum_features_per_rule]
            if len(selected) < 2:
                continue
            enough_samples = len(cluster) >= policy.minimum_family_samples_for_definition
            classification = "DEFINITION_CANDIDATE" if enough_samples and len(selected) >= 3 else "SUSPICIOUS_CANDIDATE"
            confidence = min(0.94 if enough_samples else 0.69, 0.45 + 0.08 * len(selected) + 0.03 * min(len(cluster), 5))
            token = hashlib.sha256((family + "\0" + "\0".join(value for _score, value in selected)).encode()).hexdigest()[:12]
            rule_name = f"MSAA_Local_{_safe_family(family).replace('.', '_').replace('-', '_')}_{cluster_index}_{token}"
            string_lines = "\n".join(
                f'    $s{index:02d} = "{_escape_yara(value)}" ascii wide'
                for index, (_score, value) in enumerate(selected, 1)
            )
            threshold_count = min(3 if classification == "DEFINITION_CANDIDATE" else 2, len(selected))
            format_hints = {sample.format_hint for sample in cluster}
            format_hint = next(iter(format_hints)) if len(format_hints) == 1 else "mixed"
            source = (
                f"rule {rule_name} {{\n"
                "  meta:\n"
                f'    description = "Locally learned {classification.lower().replace("_", " ")}; analyst review required"\n'
                f'    family = "{_escape_yara(family)}"\n'
                f'    msaa_model = "{MODEL_VERSION}"\n'
                f'    msaa_confidence = "{confidence:.2f}"\n'
                f'    msaa_format_hint = "{format_hint}"\n'
                '    msaa_automatic_activation = "false"\n'
                "  strings:\n"
                f"{string_lines}\n"
                "  condition:\n"
                f"    filesize < 1073741824 and {_format_condition(format_hint)} and {threshold_count} of ($s*)\n"
                "}\n"
            )
            learned.append(LearnedCandidate(
                candidate_id="local-yara-" + token,
                rule_name=rule_name,
                family=family,
                classification=classification,
                confidence=round(confidence, 3),
                sample_count=len(cluster),
                cluster_count=cluster_index,
                format_hint=format_hint,
                features=tuple(value for _score, value in selected),
                feature_scores=tuple(round(score, 6) for score, _value in selected),
                source_sample_ids=tuple(sorted(sample.sample_id for sample in cluster)),
                yara_source=source,
            ))
    return learned


def _compile_candidates(
    candidates: list[LearnedCandidate],
    *,
    benign_controls: tuple[bytes, ...] = (),
) -> tuple[list[LearnedCandidate], list[dict[str, str]]]:
    try:
        import yara
    except (ImportError, OSError) as exc:
        return [], [{"candidate_id": "*", "error_type": type(exc).__name__}]
    accepted: list[LearnedCandidate] = []
    rejected: list[dict[str, str]] = []
    for candidate in candidates:
        try:
            compiled = yara.compile(source=candidate.yara_source)
            for control in (
                b"MSAA harmless local YARA learning control",
                b"#!/bin/zsh\necho harmless\n",
                b"<?xml version='1.0'?><plist><dict/></plist>",
                *benign_controls,
            ):
                if compiled.match(data=control, timeout=2):
                    raise ValueError("benign_control_match")
            accepted.append(candidate)
        except Exception as exc:  # noqa: BLE001 - backend-specific compile errors are summarized
            rejected.append({"candidate_id": candidate.candidate_id, "error_type": type(exc).__name__})
    return accepted, rejected


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _default_candidate_store() -> Path:
    return Path.home() / "Library" / "Application Support" / "MSAA" / "YaraCandidates"


def learn_local_yara_candidates(
    corpus_root: Path,
    output_root: Path | None = None,
    *,
    benign_root: Path | None = None,
    policy: LocalYaraLearningPolicy | None = None,
) -> dict[str, Any]:
    """Analyze inert bytes and atomically write an immutable review-only run."""
    effective = (policy or LocalYaraLearningPolicy()).validated()
    corpus = Path(corpus_root).expanduser().resolve()
    candidate_store = Path(output_root or _default_candidate_store()).expanduser()
    if candidate_store.exists() and candidate_store.is_symlink():
        raise ValueError("output root may not be a symlink")
    candidate_store = candidate_store.resolve()
    if candidate_store == corpus or _is_within(candidate_store, corpus):
        raise ValueError("candidate output must be outside the untrusted corpus")
    benign = Path(benign_root).expanduser().resolve() if benign_root is not None else None
    if benign is not None and (benign == corpus or _is_within(benign, corpus) or _is_within(corpus, benign)):
        raise ValueError("benign controls must be separate from the untrusted corpus")

    candidate_store.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(candidate_store, 0o700)
    generated_at = utc_now_iso()
    run_id = "local-" + re.sub(r"[^0-9]", "", generated_at)[:14] + "-" + secrets.token_hex(4)
    staging = candidate_store / (".staging-" + run_id)
    output = candidate_store / run_id
    staging.mkdir(mode=0o700)

    samples, inventory = inventory_corpus(corpus, effective)
    benign_samples: list[CorpusSample] = []
    benign_inventory: dict[str, Any] | None = None
    if benign is not None:
        benign_samples, benign_inventory = inventory_corpus(benign, effective)
    benign_features = frozenset(feature for sample in benign_samples for feature in sample.strings)
    # Reuse already minimized, in-memory features as controls; no benign path or
    # content is persisted in the run manifest.
    benign_controls = tuple(
        "\n".join(sample.strings).encode("utf-8", "replace")
        for sample in benign_samples
        if sample.strings
    )
    candidates, rejected = _compile_candidates(
        _learn_candidates(samples, effective, forbidden_features=benign_features),
        benign_controls=benign_controls,
    )
    candidate_dir = staging / "candidates"
    candidate_dir.mkdir(mode=0o700, exist_ok=True)
    for candidate in candidates:
        path = candidate_dir / f"{candidate.candidate_id}.yar"
        path.write_text(candidate.yara_source, encoding="utf-8", newline="\n")
        os.chmod(path, 0o600)
    combined_artifacts: dict[str, str] = {}
    for classification, filename in (
        ("DEFINITION_CANDIDATE", "definition_candidates.yar"),
        ("SUSPICIOUS_CANDIDATE", "suspicious_candidates.yar"),
    ):
        content = "\n".join(
            candidate.yara_source for candidate in candidates
            if candidate.classification == classification
        )
        if content:
            combined = staging / filename
            combined.write_text(content, encoding="utf-8", newline="\n")
            os.chmod(combined, 0o600)
            combined_artifacts[filename] = hashlib.sha256(content.encode()).hexdigest()
    hashes = staging / "local-corpus-sha256.jsonl"
    with hashes.open("w", encoding="utf-8", newline="\n") as handle:
        for sample in samples:
            handle.write(json.dumps({
                "sample_id": sample.sample_id, "sha256": sample.sha256,
                "family": sample.family, "classification": "LOCAL_UNVERIFIED_CORPUS",
                "active": False, "review_required": True,
            }, sort_keys=True) + "\n")
    os.chmod(hashes, 0o600)
    hash_list = staging / "sha256_candidates.txt"
    hash_list.write_text("".join(f"{sample.sha256}\n" for sample in samples), encoding="ascii", newline="\n")
    os.chmod(hash_list, 0o600)
    combined_artifacts[hashes.name] = _sha256(hashes)
    combined_artifacts[hash_list.name] = _sha256(hash_list)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "operation": "local_yara_candidate_learning",
        "inventory": inventory,
        "benign_control_inventory": (
            {
                "configured": True,
                "samples_read": len(benign_samples),
                "feature_count": len(benign_features),
                "corpus_path_persisted": False,
                "errors": (benign_inventory or {}).get("errors", {}),
            }
            if benign is not None
            else {"configured": False, "samples_read": 0, "feature_count": 0, "corpus_path_persisted": False}
        ),
        "policy": asdict(effective),
        "sample_count": len(samples),
        "family_count": len({sample.family for sample in samples}),
        "candidate_count": len(candidates),
        "definition_candidate_count": sum(item.classification == "DEFINITION_CANDIDATE" for item in candidates),
        "suspicious_candidate_count": sum(item.classification == "SUSPICIOUS_CANDIDATE" for item in candidates),
        "rejected_candidate_count": len(rejected),
        "rejected": rejected,
        "artifact_hashes": combined_artifacts,
        "candidates": [
            {key: value for key, value in asdict(candidate).items() if key != "yara_source"}
            | {"yara_sha256": hashlib.sha256(candidate.yara_source.encode()).hexdigest()}
            for candidate in candidates
        ],
        "safety": {
            "samples_executed": False,
            "archives_extracted": False,
            "disk_images_mounted": False,
            "network_access": False,
            "automatic_activation": False,
            "analyst_review_required": True,
        },
        "qualification": "Statistical similarity is evidence for review, not proof of malware family identity or malicious intent.",
        "quality_warnings": (
            [] if benign is not None
            else ["NO_KNOWN_GOOD_CORPUS: cross-family controls were applied, but representative benign files were not supplied."]
        ),
    }
    manifest["manifest_sha256"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    manifest_path = staging / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest) + b"\n")
    os.chmod(manifest_path, 0o600)
    os.replace(staging, output)
    final_manifest = output / "manifest.json"
    return {**manifest, "output_root": str(output), "manifest_path": str(final_manifest)}


def verify_local_yara_run(run_root: Path) -> dict[str, Any]:
    """Verify a local candidate run's manifest, artifacts, rules, and safety flags."""
    run = Path(run_root).expanduser()
    if run.is_symlink() or not run.is_dir():
        raise ValueError("candidate run must be an existing non-symlink directory")
    run = run.resolve()
    manifest_path = run / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("candidate manifest is missing, linked, or oversized")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise TypeError("candidate manifest must be a JSON object")
    claimed_manifest_hash = str(document.pop("manifest_sha256", ""))
    actual_manifest_hash = hashlib.sha256(canonical_json(document)).hexdigest()
    if claimed_manifest_hash != actual_manifest_hash:
        raise ValueError("candidate manifest integrity mismatch")
    safety = document.get("safety", {})
    if not isinstance(safety, dict) or safety.get("automatic_activation") is not False or safety.get("analyst_review_required") is not True:
        raise ValueError("candidate safety policy is invalid")
    verified_artifacts = 0
    for relative_name, expected_hash in dict(document.get("artifact_hashes", {})).items():
        if Path(str(relative_name)).name != relative_name:
            raise ValueError("candidate artifact name is unsafe")
        artifact = run / relative_name
        if artifact.is_symlink() or not artifact.is_file() or _sha256(artifact) != expected_hash:
            raise ValueError(f"candidate artifact integrity mismatch: {relative_name}")
        verified_artifacts += 1
    candidate_dir = run / "candidates"
    verified_rules = 0
    for candidate in document.get("candidates", []):
        if not isinstance(candidate, dict):
            raise TypeError("candidate record is malformed")
        candidate_id = str(candidate.get("candidate_id", ""))
        if not re.fullmatch(r"local-yara-[0-9a-f]{12}", candidate_id):
            raise ValueError("candidate identifier is unsafe")
        rule_path = candidate_dir / f"{candidate_id}.yar"
        if rule_path.is_symlink() or not rule_path.is_file() or _sha256(rule_path) != candidate.get("yara_sha256"):
            raise ValueError(f"candidate rule integrity mismatch: {candidate_id}")
        verified_rules += 1
    try:
        import yara
    except (ImportError, OSError) as exc:
        raise ValueError(f"YARA compiler unavailable: {type(exc).__name__}") from exc
    compiled_packs = 0
    for filename in ("definition_candidates.yar", "suspicious_candidates.yar"):
        path = run / filename
        if path.is_file():
            yara.compile(filepath=str(path))
            compiled_packs += 1
    return {
        "status": "VALID",
        "run_id": document.get("run_id"),
        "model_version": document.get("model_version"),
        "manifest_sha256": actual_manifest_hash,
        "verified_artifacts": verified_artifacts,
        "verified_rules": verified_rules,
        "compiled_rule_packs": compiled_packs,
        "automatic_activation": False,
        "analyst_review_required": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Learn review-only local YARA candidates from inert corpus bytes.")
    parser.add_argument("corpus", type=Path)
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Candidate store (default: ~/Library/Application Support/MSAA/YaraCandidates)",
    )
    parser.add_argument(
        "--benign-corpus", type=Path, default=None,
        help="Optional separate benign corpus used only for negative feature/control testing",
    )
    parser.add_argument("--maximum-files", type=int, default=2500)
    parser.add_argument("--sample-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    policy = LocalYaraLearningPolicy(
        maximum_files=args.maximum_files,
        sampled_bytes_per_file=args.sample_bytes,
    )
    result = learn_local_yara_candidates(
        args.corpus, args.output, benign_root=args.benign_corpus, policy=policy,
    )
    summary = {
        key: result[key] for key in (
            "operation", "model_version", "sample_count", "family_count",
            "candidate_count", "definition_candidate_count",
            "suspicious_candidate_count", "rejected_candidate_count",
            "manifest_path", "safety", "qualification", "quality_warnings",
        )
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if result["candidate_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CorpusSample", "LearnedCandidate", "LocalYaraLearningPolicy",
    "inventory_corpus", "learn_local_yara_candidates", "main", "verify_local_yara_run",
]
