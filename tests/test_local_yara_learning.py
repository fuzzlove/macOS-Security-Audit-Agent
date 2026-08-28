from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from mac_audit_agent.threat_definitions.cli import main as definitions_cli_main
from mac_audit_agent.threat_definitions.local_yara_learning import (
    LocalYaraLearningPolicy,
    inventory_corpus,
    learn_local_yara_candidates,
    verify_local_yara_run,
)

SHARED = (
    "com.example.macos.loader.signal",
    "unique_dispatch_marker_74c1",
    "persistence_sequence_marker_18f2",
    "network_beacon_format_marker_63d9",
)


def _sample(path: Path, *values: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xcf\xfa\xed\xfe\x00\x00\x00\x00" + "\n".join(values).encode("ascii"))


def _policy(**updates: object) -> LocalYaraLearningPolicy:
    values = {
        "maximum_files": 20,
        "sampled_bytes_per_file": 4096,
        "minimum_family_prevalence": 0.5,
    }
    values.update(updates)
    return LocalYaraLearningPolicy(**values)


def test_learns_compiled_review_only_definition_candidate(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED, "variant_alpha_one_marker")
    _sample(corpus / "FamilyAlpha" / "two.bin", *SHARED, "variant_alpha_two_marker")

    result = learn_local_yara_candidates(corpus, tmp_path / "candidate-store", policy=_policy())

    assert result["definition_candidate_count"] == 1
    assert result["suspicious_candidate_count"] == 0
    assert result["safety"] == {
        "samples_executed": False,
        "archives_extracted": False,
        "disk_images_mounted": False,
        "network_access": False,
        "automatic_activation": False,
        "analyst_review_required": True,
    }
    candidate = result["candidates"][0]
    assert candidate["classification"] == "DEFINITION_CANDIDATE"
    assert candidate["review_required"] is True
    assert candidate["automatically_active"] is False
    run = Path(result["output_root"])
    assert run.name.startswith("local-")
    assert (run / "manifest.json").is_file()
    assert len(list((run / "candidates").glob("*.yar"))) == 1
    assert stat_mode(run / "manifest.json") == 0o600


def test_single_sample_is_only_suspicious_candidate(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _sample(corpus / "Unclassified" / "one.bin", *SHARED)

    result = learn_local_yara_candidates(corpus, tmp_path / "out", policy=_policy())

    assert result["candidate_count"] == 1
    assert result["definition_candidate_count"] == 0
    assert result["suspicious_candidate_count"] == 1
    assert result["candidates"][0]["classification"] == "SUSPICIOUS_CANDIDATE"


def test_hashes_are_exact_but_remain_inactive_and_unverified(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    target = corpus / "FamilyAlpha" / "one.bin"
    _sample(target, *SHARED)

    result = learn_local_yara_candidates(corpus, tmp_path / "out", policy=_policy())
    line = json.loads((Path(result["output_root"]) / "local-corpus-sha256.jsonl").read_text().strip())

    assert line["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert line["classification"] == "LOCAL_UNVERIFIED_CORPUS"
    assert line["active"] is False
    assert line["review_required"] is True


def test_benign_corpus_removes_shared_features(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    benign = tmp_path / "benign"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED)
    _sample(corpus / "FamilyAlpha" / "two.bin", *SHARED)
    _sample(benign / "KnownGood" / "control.bin", *SHARED)

    result = learn_local_yara_candidates(
        corpus, tmp_path / "out", benign_root=benign, policy=_policy(),
    )

    assert result["candidate_count"] == 0
    assert result["benign_control_inventory"]["configured"] is True
    assert result["benign_control_inventory"]["samples_read"] == 1


def test_paths_are_not_persisted_and_symlinks_are_skipped(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    target = corpus / "FamilyAlpha" / "one.bin"
    _sample(target, *SHARED)
    try:
        os.symlink(target, corpus / "FamilyAlpha" / "link.bin")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    samples, inventory = inventory_corpus(corpus, _policy())
    assert len(samples) == 1
    assert inventory["corpus_path_persisted"] is False
    assert all(str(corpus) not in json.dumps(sample.__dict__) for sample in samples)


def test_identical_sha256_copies_do_not_inflate_family_support(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED)
    _sample(corpus / "FamilyAlpha" / "copied.bin", *SHARED)

    result = learn_local_yara_candidates(corpus, tmp_path / "out", policy=_policy())

    assert result["sample_count"] == 1
    assert result["inventory"]["skipped"]["duplicate_sha256"] == 1
    assert result["definition_candidate_count"] == 0
    assert result["suspicious_candidate_count"] == 1


def test_rejects_output_inside_untrusted_corpus(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED)

    with pytest.raises(ValueError, match="outside"):
        learn_local_yara_candidates(corpus, corpus / "generated", policy=_policy())


def test_secret_like_strings_are_not_used_as_features(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    secret = "Authorization: Bearer should-never-persist"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED, secret)
    _sample(corpus / "FamilyAlpha" / "two.bin", *SHARED, secret)

    result = learn_local_yara_candidates(corpus, tmp_path / "out", policy=_policy())

    assert secret not in json.dumps(result)
    yara_text = next((Path(result["output_root"]) / "candidates").glob("*.yar")).read_text()
    assert secret not in yara_text


def test_definitions_cli_builds_local_candidates_without_activation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    corpus = tmp_path / "corpus"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED)
    _sample(corpus / "FamilyAlpha" / "two.bin", *SHARED)

    exit_code = definitions_cli_main([
        "learn-local-yara", str(corpus), "--output", str(tmp_path / "out"),
        "--maximum-files", "10", "--sample-bytes", "4096", "--json",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["candidate_count"] == 1
    assert payload["safety"]["automatic_activation"] is False


def test_verifier_detects_tampering(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _sample(corpus / "FamilyAlpha" / "one.bin", *SHARED)
    _sample(corpus / "FamilyAlpha" / "two.bin", *SHARED, "distinct_second_sample")
    result = learn_local_yara_candidates(corpus, tmp_path / "out", policy=_policy())
    run = Path(result["output_root"])

    verified = verify_local_yara_run(run)
    assert verified["status"] == "VALID"
    assert verified["verified_rules"] == result["candidate_count"]

    (run / "sha256_candidates.txt").write_text("0" * 64 + "\n", encoding="ascii")
    with pytest.raises(ValueError, match="integrity mismatch"):
        verify_local_yara_run(run)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
