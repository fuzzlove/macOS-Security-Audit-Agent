from __future__ import annotations

import hashlib
import unicodedata
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from .configuration import COMMON_TLDS, KEYBOARDS, SERVICE_WORDS
from .models import AssetType, CandidateReason, GenerationConfiguration, PackageEcosystem, ProtectedAsset
from .normalization import CONFUSABLES, domain_ascii, normalize_npm, normalize_pypi, parse_npm

RawCandidate = Tuple[str, CandidateReason, str]


def _base_parts(asset: ProtectedAsset) -> Tuple[str, str, str]:
    if asset.asset_type == AssetType.DOMAIN:
        ascii_name = domain_ascii(asset.canonical_name)
        labels = ascii_name.split(".")
        return labels[0], ".".join(labels[1:]), "domain"
    if asset.ecosystem == PackageEcosystem.NPM:
        scope, package = parse_npm(asset.canonical_name)
        return package, scope, "npm"
    if asset.ecosystem == PackageEcosystem.PYPI:
        if not asset.canonical_name:
            raise ValueError("Python distribution name is required.")
        return asset.canonical_name, "", "pypi"
    if asset.ecosystem:
        from .namespaces import adapter_for
        parsed = adapter_for(asset.ecosystem).parse_identifier(asset.canonical_name)
        values = {item.name: item.value for item in parsed.components}
        if asset.ecosystem == PackageEcosystem.MAVEN_CENTRAL:
            return values["artifact_id"], values["group_id"], "maven-central"
        if asset.ecosystem == PackageEcosystem.GO_MODULE:
            parts = parsed.canonical.split("/"); suffix = parts[-1] if parts[-1].startswith("v") and parts[-1][1:].isdigit() else ""
            token_index = -2 if suffix else -1
            return parts[token_index], "/".join(parts[:token_index]) + ("|" + suffix if suffix else ""), "go-module"
        if asset.ecosystem == PackageEcosystem.PACKAGIST:
            return values["package"], values["vendor"], "packagist"
        return parsed.canonical, "", asset.ecosystem.value
    raise ValueError("Software packages require an ecosystem.")


def _rebuild(token: str, suffix: str, kind: str) -> str:
    if kind == "domain":
        return token + "." + suffix
    if kind == "npm" and suffix:
        return suffix + "/" + token
    if kind == "maven-central": return suffix + ":" + token
    if kind == "packagist": return suffix + "/" + token
    if kind == "go-module":
        prefix, _, major = suffix.partition("|")
        return prefix + "/" + token + ("/" + major if major else "")
    return token


def _human(token: str, suffix: str, kind: str) -> Iterable[RawCandidate]:
    for index in range(len(token)):
        yield _rebuild(token[:index] + token[index + 1 :], suffix, kind), CandidateReason("HUMAN.OMISSION", "One character was omitted.", "human_typo"), "delete:%d" % index
    for index, char in enumerate(token):
        yield _rebuild(token[:index] + char + token[index:], suffix, kind), CandidateReason("HUMAN.REPEAT", "A key was accidentally repeated.", "human_typo"), "repeat:%d" % index
    for index in range(len(token) - 1):
        if token[index] != token[index + 1]:
            swapped = token[:index] + token[index + 1] + token[index] + token[index + 2 :]
            yield _rebuild(swapped, suffix, kind), CandidateReason("HUMAN.TRANSPOSE", "Two adjacent characters were transposed.", "human_typo"), "transpose:%d" % index
    if "-" in token:
        yield _rebuild(token.replace("-", ""), suffix, kind), CandidateReason("HUMAN.MISSING_SEPARATOR", "A word separator was omitted.", "separator_confusion"), "remove-hyphen"
    elif len(token) >= 6:
        midpoint = len(token) // 2
        yield _rebuild(token[:midpoint] + "-" + token[midpoint:], suffix, kind), CandidateReason("HUMAN.ADDED_SEPARATOR", "A hyphen was inserted near a word boundary.", "separator_confusion"), "add-hyphen"


def _adjacency(rows: List[str]) -> Dict[str, set]:
    result = defaultdict(set)
    for row in rows:
        for index, char in enumerate(row):
            for other in row[max(0, index - 1) : index + 2]:
                if other != char:
                    result[char].add(other)
    return result


def _keyboard(token: str, suffix: str, kind: str, locales: tuple) -> Iterable[RawCandidate]:
    for locale in locales:
        rows = KEYBOARDS.get(locale, KEYBOARDS["generic-qwerty"])
        verified = locale in KEYBOARDS
        for index, char in enumerate(token.lower()):
            for replacement in sorted(_adjacency(rows).get(char, set()))[:2]:
                value = token[:index] + replacement + token[index + 1 :]
                explanation = "Adjacent key %s was entered instead of %s on %s." % (replacement, char, locale)
                yield _rebuild(value, suffix, kind), CandidateReason("KEYBOARD.ADJACENT_SUBSTITUTION", explanation, "regional_keyboard", locale if verified else "generic-fallback"), "substitute:%s>%s" % (char, replacement)


def _phonetic(token: str, suffix: str, kind: str) -> Iterable[RawCandidate]:
    for source, replacement in (("ph", "f"), ("ck", "k"), ("ie", "ei"), ("tion", "shun")):
        if source in token.lower():
            value = token.lower().replace(source, replacement, 1)
            yield _rebuild(value, suffix, kind), CandidateReason("PHONETIC.%s_%s" % (source.upper(), replacement.upper()), "A documented phonetic or digraph confusion was applied.", "phonetic", "generic-fallback"), "phonetic:%s>%s" % (source, replacement)


def _unicode(token: str, suffix: str, kind: str) -> Iterable[RawCandidate]:
    reverse = defaultdict(list)
    for confusable, skeleton in CONFUSABLES.items():
        reverse[skeleton].append(confusable)
    for index, char in enumerate(token.lower()):
        for replacement in sorted(reverse.get(char, []))[:2]:
            value = token[:index] + replacement + token[index + 1 :]
            yield _rebuild(value, suffix, kind), CandidateReason("UNICODE.CONFUSABLE", "A versioned Unicode visual confusable replaced one character.", "visual_confusable"), "confusable:U+%04X" % ord(replacement)


def generate(asset: ProtectedAsset, config: GenerationConfiguration) -> List[Tuple[str, List[CandidateReason], List[str]]]:
    token, suffix, kind = _base_parts(asset)
    raw: List[RawCandidate] = []
    if config.include_human_typos:
        raw.extend(_human(token, suffix, kind))
    if config.include_keyboard:
        raw.extend(_keyboard(token, suffix, kind, config.locales))
    if config.include_phonetic:
        raw.extend(_phonetic(token, suffix, kind))
    if config.include_unicode and asset.asset_type == AssetType.DOMAIN:
        raw.extend(_unicode(token, suffix, kind))
    if config.include_tld_confusion and kind == "domain":
        for tld in COMMON_TLDS:
            if tld != suffix:
                raw.append((token + "." + tld, CandidateReason("DOMAIN.TLD_CONFUSION", "A commonly confused top-level domain was substituted.", "tld_confusion"), "tld:%s>%s" % (suffix, tld)))
    if config.include_service_words and kind == "domain":
        for word in SERVICE_WORDS:
            raw.append((word + "-" + token + "." + suffix, CandidateReason("DOMAIN.SERVICE_WORD_PREFIX", "A trust-related service word was added; this is impersonation-oriented, not an ordinary typo.", "combosquatting"), "prefix:" + word))
    if config.include_package_confusion and kind in {"npm", "pypi"}:
        for separator in ("-", "_", "."):
            if any(item in token for item in "-_."):
                value = token.replace("-", separator).replace("_", separator).replace(".", separator)
                raw.append((_rebuild(value, suffix, kind), CandidateReason("PACKAGE.NORMALIZATION_COLLISION", "Registry separator normalization may collapse this spelling to the same identifier.", "normalization_collision"), "separator-normalization"))
        if kind == "npm" and suffix:
            raw.append((token, CandidateReason("NPM.SCOPE_OMISSION", "The organization scope was omitted.", "namespace_confusion"), "omit-scope"))
    if config.include_package_confusion and kind == "crates-io" and "-" in token:
        raw.append((token.replace("-", "_"), CandidateReason("CRATES.IMPORT_PROJECTION", "Cargo hyphens project to underscores in Rust source identifiers; registry identities remain distinct.", "projection_confusion"), "hyphen-to-underscore"))
    if config.include_package_confusion and kind == "rubygems" and "-" in token:
        raw.append((token.replace("-", "_"), CandidateReason("RUBYGEMS.REQUIRE_PROJECTION", "Gem spelling and common require-path spelling may differ.", "projection_confusion"), "gem-to-require"))
    if config.include_package_confusion and kind == "nuget":
        for suffix_word in ("Core", "Client", "Extensions", "SDK", "Runtime", "Tools"):
            raw.append((token + "." + suffix_word, CandidateReason("NUGET.SUFFIX_CONFUSION", "A common NuGet package family suffix was added.", "namespace_confusion"), "suffix:" + suffix_word))
    if config.include_package_confusion and kind == "maven-central":
        group_parts = suffix.split(".")
        if len(group_parts) > 2:
            raw.append((".".join(group_parts[:-1]) + ":" + token, CandidateReason("MAVEN.GROUP_SEGMENT_OMISSION", "One publisher group segment was omitted while preserving the artifact.", "namespace_confusion"), "group-segment-omission"))
    if config.include_package_confusion and kind == "go-module":
        prefix, marker, major = suffix.partition("|")
        if major:
            raw.append((prefix + "/" + token, CandidateReason("GO.SEMANTIC_MAJOR_OMISSION", "The semantic import-version suffix was omitted.", "namespace_confusion"), "omit-major:" + major))
    if config.include_package_confusion and kind == "packagist":
        if len(suffix) > 2:
            raw.append((suffix[:-1] + "/" + token, CandidateReason("PACKAGIST.VENDOR_TYPO", "The vendor namespace contains a one-character omission.", "namespace_confusion"), "vendor-omission"))
    canonical_key = normalize(asset.canonical_name, kind)
    merged: Dict[str, Tuple[str, List[CandidateReason], List[str]]] = {}
    for name, reason, operation in raw[: config.pre_dedup_limit]:
        try:
            key = normalize(name, kind)
        except ValueError:
            continue
        if key == canonical_key and reason.rule_id != "PACKAGE.NORMALIZATION_COLLISION":
            continue
        if key not in merged:
            merged[key] = (name, [], [])
        merged[key][1].append(reason)
        merged[key][2].append(operation)
    ordered = sorted(merged.values(), key=lambda item: (min(rule_rank(reason.rule_id) for reason in item[1]), item[0]))
    return ordered[: config.post_dedup_limit]


def normalize(name: str, kind: str) -> str:
    if kind == "domain":
        try:
            return domain_ascii(name)
        except ValueError:
            # Preserve a deterministic comparison identity for Unicode display
            # risk even when the optional IDNA2008 library is unavailable or a
            # registry would reject the spelling. Validation remains explicit
            # in the resulting Candidate and no lookup is attempted.
            if any(not char.isascii() for char in name):
                return "unicode:" + unicodedata.normalize("NFC", name).casefold()
            raise
    if kind == "pypi":
        return normalize_pypi(name)
    if kind == "npm":
        parse_npm(name); return normalize_npm(name)
    from .models import PackageEcosystem
    from .namespaces import adapter_for
    return adapter_for(PackageEcosystem(kind)).parse_identifier(name).comparison_key


def rule_rank(rule_id: str) -> int:
    # Visual candidates must survive the bounded queue.  They used to rank
    # behind every typing candidate and were therefore unreachable for common
    # names even when explicitly enabled.
    order = {"UNICODE.CONFUSABLE": 1, "HUMAN.TRANSPOSE": 2, "KEYBOARD.ADJACENT_SUBSTITUTION": 3, "HUMAN.OMISSION": 4, "HUMAN.REPEAT": 5, "PACKAGE.NORMALIZATION_COLLISION": 6, "NPM.SCOPE_OMISSION": 6, "DOMAIN.TLD_CONFUSION": 7}
    return order.get(rule_id, 20)


def candidate_id(canonical: str, normalized: str) -> str:
    return hashlib.sha256((canonical + "\0" + normalized).encode("utf-8")).hexdigest()[:20]
