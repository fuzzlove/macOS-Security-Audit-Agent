from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LanguageProfile:
    name: str
    suffixes: tuple[str, ...]


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    languages: frozenset[str]
    pattern: re.Pattern[str]
    reason: str
    confidence: str = "medium"


LANGUAGES = (
    LanguageProfile("Swift", (".swift",)),
    LanguageProfile("Objective-C", (".m", ".mm")),
    LanguageProfile("C", (".c", ".h")),
    LanguageProfile("C++", (".cc", ".cpp", ".cxx", ".hpp", ".hh")),
    LanguageProfile("Rust", (".rs",)),
    LanguageProfile("Go", (".go",)),
    LanguageProfile("Java", (".java",)),
    LanguageProfile("Kotlin", (".kt", ".kts")),
    LanguageProfile("JavaScript", (".js", ".jsx", ".mjs", ".cjs")),
    LanguageProfile("TypeScript", (".ts", ".tsx")),
    LanguageProfile("Shell", (".sh", ".bash", ".zsh")),
    LanguageProfile("Ruby", (".rb",)),
    LanguageProfile("PHP", (".php",)),
    LanguageProfile("Perl", (".pl", ".pm")),
    LanguageProfile("C#", (".cs",)),
    LanguageProfile("Lua", (".lua",)),
    LanguageProfile("SQL", (".sql",)),
)

SUFFIX_LANGUAGE = {suffix: profile.name for profile in LANGUAGES for suffix in profile.suffixes}
ALL = frozenset(profile.name for profile in LANGUAGES)


def supported_language_names() -> tuple[str, ...]:
    return ("Python", *(profile.name for profile in LANGUAGES))


def _rule(rule_id: str, languages: set[str] | frozenset[str], pattern: str, reason: str, confidence: str = "medium") -> PatternRule:
    return PatternRule(rule_id, frozenset(languages), re.compile(pattern, re.I), reason, confidence)


RULES = (
    _rule("GEN-CMD-001", ALL, r"\b(?:system|popen|exec|execl|execv|Process\.launchedProcess|Runtime\.getRuntime\(\)\.exec|child_process\.(?:exec|execSync)|Command::new)\s*\([^\n]*(?:\+|\$\{|format!|sprintf|String\.format)", "a command execution sink is combined with dynamically constructed text", "high"),
    _rule("GEN-SQL-001", ALL, r"\b(?:execute|execSQL|rawQuery|query|prepareStatement|mysqli_query|pg_query)\s*\([^\n]*(?:\+|\$\{|\.format\(|sprintf)", "a database query is assembled dynamically at the execution sink instead of using bound parameters", "high"),
    _rule("GEN-SECRET-001", ALL, r"\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']", "a credential-like identifier is assigned a non-trivial string literal", "high"),
    _rule("GEN-TLS-001", ALL, r"(?:verify\s*[:=]\s*false|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|allowsAnyHTTPSCertificateForHost|TrustAllCerts|CERT_NONE)", "TLS peer or hostname verification appears to be explicitly disabled", "high"),
    _rule("GEN-DESER-001", ALL, r"\b(?:ObjectInputStream|BinaryFormatter|Marshal\.load|YAML\.load|unserialize|pickle\.loads?|NSKeyedUnarchiver\.unarchiveObject)\b", "a general-purpose deserializer can construct objects from potentially attacker-controlled content", "medium"),
    _rule("GEN-CRYPTO-001", ALL, r"\b(?:MD5|SHA1|md5|sha1)\s*\(", "a legacy digest is used and requires review when protecting credentials, signatures, or integrity", "medium"),
    _rule("GEN-PATH-001", ALL, r"(?:open|fopen|File\(|Path\(|readFile|writeFile|FileManager\.default\.[A-Za-z]+Item)\s*\([^\n]*(?:\+|\$\{|format!|sprintf)", "a filesystem path is dynamically constructed at a file-operation sink; canonical-root and traversal validation are not evident", "medium"),
    _rule("GEN-XSS-001", {"JavaScript", "TypeScript", "PHP", "Ruby", "Java", "Kotlin"}, r"(?:innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|\.html\s*\([^\n]*(?:req\.|params|query|body))", "untrusted-looking content may reach an HTML interpretation sink without context-specific encoding", "medium"),
    _rule("C-MEM-001", {"C", "C++", "Objective-C"}, r"\b(?:gets|strcpy|strcat|sprintf|scanf\s*\(\s*[\"'][^\"']*%s)\s*\(", "an unbounded memory/string API is used and may permit memory corruption", "high"),
    _rule("SHELL-EVAL-001", {"Shell", "Ruby", "PHP", "Perl", "JavaScript", "TypeScript", "Lua"}, r"\beval\s*(?:\(|\s+)[^\n]*[$@]", "dynamic input reaches an eval-style interpreter sink", "high"),
)


def language_for_path(path: Path) -> str | None:
    if path.name in {"Makefile", "makefile"}:
        return "Make"
    return SUFFIX_LANGUAGE.get(path.suffix.lower())


def scan_text(path: Path, source: str) -> list[dict[str, object]]:
    language = language_for_path(path)
    if language is None:
        return []
    matches: list[dict[str, object]] = []
    lines = source.splitlines()
    constructed_values: dict[str, int] = {}
    assignment = re.compile(r"\b(?:let|var|const|char\s*\*|String|string|str)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=][^\n]*(?:\+|\$\{|format!|sprintf)")
    command_sink = re.compile(r"\b(?:system|popen|exec|Process\.launchedProcess|Runtime\.getRuntime\(\)\.exec|child_process\.(?:exec|execSync)|Command::new)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)")
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "--", "/*", "*")):
            continue
        assigned = assignment.search(line)
        if assigned:
            constructed_values[assigned.group(1)] = number
        sink = command_sink.search(line)
        if sink and sink.group(1) in constructed_values:
            matches.append({
                "rule_id": "GEN-CMD-001", "line": number, "evidence": stripped[:500],
                "reason": f"dynamically constructed value '{sink.group(1)}' reaches a command execution sink",
                "confidence": "medium", "language": language,
            })
        for rule in RULES:
            if language in rule.languages and rule.pattern.search(line):
                matches.append({
                    "rule_id": rule.rule_id,
                    "line": number,
                    "evidence": stripped[:500],
                    "reason": rule.reason,
                    "confidence": rule.confidence,
                    "language": language,
                })
    return matches


__all__ = ["LANGUAGES", "RULES", "language_for_path", "scan_text", "supported_language_names"]
