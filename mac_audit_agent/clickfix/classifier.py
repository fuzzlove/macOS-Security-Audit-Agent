"""Bounded generic classifier used by CLI self-tests and IPC validation.

The signed native rule bundle remains authoritative. This module intentionally
contains only generic public command grammar and never executes input.
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Optional, Tuple

from .models import Classification

MAX_INPUT = 64 * 1024
MAX_DECODED = 128 * 1024
MAX_TOKENS = 4096
CLASSIFIER_VERSION = "generic-fallback-1.0.0"
_BIDI = frozenset(chr(value) for value in range(0x202A, 0x202F)) | frozenset(chr(value) for value in range(0x2066, 0x206A))
_ZERO_WIDTH = frozenset(("\u200b", "\u200c", "\u200d", "\ufeff"))


@dataclass(frozen=True)
class ClassificationResult:
    classification: str
    confidence: float
    language_candidates: Tuple[str, ...]
    matched_categories: Tuple[str, ...]
    command_like: bool
    script_like: bool
    encoded_content: bool
    redacted_preview: Optional[str]
    classifier_version: str = CLASSIFIER_VERSION
    truncated: bool = False


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts if count)


def _preview(text: str) -> str:
    cleaned = "".join(" " if unicodedata.category(ch).startswith("C") else ch for ch in text)
    cleaned = re.sub(r"(?i)(password|token|secret|authorization)\s*[:=]\s*\S+", r"\1=[REDACTED]", cleaned)
    cleaned = re.sub(r"\b[A-Za-z0-9+/]{32,}={0,2}\b", "[ENCODED DATA REDACTED]", cleaned)
    return cleaned[:240]


def classify_text(value: str, *, deadline_ms: int = 100) -> ClassificationResult:
    started = time.monotonic_ns()
    raw = value.encode("utf-8", "replace")
    truncated = len(raw) > MAX_INPUT
    raw = raw[:MAX_INPUT]
    text = unicodedata.normalize("NFKC", raw.decode("utf-8", "replace"))
    tokens = re.findall(r"[^\s]+", text[:MAX_INPUT])[:MAX_TOKENS]
    lowered = text.lower()
    categories = set()
    languages = set()
    interpreters = ("sh", "bash", "zsh", "fish", "csh", "tcsh", "osascript", "python", "python3", "perl", "ruby", "php", "node", "deno", "pwsh", "powershell", "swift", "xcrun", "make", "cmake")
    if any(re.search(r"(?:^|[\s;|&])(?:/(?:usr/)?bin/)?" + re.escape(item) + r"(?:\s|$)", lowered) for item in interpreters):
        categories.add("INTERPRETER"); languages.update(item for item in interpreters if re.search(r"\b" + re.escape(item) + r"\b", lowered))
    shell_commands = (
        "sudo", "rm", "mv", "cp", "open", "defaults", "launchctl", "installer",
        "pkgutil", "hdiutil", "ditto", "chmod", "chown", "xattr", "kill", "pkill",
        "eval", "exec", "env", "nohup", "nc", "ncat", "ssh", "scp",
    )
    shell_command_pattern = r"(?m)(?:^|[;|&]\s*)(?:/(?:usr/)?bin/)?(?:" + "|".join(map(re.escape, shell_commands)) + r")(?:\s|$)"
    if re.search(shell_command_pattern, lowered):
        categories.add("SHELL_COMMAND")
    if lowered.startswith("#!") or "\n" in text and categories:
        categories.add("SCRIPT_GRAMMAR")
    if re.search(r"(?:\|\||&&|[|;]|`|\$\(|<<|>>|\d?>|<\(|>\()", text):
        categories.add("EXECUTION_CHAINING")
    if re.search(r"(?i)\b(curl|wget|fetch)\b|https?://", text):
        categories.add("DOWNLOAD")
    if "DOWNLOAD" in categories and ("EXECUTION_CHAINING" in categories or re.search(r"(?i)\b(chmod|sh|bash|zsh|python3?)\b", text)):
        categories.add("DOWNLOAD_AND_EXECUTE")
    if re.search(r"(?i)\b(launchagents?|launchdaemons?|crontab|login item)\b|\blaunchctl\s+(?:load|bootstrap|enable)\b|\.zshrc|\.bash_profile", text):
        categories.add("PERSISTENCE")
    if re.search(r"(?i)\bsecurity\s+(find|dump|export)|\.ssh/|keychain|cookies?|wallet|aws/credentials|gcloud", text):
        categories.add("CREDENTIAL_ACCESS")
    if re.search(r"(?i)\b(spctl|csrutil|tccutil|pfctl)\b|xattr\s+[^\n]*-d\s+com\.apple\.quarantine|disable[^\n]*(firewall|logging|update)", text):
        categories.add("SECURITY_IMPAIRMENT")
    invisible = any(char in text for char in _BIDI | _ZERO_WIDTH)
    if invisible:
        categories.add("INVISIBLE_UNICODE")
    encoded = bool(re.search(r"(?i)\b(base64|xxd\s+-r|fromhex|charcode)\b", text))
    if encoded:
        categories.add("ENCODING")
        candidate = re.search(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text)
        if candidate:
            try:
                decoded = base64.b64decode(candidate.group(0), validate=True)[:MAX_DECODED]
                if any(word in decoded.lower() for word in (b"curl", b"bash", b"osascript", b"python")):
                    categories.add("DECODED_COMMAND_INDICATOR")
            except (ValueError, base64.binascii.Error):
                pass
    simple_command = bool(re.fullmatch(r"\s*(?:ls|whoami|id|pwd|uname|date)(?:\s+[^\n;|&]+)?\s*", lowered))
    command_like = simple_command or bool(categories & {"INTERPRETER", "SHELL_COMMAND", "EXECUTION_CHAINING", "DOWNLOAD_AND_EXECUTE", "PERSISTENCE", "CREDENTIAL_ACCESS", "SECURITY_IMPAIRMENT", "DECODED_COMMAND_INDICATOR"})
    script_like = "SCRIPT_GRAMMAR" in categories
    if "SECURITY_IMPAIRMENT" in categories: classification = Classification.SECURITY_IMPAIRMENT
    elif "CREDENTIAL_ACCESS" in categories: classification = Classification.CREDENTIAL_ACCESS
    elif "PERSISTENCE" in categories: classification = Classification.PERSISTENCE_COMMAND
    elif "DOWNLOAD_AND_EXECUTE" in categories: classification = Classification.DOWNLOAD_AND_EXECUTE
    elif encoded and command_like: classification = Classification.ENCODED_COMMAND
    elif script_like: classification = Classification.SCRIPT_LIKE
    elif command_like: classification = Classification.COMMAND_LIKE
    elif re.search(r"[{}()]|\b(function|class|import|let|const|struct)\b", text) and len(tokens) > 2: classification = Classification.SOURCE_CODE_FRAGMENT
    else: classification = Classification.PLAIN_TEXT
    if (time.monotonic_ns() - started) / 1_000_000 > deadline_ms:
        classification = Classification.CLASSIFICATION_FAILED; command_like = False; categories.add("DEADLINE_EXCEEDED")
    confidence = min(0.99, 0.55 + 0.07 * len(categories)) if command_like else 0.9
    return ClassificationResult(classification.value, confidence, tuple(sorted(languages)), tuple(sorted(categories)), command_like, script_like, encoded, _preview(text), truncated=truncated)


def evidence_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
