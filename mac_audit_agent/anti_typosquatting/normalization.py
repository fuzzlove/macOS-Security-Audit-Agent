from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Tuple

CONTROL_CLASSES = {"Cc", "Cf"}
PYPI_NAME = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])\Z", re.I)
NPM_UNSCOPED = re.compile(r"^[a-z0-9][a-z0-9._-]{0,213}\Z")

# Audited subset for the bundled proof-of-capability. The manifest explicitly
# records that this is not the complete Unicode confusables data set.
CONFUSABLES: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "ɑ": "a", "ɡ": "g", "ⅼ": "l", "і": "i", "ј": "j", "ѕ": "s", "ⅿ": "m",
}


def visible_text(value: str) -> str:
    parts = []
    for char in value:
        if unicodedata.category(char) in CONTROL_CLASSES:
            parts.append("<U+%04X %s>" % (ord(char), unicodedata.name(char, "CONTROL")))
        else:
            parts.append(char)
    return "".join(parts)


def reject_controls(value: str) -> None:
    if any(unicodedata.category(char) in CONTROL_CLASSES for char in value):
        raise ValueError("Names must not contain control or bidirectional formatting characters.")


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_npm(name: str) -> str:
    return unicodedata.normalize("NFC", name).lower()


def parse_npm(name: str) -> Tuple[str, str]:
    normalized = normalize_npm(name)
    if normalized.startswith("@"):
        parts = normalized.split("/", 1)
        if len(parts) != 2 or not NPM_UNSCOPED.fullmatch(parts[0][1:]) or not NPM_UNSCOPED.fullmatch(parts[1]):
            raise ValueError("Invalid scoped npm package name.")
        return parts[0], parts[1]
    if not NPM_UNSCOPED.fullmatch(normalized):
        raise ValueError("Invalid npm package name.")
    return "", normalized


def domain_ascii(name: str) -> str:
    name = unicodedata.normalize("NFC", name.strip().rstrip(".")).lower()
    reject_controls(name)
    if "://" in name or any(char in name for char in "/?#@"):
        raise ValueError("Enter a bare domain name, not a URL, email address, path, query, or fragment.")
    if not name or len(name) > 253 or "." not in name:
        raise ValueError("Enter a complete domain with labels separated by a period.")
    try:
        import idna
        ascii_name = idna.encode(name, uts46=False, std3_rules=True).decode("ascii")
    except ImportError:
        if not name.isascii():
            raise ValueError("Internationalized domain analysis requires the optional IDNA2008 dependency.")
        ascii_name = name
    except Exception as exc:
        raise ValueError("Domain is not valid under the configured IDNA2008 processor.") from exc
    if len(ascii_name) > 253 or any(not label or len(label.encode("ascii")) > 63 for label in ascii_name.split(".")):
        raise ValueError("Domain exceeds DNS label or total length limits after IDNA conversion.")
    return ascii_name


def confusable_skeleton(value: str) -> str:
    value = unicodedata.normalize("NFD", value).casefold()
    mapped = "".join(CONFUSABLES.get(char, char) for char in value)
    return unicodedata.normalize("NFD", mapped)


def scripts(value: str) -> List[str]:
    found = set()
    for char in value:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "UNKNOWN")
        found.add(name.split(" ", 1)[0] if name else "UNKNOWN")
    return sorted(found)


def code_points(value: str) -> List[str]:
    return ["U+%04X %s" % (ord(char), unicodedata.name(char, "UNNAMED")) for char in value if not char.isascii() or unicodedata.category(char) in CONTROL_CLASSES]
