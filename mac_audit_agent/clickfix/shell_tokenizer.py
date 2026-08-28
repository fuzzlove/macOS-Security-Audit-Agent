from __future__ import annotations

import unicodedata
from dataclasses import dataclass

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
SEPARATORS = {"|", ";", "\n", "&&", "||", "&"}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str


@dataclass(frozen=True)
class Tokenization:
    tokens: tuple[Token, ...]
    normalized: str
    unicode_anomaly: bool
    control_anomaly: bool
    escaped_name: bool


def tokenize(command: str, *, maximum_depth: int = 32) -> Tokenization:
    normalized = unicodedata.normalize("NFKC", command)
    unicode_anomaly = normalized != command or any(c in ZERO_WIDTH or (c.isspace() and c not in " \t\r\n") for c in command)
    normalized = "".join("" if c in ZERO_WIDTH else " " if c.isspace() and c not in " \t\r\n" else c for c in normalized)
    control = any(ord(c) < 32 and c not in "\t\r\n" for c in normalized)
    normalized = "".join("" if ord(c) < 32 and c not in "\t\r\n" else c for c in normalized)
    out: list[Token] = []; buf: list[str] = []; quote = ""; escaped = False; depth = 0; escaped_name = False
    def flush() -> None:
        if buf:
            value = "".join(buf); out.append(Token("assignment" if "=" in value and not value.startswith("=") and value.split("=",1)[0].replace("_","").isalnum() else "word", value)); buf.clear()
    i = 0
    while i < len(normalized):
        c = normalized[i]
        if escaped: buf.append(c); escaped_name = escaped_name or c.isalpha(); escaped = False; i += 1; continue
        if c == "\\" and quote != "'": escaped = True; i += 1; continue
        if quote:
            if c == quote: quote = ""
            else: buf.append(c)
            i += 1; continue
        if c in "'\"": quote = c; i += 1; continue
        pair = normalized[i:i+2]
        if pair in {"&&", "||", "$("}:
            flush(); out.append(Token("substitution_start" if pair == "$(" else "separator", pair)); depth += pair == "$("; i += 2
        elif c in "()":
            flush(); depth += 1 if c == "(" else -1
            if depth > maximum_depth or depth < 0: raise ValueError("parser_depth_limit")
            out.append(Token("subshell", c)); i += 1
        elif c in "|;&\n": flush(); out.append(Token("separator", c)); i += 1
        elif c in "<>":
            flush(); value = c
            if i+1 < len(normalized) and normalized[i+1] in "><&": value += normalized[i+1]; i += 1
            out.append(Token("redirect", value)); i += 1
        elif c.isspace(): flush(); i += 1
        else: buf.append(c); i += 1
    if quote: raise ValueError("unterminated_quote")
    if escaped: buf.append("\\")
    flush()
    return Tokenization(tuple(out), normalized, unicode_anomaly, control, escaped_name)


def command_segments(tokens: tuple[Token, ...]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token.kind == "separator": segments.append([])
        elif token.kind in {"word", "assignment"}: segments[-1].append(token.value)
    return [segment for segment in segments if segment]
