from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HashIndicator:
    indicator_id: str
    algorithm: str
    digest: str
    severity: str
    confidence: str
    source: str
    expires_at: str = ""
    action: str = "CORRELATE"
    malware_family: str = ""


class HashIndicatorBackend:
    def __init__(self, indicators=()):
        items = tuple(indicators)
        self._sha256 = {item.digest.lower(): item for item in items if item.algorithm.lower() == "sha256" and len(item.digest) == 64}
        self._correlation = {(item.algorithm.lower(), item.digest.lower()): item for item in items if item.algorithm.lower() in {"sha1", "md5"}}

    @property
    def indicator_count(self) -> int:
        return len(self._sha256) + len(self._correlation)

    @property
    def algorithms(self) -> tuple[str, ...]:
        values = ({"sha256"} if self._sha256 else set()) | {algorithm for algorithm, _digest in self._correlation}
        return tuple(sorted(values))

    @classmethod
    def from_threat_definitions(cls, definitions: Iterable[object]) -> HashIndicatorBackend:
        from mac_audit_agent.threat_definitions.models import (
            DefinitionAction,
            DefinitionLifecycle,
            DefinitionType,
        )

        inactive = {
            DefinitionLifecycle.EXPIRED,
            DefinitionLifecycle.REVOKED,
            DefinitionLifecycle.FALSE_POSITIVE,
            DefinitionLifecycle.DISABLED,
            DefinitionLifecycle.SUPERSEDED,
        }
        algorithms = {
            DefinitionType.MD5: "md5",
            DefinitionType.SHA1: "sha1",
            DefinitionType.SHA256: "sha256",
        }
        indicators: list[HashIndicator] = []
        for item in definitions:
            algorithm = algorithms.get(getattr(item, "definition_type", None))
            if not algorithm or getattr(item, "lifecycle", None) in inactive or getattr(item, "action", None) == DefinitionAction.DISABLED:
                continue
            provenance = getattr(item, "provenance", ())
            indicators.append(HashIndicator(
                str(item.definition_id), algorithm, str(item.value), str(item.severity.value).lower(),
                f"{float(item.confidence):.0%}", ",".join(sorted({entry.source_id for entry in provenance})),
                item.expires_at.isoformat() if item.expires_at else "", str(item.action.value),
                str(item.malware_family or ""),
            ))
        return cls(indicators)

    @staticmethod
    def sha256_file(path: Path, *, maximum_bytes: int = 128 * 1024 * 1024) -> str:
        path = Path(path)
        info = path.lstat()
        if not path.is_file() or path.is_symlink() or info.st_size > maximum_bytes:
            raise ValueError("file is not a bounded regular file")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024): digest.update(chunk)
        return digest.hexdigest()

    def match_file(self, path: Path):
        digest = self.sha256_file(path)
        return self._sha256.get(digest), digest

    def match_file_all(self, path: Path, *, maximum_bytes: int = 128 * 1024 * 1024):
        path = Path(path)
        info = path.lstat()
        if not path.is_file() or path.is_symlink() or info.st_size > maximum_bytes:
            raise ValueError("file is not a bounded regular file")
        # SHA-256 is always the canonical identity. Legacy digests are added
        # only when an active release actually contains them, and all hashes
        # are calculated during the same bounded read.
        hashers = {
            algorithm: hashlib.new(algorithm)
            for algorithm in ({"sha256"} | set(self.algorithms))
        }
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                for digest in hashers.values():
                    digest.update(chunk)
        digests = {algorithm: digest.hexdigest() for algorithm, digest in hashers.items()}
        matches = tuple(
            match
            for algorithm, digest in digests.items()
            if (match := self.match_digest(algorithm, digest)) is not None
        )
        return matches, digests

    def match_digest(self, algorithm: str, digest: str):
        algorithm = algorithm.lower()
        return self._sha256.get(digest.lower()) if algorithm == "sha256" else self._correlation.get((algorithm, digest.lower()))
