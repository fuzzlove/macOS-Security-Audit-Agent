from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class YaraCapability:
    available: bool
    state: str
    reason: str


class YaraBackend:
    def __init__(
        self, *, timeout_seconds: int = 5, maximum_file_bytes: int = 32 * 1024 * 1024,
        maximum_rule_bytes: int = 64 * 1024 * 1024, maximum_namespaces: int = 100_000,
    ):
        self.timeout_seconds = max(1, min(timeout_seconds, 30))
        self.maximum_file_bytes = maximum_file_bytes
        self.maximum_rule_bytes = max(1_000_000, min(int(maximum_rule_bytes), 128 * 1024 * 1024))
        self.maximum_namespaces = max(1_000, min(int(maximum_namespaces), 100_000))
        try:
            import yara
            self._yara, self.capability = yara, YaraCapability(True, "AVAILABLE", "YARA backend loaded.")
        except (ImportError, OSError) as exc:
            self._yara, self.capability = None, YaraCapability(False, "DEPENDENCY_MISSING", type(exc).__name__)

    def compile(self, sources: dict[str, str]):
        if not self._yara:
            raise RuntimeError("YARA capability is unavailable; exact SHA-256 matching remains active.")
        sizes = [len(value.encode("utf-8")) for value in sources.values()]
        if (
            not sources
            or len(sources) > self.maximum_namespaces
            or any(size > self.maximum_rule_bytes for size in sizes)
            or sum(sizes) > self.maximum_rule_bytes
        ):
            raise ValueError("YARA rule package exceeds bounded runtime limits.")
        return self._yara.compile(sources=sources)

    def scan(self, compiled, path: Path):
        path=Path(path); info=path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_size > self.maximum_file_bytes: raise ValueError("YARA target is not a bounded regular file.")
        return compiled.match(str(path), timeout=self.timeout_seconds)
