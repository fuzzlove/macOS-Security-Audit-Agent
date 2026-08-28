from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


BaselineMode = Literal["source_development", "packaged_app", "installed_runtime", "release"]


@dataclass(frozen=True)
class IntegrityBaselineMode:
    mode: BaselineMode
    display_name: str
    trust_requirements: list[str] = field(default_factory=list)
    signature_required: bool = False
    full_release_evidence_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BASELINE_MODES = {
    "source_development": IntegrityBaselineMode(
        "source_development",
        "Source Development Mode",
        [
            "trusted manifest exists",
            "changed files match an approved change record before rebaseline",
            "compileall passes",
            "tests pass when strict mode requires them",
            "manifest regenerated only after explicit approval",
        ],
    ),
    "packaged_app": IntegrityBaselineMode(
        "packaged_app",
        "Packaged App Mode",
        ["packaged manifest exists", "bundle files match manifest", "signature/ad-hoc status is recorded"],
        signature_required=False,
    ),
    "installed_runtime": IntegrityBaselineMode(
        "installed_runtime",
        "Installed Runtime Mode",
        ["runtime install manifest exists", "runtime hashes match manifest", "plist paths and owner/permissions match mode"],
    ),
    "release": IntegrityBaselineMode(
        "release",
        "Release Mode",
        ["compileall passes", "pytest passes", "build passes", "twine check passes if PyPI", "signed manifest exists", "no unapproved modifications"],
        signature_required=True,
        full_release_evidence_required=True,
    ),
}


def baseline_mode_for_source_type(source_type: str, *, release: bool = False) -> str:
    if release:
        return "release"
    mode = str(source_type or "source_tree")
    if mode == "source_tree":
        return "source_development"
    if mode in {"pyinstaller_app", "pip_package", "pypi_wheel"}:
        return "packaged_app"
    if mode in {"system_daemon_runtime", "user_notifier_runtime", "system_runtime", "user_runtime"}:
        return "installed_runtime"
    return "source_development"


def baseline_mode_details(mode: str) -> IntegrityBaselineMode:
    return BASELINE_MODES.get(str(mode), BASELINE_MODES["source_development"])


__all__ = ["BaselineMode", "IntegrityBaselineMode", "BASELINE_MODES", "baseline_mode_for_source_type", "baseline_mode_details"]
