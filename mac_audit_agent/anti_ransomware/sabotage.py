from __future__ import annotations

from dataclasses import dataclass

from .models import DetectionSignal


@dataclass(frozen=True)
class CommandObservation:
    executable: str
    arguments: tuple[str, ...]
    target: str = ""
    approved_maintenance: bool = False


SNAPSHOT_DELETE = {("tmutil", "deletelocalsnapshots"), ("diskutil", "apfs"), ("mount_apfs", "-s")}
SERVICE_IMPAIR = {"bootout", "unload", "disable", "remove"}


def sabotage_signals(observation: CommandObservation) -> list[DetectionSignal]:
    joined = " ".join(observation.arguments).lower()
    name = observation.executable.rsplit("/", 1)[-1].lower()
    signals: list[DetectionSignal] = []
    if (name, observation.arguments[0].lower() if observation.arguments else "") in SNAPSHOT_DELETE or (name == "tmutil" and "delete" in joined):
        signals.append(DetectionSignal("snapshot_deletion_attempt", 45, "command intent may delete backup or filesystem snapshots"))
    if name == "launchctl" and any(token in SERVICE_IMPAIR for token in observation.arguments) and "macauditagent" in joined:
        signals.append(DetectionSignal("protection_service_impairment", 60, "command targets an MSAA launchd service"))
    if any(token in joined for token in ("integrity_manifest", "anti_ransomware", "evidence")) and any(token in joined for token in ("rm ", "unlink", "chmod 777", "chown")):
        signals.append(DetectionSignal("protection_or_evidence_tamper", 50, "command intent targets protected policy, binary, or evidence state"))
    if observation.approved_maintenance:
        signals = [DetectionSignal(s.signal_id, max(0, s.weight - 25), s.rationale + "; approved maintenance lowers but does not erase risk", s.evidence) for s in signals]
    return signals
