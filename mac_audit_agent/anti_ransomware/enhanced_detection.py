from __future__ import annotations

from dataclasses import dataclass

from .models import DetectionSignal, FileStatistics


@dataclass(frozen=True)
class FileTransition:
    before: FileStatistics | None
    after: FileStatistics
    operation: str
    extension_changed: bool = False
    original_deleted: bool = False
    rename_over_original: bool = False
    canary: bool = False
    ransom_note: bool = False


def transition_signals(transition: FileTransition) -> list[DetectionSignal]:
    """Return explainable signals without retaining file contents."""
    signals: list[DetectionSignal] = []
    before_entropy = transition.before.entropy if transition.before else None
    entropy_delta = transition.after.entropy - before_entropy if before_entropy is not None else 0.0
    if transition.after.entropy >= 7.8 and (before_entropy is None or entropy_delta >= 1.0):
        signals.append(DetectionSignal("high_entropy_transition", 35, "recognizable/lower-entropy content became high entropy", {"before_entropy": before_entropy, "after_entropy": transition.after.entropy}))
    if transition.extension_changed:
        signals.append(DetectionSignal("extension_changed", 10, "file extension changed during replacement"))
    if transition.original_deleted:
        signals.append(DetectionSignal("original_deleted", 15, "original was deleted after a replacement was produced"))
    if transition.rename_over_original:
        signals.append(DetectionSignal("rename_over_original", 20, "temporary or replacement file was renamed over the original"))
    if transition.canary:
        signals.append(DetectionSignal("protected_canary_modified", 60, "an approved synthetic canary changed"))
    if transition.ransom_note:
        signals.append(DetectionSignal("ransom_note_pattern", 30, "a synthetic or observed filename matched the configured ransom-note policy"))
    if transition.after.size > 50 * 1024 * 1024 and transition.after.bytes_sampled < transition.after.size:
        signals.append(DetectionSignal("large_file_sampled", 5, "large file was analyzed with bounded samples", {"size": transition.after.size, "sampled": transition.after.bytes_sampled}))
    return signals
