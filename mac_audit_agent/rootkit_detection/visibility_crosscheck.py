from __future__ import annotations

from mac_audit_agent.rootkit_detection.models import PortVisibilityFinding, VisibilityMismatch, stable_id


FALSE_POSITIVE_CAUSES = [
    "permission limitation",
    "race condition",
    "process exited between samples",
    "transient socket",
    "tool parsing failure",
    "macOS privacy permissions",
]


def crosscheck_port_visibility(ports: list[PortVisibilityFinding]) -> list[VisibilityMismatch]:
    mismatches: list[VisibilityMismatch] = []
    for item in ports:
        if item.visibility_status not in {"missing_owner", "hidden_candidate", "mismatch"}:
            continue
        explanation = (
            f"{item.protocol}/{item.port} was not consistently visible across local tools. "
            f"Possible benign causes include {', '.join(FALSE_POSITIVE_CAUSES)}."
        )
        mismatches.append(
            VisibilityMismatch(
                mismatch_id=stable_id("port_visibility", item.protocol, item.port, item.visibility_status),
                component=f"{item.protocol}/{item.port}",
                source_a="lsof",
                source_b="netstat/local_probe",
                observed_a="seen" if item.lsof_seen else "not seen",
                observed_b="seen" if item.netstat_seen or item.nc_seen else "not seen",
                mismatch_type=item.visibility_status,
                severity=item.severity,
                confidence=item.confidence,
                explanation=explanation,
            )
        )
    return mismatches


def crosscheck_visibility(ports: list[PortVisibilityFinding]) -> list[VisibilityMismatch]:
    return crosscheck_port_visibility(ports)
