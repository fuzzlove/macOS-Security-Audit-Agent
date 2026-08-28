"""Sensor capability description with explicit degradation."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SensorStatus:
    endpoint_security_available: bool
    full_disk_access: bool
    tcc_available: bool
    mode: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_sensor_status(*, endpoint_security: bool = False, full_disk_access: bool = False,
                          tcc_available: bool = False) -> SensorStatus:
    limitations = []
    if not endpoint_security: limitations.append("Endpoint Security entitlement unavailable; preemptive containment is disabled.")
    if not full_disk_access: limitations.append("Full Disk Access missing; protected paths may be unavailable.")
    if not tcc_available: limitations.append("TCC-limited collectors are disabled.")
    return SensorStatus(endpoint_security, full_disk_access, tcc_available,
                        "protected" if endpoint_security and full_disk_access else "degraded_observation_mode", tuple(limitations))


__all__ = ["SensorStatus", "resolve_sensor_status"]
