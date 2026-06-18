from __future__ import annotations

import hashlib
import json
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.rules import correlation_id_for, evidence_hash, normalized_signal, rule_for_event


USB_DEVICE_RE = re.compile(r"^[+| ]*-o (?P<name>.+?)@(?P<location>[0-9A-Fa-f]+)\s+<class IOUSBHostDevice,", re.MULTILINE)
BLUETOOTH_DEVICE_RE = re.compile(r"^[+| ]*-o (?P<name>.+?)\s+<class IOBluetoothDevice,", re.MULTILINE)
PROPERTY_RE = re.compile(r'"(?P<key>[^"]+)"\s*=\s*(?:"(?P<quoted>[^"]*)"|(?P<raw>[^\n]+))')
MOISTURE_RE = re.compile(
    r"\b(?:moisture|liquid|water)\b.{0,48}\b(?:detected|present|ingress|warning)\b"
    r"|\b(?:detected|present)\b.{0,48}\b(?:moisture|liquid|water)\b",
    re.IGNORECASE,
)
SELF_QUERY_MARKERS = {"log run noninteractively", "eventmessage contains", "--predicate"}
INTERNAL_USB_PORT_TYPE = "2"


def run_command(command: list[str]) -> tuple[int, str, str]:
    executable = Path(command[0])
    if not executable.exists():
        return 127, "", f"command not found: {command[0]}"
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:
        return 1, "", str(exc)


@dataclass
class HardwareMonitorSnapshot:
    usb_devices: list[dict[str, str]] = field(default_factory=list)
    bluetooth_devices: list[dict[str, str]] = field(default_factory=list)
    nearby_bluetooth_devices: list[dict[str, str]] = field(default_factory=list)
    moisture_markers: set[str] = field(default_factory=set)
    moisture_capability: str = "explicit-marker monitoring unavailable"


class HardwareMonitor:
    def __init__(self, executor=run_command) -> None:
        self.executor = executor

    def collect_snapshot(self) -> HardwareMonitorSnapshot:
        usb_devices = self.collect_usb_devices()
        bluetooth_devices, nearby_bluetooth_devices = self.collect_bluetooth_inventory()
        hpm_code, hpm_stdout, _ = self.executor(["/usr/sbin/ioreg", "-r", "-c", "AppleHPMDevice", "-l", "-w", "0"])
        log_code, log_stdout, _ = self.executor(
            [
                "/usr/bin/log",
                "show",
                "--last",
                "2m",
                "--style",
                "compact",
                "--predicate",
                'eventMessage CONTAINS[c] "liquid" OR eventMessage CONTAINS[c] "moisture" OR eventMessage CONTAINS[c] "water detected"',
            ]
        )
        marker_text = "\n".join(value for value in [hpm_stdout if hpm_code == 0 else "", log_stdout if log_code == 0 else ""] if value)
        moisture_markers = {
            line.strip()[:500]
            for line in marker_text.splitlines()
            if MOISTURE_RE.search(line) and not any(marker in line.lower() for marker in SELF_QUERY_MARKERS)
        }
        capability = "monitoring explicit registry and unified-log markers" if hpm_code == 0 or log_code == 0 else "explicit-marker monitoring unavailable"
        return HardwareMonitorSnapshot(
            usb_devices=usb_devices,
            bluetooth_devices=bluetooth_devices,
            nearby_bluetooth_devices=nearby_bluetooth_devices,
            moisture_markers=moisture_markers,
            moisture_capability=capability,
        )

    def collect_usb_devices(self) -> list[dict[str, str]]:
        code, stdout, _ = self.executor(
            ["/usr/sbin/ioreg", "-p", "IOUSB", "-c", "IOUSBHostDevice", "-r", "-l", "-w", "0"]
        )
        return self._parse_usb_devices(stdout) if code == 0 else []

    def collect_bluetooth_devices(self) -> list[dict[str, str]]:
        connected, _nearby = self.collect_bluetooth_inventory()
        return connected

    def collect_bluetooth_inventory(self) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        code, stdout, _ = self.executor(["/usr/sbin/ioreg", "-r", "-c", "IOBluetoothDevice", "-l", "-w", "0"])
        devices = self._parse_bluetooth_devices(stdout) if code == 0 else []
        nearby_devices: list[dict[str, str]] = []
        profiler_code, profiler_stdout, _ = self.executor(["/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"])
        if profiler_code == 0:
            connected, nearby = self._parse_system_profiler_bluetooth_inventory(profiler_stdout)
            devices.extend(connected)
            nearby_devices.extend(nearby)
        by_key: dict[str, dict[str, str]] = {}
        for device in devices:
            key = self._bluetooth_key(device)
            if key:
                by_key[key] = {**by_key.get(key, {}), **device}
        connected_devices = sorted(by_key.values(), key=self._bluetooth_key)
        connected_keys = {self._bluetooth_key(item) for item in connected_devices}
        nearby_by_key: dict[str, dict[str, str]] = {}
        for device in nearby_devices:
            key = self._bluetooth_key(device)
            if key and key not in connected_keys:
                nearby_by_key[key] = {**nearby_by_key.get(key, {}), **device}
        return connected_devices, sorted(nearby_by_key.values(), key=self._bluetooth_key)

    def evaluate(
        self,
        previous: HardwareMonitorSnapshot | None,
        current: HardwareMonitorSnapshot,
        *,
        include_usb: bool = True,
    ) -> list[BackgroundMonitorEvent]:
        timestamp = utc_now_iso()
        events: list[BackgroundMonitorEvent] = []
        if include_usb and previous is not None:
            events.extend(self.usb_connection_events(previous.usb_devices, current.usb_devices, timestamp=timestamp))
        if previous is not None:
            events.extend(self.bluetooth_connection_events(previous.bluetooth_devices, current.bluetooth_devices, timestamp=timestamp))
            events.extend(self.nearby_bluetooth_events(previous.nearby_bluetooth_devices, current.nearby_bluetooth_devices, timestamp=timestamp))
        previous_markers = previous.moisture_markers if previous else set()
        for marker in sorted(current.moisture_markers - previous_markers):
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="system_moisture_detected",
                    severity="critical",
                    source="hardware_moisture_marker",
                    evidence=f"System moisture-related marker detected: {marker}",
                    confidence="high",
                    recommendation="Disconnect external power and accessories, stop using the affected port, and inspect the system before reconnecting devices.",
                    metadata={"marker": marker, "capability": current.moisture_capability},
                    rule=rule_for_event("system_moisture_detected"),
                    previous_state="no moisture marker",
                    current_state=marker,
                )
            )
        return events

    def nearby_bluetooth_events(
        self,
        previous_devices: list[dict[str, str]],
        current_devices: list[dict[str, str]],
        *,
        timestamp: str | None = None,
    ) -> list[BackgroundMonitorEvent]:
        timestamp = timestamp or utc_now_iso()
        previous_keys = {self._bluetooth_key(item) for item in previous_devices}
        current_keys = {self._bluetooth_key(item) for item in current_devices}
        events: list[BackgroundMonitorEvent] = []
        for item in current_devices:
            key = self._bluetooth_key(item)
            if not key or key in previous_keys:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="nearby_bluetooth_device_detected",
                    severity="medium",
                    source="system_profiler_bluetooth_observer",
                    evidence=f"New nearby or remembered Bluetooth device observed: {self._bluetooth_label(item)}.",
                    confidence="medium",
                    recommendation="Confirm whether this nearby Bluetooth identity is expected in the environment. This is a review signal, not proof of compromise.",
                    metadata=item,
                    identity=key,
                    rule=rule_for_event("nearby_bluetooth_device_detected"),
                    previous_state="device not previously observed nearby",
                    current_state=self._bluetooth_label(item),
                )
            )
        if previous_keys != current_keys:
            added = sorted(current_keys - previous_keys)
            removed = sorted(previous_keys - current_keys)
            if added or removed:
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type="nearby_bluetooth_inventory_changed",
                        severity="medium",
                        source="system_profiler_bluetooth_observer",
                        evidence=f"Nearby Bluetooth inventory changed; added={len(added)} removed={len(removed)}.",
                        confidence="medium",
                        recommendation="Review nearby Bluetooth identities and correlate with room/device activity.",
                        metadata={"added": added, "removed": removed},
                        rule=rule_for_event("nearby_bluetooth_inventory_changed"),
                        previous_state=f"nearby count={len(previous_devices)}",
                        current_state=f"nearby count={len(current_devices)}",
                    )
                )
        return events

    def bluetooth_connection_events(
        self,
        previous_devices: list[dict[str, str]],
        current_devices: list[dict[str, str]],
        *,
        timestamp: str | None = None,
    ) -> list[BackgroundMonitorEvent]:
        timestamp = timestamp or utc_now_iso()
        previous_keys = {self._bluetooth_key(item) for item in previous_devices}
        current_keys = {self._bluetooth_key(item) for item in current_devices}
        events = []
        for item in current_devices:
            if self._bluetooth_key(item) in previous_keys:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="bluetooth_device_connected",
                    severity="medium",
                    source="ioreg_bluetooth_observer",
                    evidence=f"Bluetooth device connected: {self._bluetooth_label(item)}.",
                    confidence="high",
                    recommendation="Confirm the connected Bluetooth device is expected and approved for this environment.",
                    metadata=item,
                    identity=self._bluetooth_key(item),
                    rule=rule_for_event("bluetooth_device_connected"),
                    previous_state="device not connected",
                    current_state=self._bluetooth_label(item),
                )
            )
        for item in previous_devices:
            if self._bluetooth_key(item) in current_keys:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="bluetooth_device_disconnected",
                    severity="medium",
                    source="ioreg_bluetooth_observer",
                    evidence=f"Bluetooth device disconnected: {self._bluetooth_label(item)}.",
                    confidence="high",
                    recommendation="Confirm the disconnected Bluetooth device is expected and approved for this environment.",
                    metadata=item,
                    identity=self._bluetooth_key(item),
                    rule=rule_for_event("bluetooth_device_disconnected"),
                    previous_state=self._bluetooth_label(item),
                    current_state="disconnected",
                )
            )
        if previous_keys != current_keys:
            added = sorted(current_keys - previous_keys)
            removed = sorted(previous_keys - current_keys)
            if added or removed:
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type="bluetooth_inventory_changed",
                        severity="medium",
                        source="ioreg_bluetooth_observer",
                        evidence=(
                            "Bluetooth inventory changed; "
                            f"added={len(added)} removed={len(removed)}."
                        ),
                        confidence="high",
                        recommendation="Review the Bluetooth devices that were added or removed.",
                        metadata={"added": added, "removed": removed},
                        rule=rule_for_event("bluetooth_inventory_changed"),
                        previous_state=f"count={len(previous_devices)}",
                        current_state=f"count={len(current_devices)}",
                    )
                )
        return events

    def usb_connection_events(
        self,
        previous_devices: list[dict[str, str]],
        current_devices: list[dict[str, str]],
        *,
        timestamp: str | None = None,
    ) -> list[BackgroundMonitorEvent]:
        timestamp = timestamp or utc_now_iso()
        previous_usb = {self._usb_key(item) for item in previous_devices}
        current_usb = {self._usb_key(item) for item in current_devices}
        events = []
        for item in current_devices:
            if self._usb_key(item) in previous_usb:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="usb_device_connected",
                    severity="info",
                    source="ioreg_usb_observer",
                    evidence=f"USB device recognized: {self._usb_label(item)}.",
                    confidence="high",
                    recommendation="Confirm the USB device is expected before using it.",
                    metadata=item,
                    identity=self._usb_key(item),
                    rule=rule_for_event("usb_device_connected"),
                    previous_state="device not present",
                    current_state=self._usb_label(item),
                )
            )
        for item in previous_devices:
            if self._usb_key(item) in current_usb:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="usb_device_removed",
                    severity="medium",
                    source="ioreg_usb_observer",
                    evidence=f"USB device removed: {self._usb_label(item)}.",
                    confidence="high",
                    recommendation="Confirm the USB device removal was expected and intentional.",
                    metadata=item,
                    identity=self._usb_key(item),
                    rule=rule_for_event("usb_device_removed"),
                    previous_state=self._usb_label(item),
                    current_state="removed",
                )
            )
        return events

    def _parse_usb_devices(self, output: str) -> list[dict[str, str]]:
        matches = list(USB_DEVICE_RE.finditer(output))
        devices: list[dict[str, str]] = []
        for index, match in enumerate(matches):
            block_end = matches[index + 1].start() if index + 1 < len(matches) else len(output)
            block = output[match.start():block_end]
            properties = {
                prop.group("key"): (prop.group("quoted") if prop.group("quoted") is not None else prop.group("raw").strip())
                for prop in PROPERTY_RE.finditer(block)
            }
            if properties.get("USBPortType") == INTERNAL_USB_PORT_TYPE:
                continue
            devices.append(
                {
                    "name": properties.get("USB Product Name") or match.group("name").strip(),
                    "vendor": properties.get("USB Vendor Name", ""),
                    "serial": properties.get("USB Serial Number", ""),
                    "session_id": properties.get("sessionID", ""),
                    "location_id": properties.get("locationID", match.group("location")),
                    "vendor_id": properties.get("idVendor", ""),
                    "product_id": properties.get("idProduct", ""),
                }
            )
        return devices

    def _parse_bluetooth_devices(self, output: str) -> list[dict[str, str]]:
        matches = list(BLUETOOTH_DEVICE_RE.finditer(output))
        devices: list[dict[str, str]] = []
        for index, match in enumerate(matches):
            block_end = matches[index + 1].start() if index + 1 < len(matches) else len(output)
            block = output[match.start():block_end]
            properties = {
                prop.group("key"): (prop.group("quoted") if prop.group("quoted") is not None else prop.group("raw").strip())
                for prop in PROPERTY_RE.finditer(block)
            }
            connected = str(properties.get("Connected", "")).strip().lower()
            connected = connected or str(properties.get("DeviceIsConnected", "")).strip().lower()
            connected = connected or str(properties.get("deviceIsConnected", "")).strip().lower()
            connected = connected or str(properties.get("IsConnected", "")).strip().lower()
            if connected not in {"yes", "true", "1"}:
                continue
            devices.append(
                {
                    "name": properties.get("Name") or match.group("name").strip(),
                    "address": properties.get("DeviceAddress") or properties.get("Address", ""),
                    "vendor_id": properties.get("VendorID", ""),
                    "product_id": properties.get("ProductID", ""),
                }
            )
        return devices

    def _parse_system_profiler_bluetooth_devices(self, output: str) -> list[dict[str, str]]:
        connected, _nearby = self._parse_system_profiler_bluetooth_inventory(output)
        return connected

    def _parse_system_profiler_bluetooth_inventory(self, output: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return [], []
        connected_devices: list[dict[str, str]] = []
        nearby_devices: list[dict[str, str]] = []

        def visit(value) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"device_connected", "device_not_connected", "device_paired"} and isinstance(child, list):
                        for item in child:
                            if not isinstance(item, dict):
                                continue
                            device = self._system_profiler_bluetooth_device(item, source_bucket=key)
                            if not device:
                                continue
                            if key == "device_connected":
                                connected_devices.append(device)
                            else:
                                nearby_devices.append(device)
                    visit(child)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(payload)
        return connected_devices, nearby_devices

    def _system_profiler_bluetooth_device(self, item: dict, *, source_bucket: str) -> dict[str, str]:
        name = str(item.get("_name") or item.get("device_name") or item.get("name") or "").strip()
        address = str(item.get("device_address") or item.get("address") or item.get("DeviceAddress") or "").strip()
        if not (name or address):
            return {}
        return {
            "name": name or "unknown Bluetooth device",
            "address": address,
            "vendor_id": str(item.get("device_vendorID") or item.get("vendor_id") or ""),
            "product_id": str(item.get("device_productID") or item.get("product_id") or ""),
        }

    def _usb_key(self, item: dict[str, str]) -> str:
        return "|".join(str(item.get(key, "")) for key in ["vendor_id", "product_id", "serial", "location_id", "session_id"])

    def usb_physical_key(self, item: dict[str, str]) -> str:
        serial = str(item.get("serial", "")).strip()
        keys = ["vendor_id", "product_id", "serial"] if serial else ["vendor_id", "product_id", "name", "location_id"]
        return "|".join(str(item.get(key, "")).strip() for key in keys)

    def _bluetooth_key(self, item: dict[str, str]) -> str:
        address = str(item.get("address", "")).strip()
        return address or "|".join(str(item.get(key, "")).strip() for key in ["vendor_id", "product_id", "name"])

    def _usb_label(self, item: dict[str, str]) -> str:
        vendor = str(item.get("vendor", "")).strip()
        name = str(item.get("name", "")).strip() or "unknown USB device"
        serial = str(item.get("serial", "")).strip()
        label = f"{vendor} {name}".strip()
        session_id = str(item.get("session_id", "")).strip()
        details = ", ".join(part for part in [f"serial={serial}" if serial else "", f"connection={session_id}" if session_id else ""] if part)
        return f"{label} ({details})" if details else label

    def _bluetooth_label(self, item: dict[str, str]) -> str:
        name = str(item.get("name", "")).strip() or "unknown Bluetooth device"
        address = str(item.get("address", "")).strip()
        return f"{name} (address={address})" if address else name

    def _event(
        self,
        *,
        timestamp: str,
        event_type: str,
        severity: str,
        source: str,
        evidence: str,
        confidence: str,
        recommendation: str,
        metadata: dict,
        identity: str = "",
        rule=None,
        previous_state: str = "",
        current_state: str = "",
    ) -> BackgroundMonitorEvent:
        identity_suffix = f"-{hashlib.sha256(identity.encode()).hexdigest()[:12]}" if identity else ""
        rule = rule or rule_for_event(event_type)
        raw_summary = evidence
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{source}{identity_suffix}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source=source,
            evidence=evidence,
            confidence=confidence,
            recommendation=recommendation,
            metadata_json=json.dumps(metadata, sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="hardware_detector",
            trigger_subsource=(
                "ioreg_usb"
                if event_type in {"usb_device_connected", "new_usb_device_detected"}
                else ("ioreg_bluetooth" if event_type == "bluetooth_device_connected" else "hardware_log")
            ),
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=raw_summary,
            normalized_signal=normalized_signal(event_type, raw_summary, metadata),
            evidence_hash=evidence_hash(event_type, raw_summary, metadata),
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state=previous_state,
            current_state=current_state,
            baseline_status="hardware change",
            correlation_id=correlation_id_for(event_type, source, identity or source, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Evidence={raw_summary}",
        )


class USBReconnectObserver:
    def __init__(self, monitor: HardwareMonitor, poll_seconds: float = 1.0, quiet_window_seconds: float = 0.0) -> None:
        self.monitor = monitor
        self.poll_seconds = max(0.25, poll_seconds)
        self.quiet_window_seconds = max(0.0, quiet_window_seconds)
        self.events: queue.Queue[BackgroundMonitorEvent] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="mac-audit-usb-observer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.poll_seconds * 2))

    def drain(self) -> list[BackgroundMonitorEvent]:
        drained = []
        while True:
            try:
                drained.append(self.events.get_nowait())
            except queue.Empty:
                return drained

    def _run(self) -> None:
        previous = self.monitor.collect_usb_devices()
        pending_previous: list[dict[str, str]] | None = None
        pending_current: list[dict[str, str]] | None = None
        last_topology_change = 0.0
        while not self._stop.wait(self.poll_seconds):
            current = self.monitor.collect_usb_devices()
            previous_keys = {self.monitor._usb_key(item) for item in previous}
            current_keys = {self.monitor._usb_key(item) for item in current}
            if current_keys != previous_keys:
                if self.quiet_window_seconds <= 0:
                    new_events = self.monitor.usb_connection_events(previous, current)
                    for event in new_events:
                        self.events.put(event)
                else:
                    if pending_previous is None:
                        pending_previous = previous
                    pending_current = current
                last_topology_change = time.monotonic()
            if pending_previous is not None and pending_current is not None and time.monotonic() - last_topology_change >= self.quiet_window_seconds:
                final_physical_keys = {self.monitor.usb_physical_key(item) for item in pending_current}
                pending_events = self.monitor.usb_connection_events(pending_previous, pending_current)
                for event in pending_events:
                    if event.event_type == "usb_device_removed":
                        try:
                            metadata = json.loads(event.metadata_json)
                        except json.JSONDecodeError:
                            metadata = {}
                        if self.monitor.usb_physical_key(metadata) in final_physical_keys:
                            continue
                    self.events.put(event)
                pending_previous = None
                pending_current = None
            previous = current
