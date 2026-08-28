from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sqlite3
import threading
import time
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Callable

from .analyzer import RCEAnalyzer
from .config import RCEConfig, load_rce_config
from .models import EventType, RCEEvent, TelemetryEvent, utc_now
from .repository import RCERepository
from .inventory import MacOSInventory
from .cve import CVECorrelator
from .attack import RCEAttackValidator
from .crash_diagnostics import CrashDiagnosticCollector

PS = Path("/bin/ps")


class RCEMonitorService:
    """Polling fallback integrated into MSAA's existing LaunchDaemon.

    It deliberately reports degraded coverage: polling cannot provide the
    completeness, memory telemetry, or pre-exec visibility of Endpoint Security.
    """
    def __init__(self, repository: RCERepository, config_path: Path | None = None, executor: Callable[..., Any] | None = None) -> None:
        self.repository=repository; self.config_path=config_path; self.config=load_rce_config(config_path)
        self.analyzer=RCEAnalyzer(self.config); self.executor=executor or subprocess.run
        self.known: dict[int,dict[str,Any]]={}; self.running=False; self.last_cycle=""; self.last_error=""; self._config_digest=self._digest_config(); self._last_inventory=0.0
        self._ingest_queue: Queue[TelemetryEvent] = Queue(maxsize=self.config.queue_limit)
        self._result_queue: Queue[RCEEvent] = Queue(maxsize=max(32, min(self.config.queue_limit, 2048)))
        self._worker_stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._analysis_lock = threading.Lock()
        self._queue_drops = 0
        diagnostic_roots = [Path("/Library/Logs/DiagnosticReports")]
        users_root = Path("/Users")
        try:
            diagnostic_roots.extend(home / "Library/Logs/DiagnosticReports" for home in users_root.iterdir() if home.is_dir())
        except OSError:
            pass
        self.crash_diagnostics = CrashDiagnosticCollector(diagnostic_roots[:64])

    def _digest_config(self)->str:
        if not self.config_path or not self.config_path.exists(): return "defaults"
        return hashlib.sha256(self.config_path.read_bytes()).hexdigest()

    def reload(self)->bool:
        try: candidate=load_rce_config(self.config_path)
        except (OSError,ValueError,json.JSONDecodeError) as exc:
            self.last_error=f"configuration reload rejected: {type(exc).__name__}"
            self.repository.record_health(RCEAnalyzer.health_failure(self.last_error,"rce_config"),"CONFIG_RELOAD_FAILURE")
            return False
        changed=self._digest_config()!=self._config_digest
        with self._analysis_lock:
            self.config=candidate; self.analyzer=RCEAnalyzer(candidate)
        self._config_digest=self._digest_config()
        if changed:
            event=RCEEvent(event_type=EventType.POLICY_TAMPER.value,severity="medium",confidence="high",confidence_basis="configuration content hash changed",observed_behavior=["RCE monitor configuration changed and passed strict validation."],matching_signals=["configuration change"],source_sensor="rce_config",sensor_health="healthy",recommended_validation=["Confirm the approved configuration deployment record."])
            self.repository.store_event(event)
        return True

    def start(self)->None:
        self.running=True
        self.repository.record_health(RCEEvent(event_type=EventType.SENSOR_DEGRADED.value,severity="medium",confidence="high",confidence_basis="Endpoint Security entitlement unavailable to Python LaunchDaemon",observed_behavior=["RCE monitoring started with bounded process polling and existing MSAA network/file metadata; complete exec, memory, and injection telemetry is unavailable."],matching_signals=["fallback telemetry active"],source_sensor="rce_process_poll",sensor_health="degraded_polling",recommended_validation=["Install a future entitled Endpoint Security collector to close documented telemetry gaps."]),"DEGRADED_POLLING_ACTIVE")
        self.repository.record_health(RCEEvent(event_type=EventType.INJECTION_SENSOR_DEGRADED.value,severity="medium",confidence="high",confidence_basis="macOS entitlement and sensor capability evaluation",observed_behavior=["Process injection monitoring has process polling and snapshot enrichment but lacks live cross-task memory and thread telemetry."],matching_signals=["partial process-injection sensor coverage"],source_sensor="process_injection_sensor",sensor_health="degraded_polling",sensor_reliability=30,telemetry_gaps=["task-port acquisition unavailable","cross-task memory write unavailable","thread-state modification unavailable","module event stream unavailable"],recommended_validation=["Treat unobserved primitives as UNKNOWN and deploy a reviewed entitled native sensor when available."]),"PROCESS_INJECTION_PARTIAL_COVERAGE")
        attack=RCEAttackValidator(Path(self.config.attack_data_path) if self.config.attack_data_path else None,freshness_hours=self.config.attack_freshness_hours).status()
        if attack.get("status") in {"UNAVAILABLE","STALE","INVALID"}:
            self.repository.record_health(RCEEvent(event_type=EventType.HEALTH_FAILURE.value,severity="low",confidence="high",confidence_basis="configured ATT&CK data status",observed_behavior=[f"ATT&CK data status is {attack.get('status')}; deterministic detection continues but mappings are unverified or stale."],matching_signals=["ATT&CK reference data unavailable or stale"],source_sensor="attack_validator",sensor_health="degraded",recommended_validation=["Import and approve a current ATT&CK STIX bundle and record its version, retrieval date, and hash."]),f"ATTACK_DATA_{attack.get('status')}")

    def stop(self)->None:
        self.running=False
        self._worker_stop.set()
        if self._worker is not None and self._worker.is_alive():
            self._worker.join(timeout=1.0)

    def submit(self, telemetry: TelemetryEvent) -> bool:
        """Accept native/event-bus telemetry without blocking its sensor thread."""
        self._ensure_worker()
        try:
            self._ingest_queue.put_nowait(telemetry)
            return True
        except Full:
            self._queue_drops += 1
            return False

    def _ensure_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self.running = True
        self._worker_stop.clear()
        self._worker = threading.Thread(target=self._worker_loop, name="msaa-rce-enrichment", daemon=True)
        self._worker.start()

    def drain_async_findings(self, maximum: int = 256) -> list[RCEEvent]:
        findings: list[RCEEvent] = []
        for _ in range(max(1, min(maximum, 2048))):
            try:
                findings.append(self._result_queue.get_nowait())
            except Empty:
                break
        return findings

    def _worker_loop(self) -> None:
        worker_repository = RCERepository(self.repository.path) if self.repository.path is not None else self.repository
        try:
            while not self._worker_stop.is_set():
                try:
                    telemetry = self._ingest_queue.get(timeout=0.25)
                except Empty:
                    continue
                try:
                    finding = self.ingest(telemetry, repository=worker_repository)
                    if finding is not None:
                        try:
                            self._result_queue.put_nowait(finding)
                        except Full:
                            # The canonical repository still holds the finding;
                            # only this bounded GUI-delivery item is omitted.
                            self._queue_drops += 1
                finally:
                    self._ingest_queue.task_done()
        finally:
            if worker_repository is not self.repository:
                worker_repository.conn.close()

    def ingest(self, telemetry: TelemetryEvent, *, repository: RCERepository | None = None) -> RCEEvent | None:
        """Persist a redacted base observation before best-effort enrichment."""
        active_repository = repository or self.repository
        safe = self.analyzer.sanitize(telemetry)
        try:
            ingestion_id = active_repository.store_raw_observation(safe.__dict__, observed_at=safe.observed_at, sensor=safe.sensor, maximum_rows=max(self.config.queue_limit * 4, 1000))
        except (sqlite3.Error, OSError) as exc:
            self.last_error = f"RCE evidence database unavailable: {type(exc).__name__}"
            return RCEAnalyzer.health_failure(self.last_error, "rce_repository")
        try:
            with self._analysis_lock:
                candidate = self.analyzer.analyze(safe)
            if candidate is None:
                active_repository.complete_raw_observation(ingestion_id, status="NO_FINDING")
                return None
            if safe.kind == "memory_safety_crash":
                candidate.assumptions.append("A memory-safety crash is not proof that an attacker controlled execution.")
                candidate.unknowns.extend(item for item in ("exploitability unknown", "remote origin unknown", "CVE identity unknown") if item not in candidate.unknowns)
                candidate.recommended_validation.extend([
                    "Preserve the original IPS report and its SHA-256 hash.",
                    "Correlate the crash time with process ancestry, network activity, Unified Logging, and repeated inputs.",
                    "Use only approved local CVE data for product/version or behavioral correlation.",
                ])
            similarities = safe.metadata.get("cve_similarities", [])
            if isinstance(similarities, list):
                correlator = CVECorrelator(active_repository)
                for item in similarities[:16]:
                    if not isinstance(item, dict):
                        continue
                    matching = [str(value) for value in item.get("matching_criteria", [])]
                    similarity = int(item.get("similarity", 0) or 0)
                    if len(matching) < 3 or similarity < 60:
                        continue
                    try:
                        candidate.cve_correlations.append(correlator.behavior_similarity(str(item.get("cve_id", "")), candidate.why_flagged, matching, [str(value) for value in item.get("unknown_criteria", [])], similarity))
                    except ValueError:
                        continue
            candidate.evidence_references = list(dict.fromkeys([*candidate.evidence_references, f"rce-ingest:{ingestion_id}"]))
            event_id = active_repository.store_event(candidate,raw_payload=safe.__dict__,max_representatives=self.config.max_representative_evidence)
            candidate.event_id = event_id
            if candidate.injection_analysis:
                research_id=active_repository.store_injection_analysis(event_id,candidate.injection_analysis,host_id=candidate.host_id)
                if research_id:
                    candidate.injection_analysis["research_candidate_id"]=research_id
            active_repository.complete_raw_observation(ingestion_id, status="ENRICHED")
            return candidate
        except Exception as exc:
            try:
                active_repository.complete_raw_observation(ingestion_id, status="ENRICHMENT_FAILED", error_type=type(exc).__name__)
            except (sqlite3.Error, OSError):
                pass
            failure = RCEAnalyzer.health_failure(f"RCE enrichment failed after the redacted base observation was preserved: {type(exc).__name__}", "rce_enrichment")
            try:
                active_repository.record_health(failure, "PARSER_EXCEPTION_ISOLATED")
            except (sqlite3.Error, OSError):
                self.last_error = "RCE enrichment and health persistence failed; the service remains operational"
            return failure

    def collect_processes(self)->list[dict[str,Any]]:
        if not PS.is_file(): raise RuntimeError("fixed ps executable unavailable")
        completed=self.executor([str(PS),"-axo","pid=,ppid=,user=,comm=,args="],capture_output=True,text=True,timeout=4,check=False)
        if completed.returncode != 0: raise RuntimeError("process telemetry command failed")
        if len(completed.stdout.encode("utf-8",errors="replace"))>4*1024*1024: raise RuntimeError("process telemetry exceeded 4 MiB")
        rows=[]
        for line in completed.stdout.splitlines()[:50_000]:
            parts=line.strip().split(None,4)
            if len(parts)<4: continue
            try: pid,ppid=int(parts[0]),int(parts[1])
            except ValueError: continue
            rows.append({"pid":pid,"ppid":ppid,"user":parts[2],"executable":parts[3],"command_line":parts[4] if len(parts)>4 else parts[3]})
        return rows

    def run_once(self)->list[RCEEvent]:
        if not self.running: self.start()
        if not self.config.enabled:
            event=RCEAnalyzer.health_failure("RCE monitoring is manually disabled by validated configuration.","rce_monitor")
            self.repository.record_health(event,"MONITORING_DISABLED"); return [event]
        emitted=[]
        try:
            # Crash artifacts carry their original timestamps. Analyze them
            # before polling new children so a same-cycle crash-to-exec chain
            # can be correlated by the degraded fallback.
            for finding in self.crash_diagnostics.collect_recent():
                candidate = self.ingest(finding.telemetry)
                if candidate:
                    emitted.append(candidate)
            current={row["pid"]:row for row in self.collect_processes()}
            for pid,process in current.items():
                if pid in self.known: continue
                parent=current.get(process["ppid"]) or self.known.get(process["ppid"],{})
                parent_name=Path(str(parent.get("executable",""))).name.lower()
                service_parent=parent_name in {"httpd","nginx","apache2","php-fpm","java","tomcat","mysqld","postgres","redis-server","sshd","cupsd","smbd"}
                telemetry=TelemetryEvent(kind="process_start",process=process,parent_process={**parent,"is_service":service_parent} if parent else {},user_context={"account":process.get("user","")},service_context={"network_facing":service_parent},metadata={"sensor_health":"degraded_polling","sensor_reliability":"degraded","telemetry_gaps":["Endpoint Security task/thread/memory telemetry unavailable","polling may miss short-lived processes"],"benign_contexts":self.repository.list_benign_contexts()})
                candidate=self.ingest(telemetry)
                if candidate:
                    emitted.append(candidate)
            self.known=current; self.last_cycle=utc_now(); self.last_error=""
            if time.monotonic()-self._last_inventory >= self.config.inventory_interval_seconds:
                emitted.extend(self.assess_inventory()); self._last_inventory=time.monotonic()
        except (OSError,subprocess.SubprocessError,RuntimeError,ValueError) as exc:
            self.last_error=f"process sensor failure: {type(exc).__name__}"
            event=RCEAnalyzer.health_failure(self.last_error,"rce_process_poll"); self.repository.record_health(event,"SENSOR_FAILURE"); emitted.append(event)
        return emitted

    def assess_inventory(self)->list[RCEEvent]:
        emitted=[]; correlator=CVECorrelator(self.repository)
        records=self.repository.conn.execute("SELECT cve_id,payload_json FROM rce_cve_records").fetchall()
        if not records: return emitted
        items=MacOSInventory().collect()
        by_name={"".join(c.lower() for c in item.product if c.isalnum()):item for item in items}
        for row in records:
            payload=json.loads(row["payload_json"]); key="".join(c.lower() for c in str(payload.get("product","")) if c.isalnum()); item=by_name.get(key)
            if not item: continue
            try: correlation=correlator.exposure(cve_id=row["cve_id"],product=item.product,version=item.version,backport_fixed=item.backport_fixed,mitigated=item.mitigated)
            except ValueError: continue
            if correlation.relationship_type!="EXACT_PRODUCT_VERSION_EXPOSURE": continue
            event=RCEEvent(event_type=EventType.EXPOSURE.value,severity="high",confidence="high",confidence_basis=correlation.confidence_basis,observed_behavior=[correlation.observed_behavior_summary],matching_signals=["validated product-version exposure"],source_sensor="rce_package_inventory",sensor_health="degraded_polling",package_context={"product":item.product,"version":item.version,"source":item.source,"path":item.path},cve_correlations=[correlation],unknowns=["exploitation status unknown","network reachability may be unknown"],recommended_validation=correlation.validation_required)
            self.repository.store_event(event); emitted.append(event)
        return emitted

    def status(self)->dict[str,Any]:
        return {**self.repository.status(),"running":self.running,"last_cycle":self.last_cycle,"last_error":self.last_error,"sensor_mode":"DEGRADED_POLLING","endpoint_security_available":False,"monitor_only":True,"correlation_buffer_depth":len(self.analyzer.recent),"correlation_buffer_limit":self.analyzer.recent.maxlen,"correlation_evictions":self.analyzer.dropped_events,"ingest_queue_depth":self._ingest_queue.qsize(),"ingest_queue_limit":self._ingest_queue.maxsize,"result_queue_depth":self._result_queue.qsize(),"dropped_delivery_events":self._queue_drops,"worker_alive":bool(self._worker and self._worker.is_alive()),"operation_mode":self.config.operation_mode}
