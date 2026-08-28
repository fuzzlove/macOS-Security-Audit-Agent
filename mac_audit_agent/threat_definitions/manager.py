"""Orchestration for isolated source updates, validation, activation, and health."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from .intelligence import MalwareIntelligenceDatabase, SourceHealthDatabase
from .lifecycle import apply_default_expiration, evaluate_lifecycle
from .locking import DefinitionUpdateLock
from .models import (
    DefinitionFreshness,
    DefinitionHealth,
    DefinitionHealthState,
    DefinitionType,
    SourceStatus,
    ThreatDefinition,
    ValidationState,
    utc_now,
)
from .normalization import definition_id, normalize_value
from .policy import DEFAULT_DEFINITION_POLICY, MalwareDefinitionPolicy
from .sensor_reload import DefinitionSensorReloadCoordinator
from .signing import ManifestSigner
from .sources import (
    CISAKEVAdapter,
    MalwareBazaarAdapter,
    SignedBundleAdapter,
    SourceAdapterError,
    SourceRegistry,
    ThreatFoxAdapter,
    URLhausAdapter,
    YaraForgeAdapter,
    load_source_registry,
    redact_source_url,
)
from .store import DEFAULT_DEFINITION_ROOT, BundleError, DefinitionStore
from .validation import DefinitionValidator, deduplicate, split_yara_rules

SYSTEM_SOURCE_CONFIG = Path("/Library/Application Support/MSAA/config/definition_sources.json")


class UpdateRejected(RuntimeError):
    pass


class ThreatIntelligenceManager:
    def __init__(
        self, store: DefinitionStore, *, registry: SourceRegistry | None = None,
        validator: DefinitionValidator | None = None,
        reload_callback: Callable[[Path], bool] | None = None,
        status_cache_path: Path | None = None,
        policy: MalwareDefinitionPolicy = DEFAULT_DEFINITION_POLICY,
    ) -> None:
        self.store = store
        self.registry = registry or SourceRegistry()
        self.validator = validator or DefinitionValidator()
        self.policy = policy
        self.reload_coordinator = DefinitionSensorReloadCoordinator(self.store)
        self.reload_callback = reload_callback or self.reload_coordinator.validate_and_request
        self.status_cache_path = Path(status_cache_path) if status_cache_path else self.store.metadata_dir / "public-status.json"
        self.update_lock = DefinitionUpdateLock(self.store.root / "update.lock")
        self.source_database = SourceHealthDatabase(self.store.metadata_dir / "definition_sources.sqlite3")
        try:
            for adapter in self.registry.all():
                self.source_database.sync_policy(
                    adapter.policy,
                    source_type=str(getattr(adapter, "source_type", "signed_bundle" if getattr(adapter, "bundle_package", False) else "provider")),
                    url=redact_source_url(str(getattr(adapter, "url", ""))) or None,
                )
        except (OSError, sqlite3.DatabaseError, ValueError):
            # Source-health persistence cannot disable the definition engine.
            self.source_database = SourceHealthDatabase(self.store.metadata_dir / "definition_sources.sqlite3")

    @property
    def _state_path(self) -> Path:
        return self.store.metadata_dir / "update_state.json"

    def _state(self) -> dict[str, Any]:
        path = self._state_path
        try:
            info = path.lstat()
        except FileNotFoundError:
            return {"sources": {}}
        if path.is_symlink() or not path.is_file() or info.st_size > 1024 * 1024:
            return {"sources": {}}
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            return document if isinstance(document, dict) else {"sources": {}}
        except json.JSONDecodeError:
            return {"sources": {}}

    def _save_state(self, state: dict[str, Any]) -> None:
        self.store._atomic_json(self._state_path, state)  # same fsync/rename primitive as activation pointers

    def source_statuses(self) -> list[dict[str, Any]]:
        state = self._state().get("sources", {})
        try:
            database_rows = {row["source_id"]: row for row in self.source_database.rows()}
        except (OSError, sqlite3.DatabaseError):
            database_rows = {}
        output: list[dict[str, Any]] = []
        for adapter in self.registry.all():
            stored = state.get(adapter.source_id, {}) if isinstance(state, dict) else {}
            setup: dict[str, str] | None = None
            if adapter.policy.enabled and hasattr(adapter, "setup_requirement"):
                try:
                    setup = adapter.setup_requirement()
                except SourceAdapterError as exc:
                    setup = {"status": "SETUP_ERROR", "reason": str(exc)}
            default_state = "DISABLED" if not adapter.policy.enabled else "NEVER_UPDATED"
            displayed_state = str(stored.get("state", default_state))
            if setup and not stored.get("last_success"):
                displayed_state = setup["status"]
            output.append({
                **SourceStatus(
                    adapter.source_id, displayed_state, adapter.policy.enabled,
                    _time(stored.get("last_attempt")), _time(stored.get("last_success")), stored.get("version"),
                    int(stored.get("definition_count", 0)), str(stored.get("error", "")),
                ).to_dict(),
                "policy": adapter.policy.to_dict(),
                "health": database_rows.get(adapter.source_id, {}),
                "setup": setup or {},
            })
        return output

    def _source_policies(self) -> dict[str, Any]:
        return {adapter.source_id: adapter.policy for adapter in self.registry.all()}

    def _active_contains_source(self, source_id: str) -> bool:
        if self.store.active_bundle_path() is None:
            return False
        try:
            return any(
                provenance.source_id == source_id
                for item in self.store.definitions()
                for provenance in item.provenance
            )
        except (BundleError, OSError, ValueError):
            return False

    def _download_with_bootstrap_recovery(self, adapter, source_state: dict[str, Any]):
        """Retry once without validators when 304 cannot be satisfied locally."""
        if hasattr(adapter, "set_conditional_headers"):
            adapter.set_conditional_headers(etag=source_state.get("etag"), last_modified=source_state.get("last_modified"))
        package = adapter.download()
        not_modified = package.metadata.get("not_modified") == "true" or str(package.metadata.get("http_status")) == "304"
        if not_modified and not self._active_contains_source(adapter.source_id):
            if hasattr(adapter, "set_conditional_headers"):
                adapter.set_conditional_headers()
            package = adapter.download()
            package.metadata["bootstrap_retry"] = "true"
        return package

    def _record_source_health(
        self,
        adapter,
        outcome: str,
        *,
        package=None,
        latency: float = 0.0,
        version: str = "",
        incoming_count: int = 0,
        error: str = "",
    ) -> None:
        try:
            metadata = package.metadata if package is not None else {}
            source_type = str(getattr(adapter, "source_type", ""))
            yara_count = incoming_count if source_type == "yara" else 0
            indicator_count = incoming_count - yara_count
            self.source_database.record(
                adapter.source_id, outcome=outcome, latency=latency,
                last_http_status=int(metadata.get("http_status", 0) or 0) or None,
                etag=metadata.get("etag"), last_modified=metadata.get("last-modified"),
                current_version=version or None,
                current_sha256=hashlib.sha256(package.payload).hexdigest() if package is not None and package.payload else None,
                rules_received=yara_count, rules_accepted=yara_count,
                rules_rejected=int(metadata.get("records_rejected", 0) or 0) if source_type == "yara" else 0,
                indicators_received=int(metadata.get("records_received", incoming_count) or incoming_count) if source_type != "yara" else 0,
                indicators_accepted=indicator_count,
                indicators_rejected=int(metadata.get("records_rejected", 0) or 0) if source_type != "yara" else 0,
                last_error=error,
            )
        except (OSError, sqlite3.DatabaseError, TypeError, ValueError):
            # Source metrics cannot change whether a validated release activates.
            return

    def _validated_source_items(self, adapter, incoming: list[ThreatDefinition]) -> tuple[list[ThreatDefinition], int]:
        """Keep valid definitions when one independently isolatable YARA rule is malformed."""
        complete = self.validator.validate(incoming)
        if complete.accepted:
            return incoming, 0
        non_yara = [item for item in incoming if item.definition_type != DefinitionType.YARA_RULE]
        non_yara_validation = self.validator.validate(non_yara, run_yara_gate=False)
        if not non_yara_validation.accepted:
            raise UpdateRejected("; ".join(issue.message for issue in non_yara_validation.issues))
        accepted = list(non_yara)
        rejected = 0
        for definition in (item for item in incoming if item.definition_type == DefinitionType.YARA_RULE):
            validation = self.validator.validate([definition])
            if validation.accepted:
                accepted.append(definition)
                continue
            candidates = split_yara_rules(definition.value)
            if not candidates:
                rejected += 1
                self.store.quarantine_yara(adapter.source_id, str(definition.metadata.get("rule_name", definition.definition_id)), definition.value, "; ".join(issue.message for issue in validation.issues))
                continue
            candidate_rejected = 0
            for rule_name, source in candidates:
                canonical = normalize_value(DefinitionType.YARA_RULE, source)
                candidate = replace(
                    definition, definition_id=definition_id(DefinitionType.YARA_RULE, canonical), value=canonical,
                    metadata={**definition.metadata, "rule_name": rule_name, "namespace": str(getattr(adapter, "source_id", "community"))},
                )
                result = self.validator.validate([candidate])
                if result.accepted:
                    accepted.append(candidate)
                else:
                    rejected += 1
                    candidate_rejected += 1
                    self.store.quarantine_yara(adapter.source_id, rule_name, source, "; ".join(issue.message for issue in result.issues))
            # The original package failed compilation but every extracted rule
            # compiled. Preserve the unparsed residue (for example a truncated
            # final rule) as one rejected artifact instead of silently losing it.
            if candidate_rejected == 0:
                rejected += 1
                self.store.quarantine_yara(
                    adapter.source_id, "unparsed_package_residue", definition.value,
                    "; ".join(issue.message for issue in validation.issues),
                )
        final = self.validator.validate(accepted)
        if not accepted or not final.accepted:
            raise UpdateRejected("source definitions did not contain a valid, independently loadable set")
        return accepted, rejected

    def update_source(
        self, source_id: str, *, signer: ManifestSigner | None = None, activate: bool = False,
        version: str | None = None, allow_early_update: bool = False,
    ) -> dict[str, Any]:
        with self.update_lock:
            return self._update_source(source_id, signer=signer, activate=activate, version=version, allow_early_update=allow_early_update)

    def _update_source(
        self, source_id: str, *, signer: ManifestSigner | None = None, activate: bool = False,
        version: str | None = None, allow_early_update: bool = False,
    ) -> dict[str, Any]:
        adapter = self.registry.get(source_id)
        state = self._state()
        sources = state.setdefault("sources", {})
        source_state = sources.setdefault(source_id, {})
        now = utc_now()
        last_attempt = _time(source_state.get("last_attempt"))
        if last_attempt and not allow_early_update and (now - last_attempt).total_seconds() < adapter.policy.minimum_interval_seconds:
            raise UpdateRejected("provider rate-limit window has not elapsed")
        source_state.update({"state": "UPDATING", "last_attempt": now.isoformat(), "error": ""})
        state["last_update_attempt"] = now.isoformat()
        self._save_state(state)
        self.store._record("DEF_UPDATE_STARTED", source_id, "Definition source update started.")
        started = time.monotonic()
        download_workspace: Path | None = None
        try:
            package = self._download_with_bootstrap_recovery(adapter, source_state)
            download_workspace = self.store.stage_download_artifact(source_id, package.payload)
            if package.metadata.get("not_modified") == "true" or str(package.metadata.get("http_status")) == "304":
                source_state.update({"state": "ACTIVE" if self.store.active_bundle_path() else "NEVER_UPDATED", "last_success": now.isoformat(), "error": ""})
                self._save_state(state)
                self._record_source_health(adapter, "success", package=package, latency=time.monotonic() - started)
                self.store._record("DEF_SOURCE_NOT_MODIFIED", source_id, "Provider reported that its artifact is unchanged.")
                return {"status": "NOT_MODIFIED", "source_id": source_id, "version": source_state.get("version"), "active_definitions_unchanged": True}
            if package.expected_sha256 and hashlib.sha256(package.payload).hexdigest() != package.expected_sha256.lower():
                raise UpdateRejected("provider artifact SHA-256 does not match expected metadata")
            if bool(package.metadata.get("signed_bundle")):
                previous_status = self.status()
                temporary_bundle = download_workspace / "source.download"
                imported = self.import_offline(temporary_bundle, activate=False)
                new_count = int(imported.get("manifest", {}).get("definition_count", 0))
                delta = self.validator.validate_delta(int(previous_status.get("definition_count", 0)), new_count, adapter.policy)
                if not delta.accepted:
                    self.store.reject_staged(str(imported["version"]), "Signed release failed provider-specific change guard.")
                    raise UpdateRejected("signed release failed empty-feed or suspicious-change protection")
                if activate:
                    imported["activation"] = self.activate(str(imported["version"]))
                source_state.update({
                    "state": "ACTIVE" if activate else "STAGED", "last_success": now.isoformat(),
                    "version": imported.get("version"), "definition_count": new_count, "error": "",
                })
                state["last_successful_update"] = now.isoformat()
                self._save_state(state)
                self._record_source_health(adapter, "success", package=package, latency=time.monotonic() - started, version=str(imported.get("version") or ""), incoming_count=new_count)
                self.store._record("DEF_UPDATE_SUCCESS", str(imported.get("version") or source_id), "Signed definition release update completed.")
                return {**imported, "status": source_state["state"], "source_id": source_id}
            incoming = [evaluate_lifecycle(apply_default_expiration(item)) for item in adapter.parse(package)]
            incoming, rejected_yara = self._validated_source_items(adapter, incoming)
            if rejected_yara:
                package.metadata["records_rejected"] = int(package.metadata.get("records_rejected", 0) or 0) + rejected_yara
            previous = self.store.definitions() if self.store.active_bundle_path() else []
            previous_source_count = sum(any(provenance.source_id == source_id for provenance in item.provenance) for item in previous)
            delta = self.validator.validate_delta(previous_source_count, len(incoming), adapter.policy)
            if not delta.accepted:
                raise UpdateRejected("; ".join(issue.message for issue in delta.issues))
            source_validation = self.validator.validate(incoming)
            if not source_validation.accepted:
                raise UpdateRejected("; ".join(issue.message for issue in source_validation.issues))
            retained: list[ThreatDefinition] = []
            for item in previous:
                provenance = tuple(entry for entry in item.provenance if entry.source_id != source_id)
                if provenance:
                    retained.append(replace(item, provenance=provenance))
            combined, conflicts = deduplicate((*retained, *incoming))
            validation = self.validator.validate(combined)
            if not validation.accepted:
                raise UpdateRejected("combined definition bundle did not pass validation")
            bundle_version = version or self._next_version()
            artifact_sha256 = hashlib.sha256(package.payload).hexdigest()
            manifest = self.store.stage(
                bundle_version, combined,
                source_versions={source_id: str(package.metadata.get("etag") or package.metadata.get("last-modified") or now.strftime("%Y%m%dT%H%M%SZ"))},
                source_hashes={source_id: artifact_sha256}, source_policies=self._source_policies(), signer=signer,
            )
            source_state.update({
                "state": "STAGED", "last_success": now.isoformat(), "version": bundle_version,
                "definition_count": len(incoming), "error": "", "etag": package.metadata.get("etag"),
                "last_modified": package.metadata.get("last-modified"), "current_sha256": artifact_sha256,
            })
            state["last_successful_update"] = now.isoformat()
            self._save_state(state)
            result: dict[str, Any] = {
                "status": "STAGED", "source_id": source_id, "version": bundle_version,
                "incoming_count": len(incoming), "active_count": len(combined), "conflicts": conflicts,
                "manifest": manifest, "validation": validation.to_dict(),
            }
            if activate:
                result["activation"] = self.activate(bundle_version)
                source_state["state"] = "ACTIVE"
                self._save_state(state)
            self._record_source_health(adapter, "success", package=package, latency=time.monotonic() - started, version=bundle_version, incoming_count=len(incoming))
            self.store._record("DEF_UPDATE_SUCCESS", bundle_version, f"Source {source_id} update completed with {len(incoming)} accepted definitions.")
            return result
        except Exception as exc:
            source_state.update({"state": "FAILED", "error": str(exc)[:512]})
            self._save_state(state)
            self._record_source_health(adapter, "failure", latency=time.monotonic() - started, error=str(exc))
            self.store._record("DEF_UPDATE_FAILURE", source_id, f"{type(exc).__name__}: {str(exc)[:400]}")
            if isinstance(exc, (UpdateRejected, BundleError, SourceAdapterError)):
                raise
            raise UpdateRejected(f"source update failed safely: {type(exc).__name__}") from exc
        finally:
            if download_workspace is not None:
                self.store.discard_download_artifact(download_workspace)

    def update_enabled(
        self, *, signer: ManifestSigner | None = None, activate: bool = False,
        allow_early_update: bool = False, source_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        with self.update_lock:
            return self._update_enabled(
                signer=signer, activate=activate, allow_early_update=allow_early_update,
                source_ids=source_ids,
            )

    def _update_enabled(
        self, *, signer: ManifestSigner | None = None, activate: bool = False,
        allow_early_update: bool = False, source_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Compile enabled raw feeds into one provenance-preserving bundle.

        Provider downloads and validation remain isolated, so one failed feed
        does not erase either successful incoming knowledge or its own last
        known-good definitions. Prebuilt signed releases stay on their
        signature-verification path and are never unpacked/re-signed locally.
        """
        results: dict[str, Any] = {}
        self.store._record("DEF_UPDATE_STARTED", "enabled-sources", "Scheduled combined definition update started.")
        raw_adapters = []
        for adapter in self.registry.all():
            if source_ids is not None and adapter.source_id not in source_ids:
                results[adapter.source_id] = {"status": "NOT_DUE", "reason": "source schedule is not due"}
                continue
            if not adapter.policy.enabled:
                results[adapter.source_id] = {"status": "DISABLED", "reason": "source or licensing policy is not enabled"}
                continue
            try:
                setup_requirement = adapter.setup_requirement() if hasattr(adapter, "setup_requirement") else None
            except SourceAdapterError as exc:
                results[adapter.source_id] = {"status": "FAILED", "error": str(exc)}
                continue
            if setup_requirement:
                results[adapter.source_id] = dict(setup_requirement)
                continue
            if bool(getattr(adapter, "bundle_package", False)):
                try:
                    results[adapter.source_id] = self.update_source(
                        adapter.source_id, signer=signer, activate=activate,
                        allow_early_update=allow_early_update,
                    )
                except Exception as exc:  # noqa: BLE001 - one provider must not abort unrelated sources
                    results[adapter.source_id] = {"status": "FAILED", "error": str(exc)}
                continue
            raw_adapters.append(adapter)
        if not raw_adapters:
            results["_compilation"] = {
                "status": "NO_CHANGE",
                "reason": "no source is ready to download; complete any reported free setup requirements",
            }
            return results

        state = self._state()
        source_states = state.setdefault("sources", {})
        now = utc_now()
        state["last_update_attempt"] = now.isoformat()
        previous = self.store.definitions() if self.store.active_bundle_path() else []
        incoming_by_source: dict[str, list[ThreatDefinition]] = {}
        source_versions: dict[str, str] = {}
        source_hashes: dict[str, str] = {}
        for adapter in raw_adapters:
            source_state = source_states.setdefault(adapter.source_id, {})
            last_attempt = _time(source_state.get("last_attempt"))
            if last_attempt and not allow_early_update and (now - last_attempt).total_seconds() < adapter.policy.minimum_interval_seconds:
                results[adapter.source_id] = {"status": "NOT_DUE", "reason": "provider rate-limit window has not elapsed"}
                continue
            source_state.update({"state": "UPDATING", "last_attempt": now.isoformat(), "error": ""})
            started = time.monotonic()
            download_workspace: Path | None = None
            try:
                package = self._download_with_bootstrap_recovery(adapter, source_state)
                download_workspace = self.store.stage_download_artifact(adapter.source_id, package.payload)
                if package.metadata.get("not_modified") == "true" or str(package.metadata.get("http_status")) == "304":
                    results[adapter.source_id] = {"status": "NOT_MODIFIED"}
                    source_state.update({"state": "ACTIVE" if self.store.active_bundle_path() else "NEVER_UPDATED", "last_success": now.isoformat(), "error": ""})
                    self._record_source_health(adapter, "success", package=package, latency=time.monotonic() - started)
                    continue
                if package.expected_sha256 and hashlib.sha256(package.payload).hexdigest() != package.expected_sha256.lower():
                    raise UpdateRejected("provider artifact SHA-256 does not match expected metadata")
                incoming = [evaluate_lifecycle(apply_default_expiration(item)) for item in adapter.parse(package)]
                incoming, rejected_yara = self._validated_source_items(adapter, incoming)
                if rejected_yara:
                    package.metadata["records_rejected"] = int(package.metadata.get("records_rejected", 0) or 0) + rejected_yara
                previous_count = sum(any(entry.source_id == adapter.source_id for entry in item.provenance) for item in previous)
                delta = self.validator.validate_delta(previous_count, len(incoming), adapter.policy)
                validation = self.validator.validate(incoming)
                if not delta.accepted or not validation.accepted:
                    issues = (*delta.issues, *validation.issues)
                    raise UpdateRejected("; ".join(item.message for item in issues))
                incoming_by_source[adapter.source_id] = incoming
                source_versions[adapter.source_id] = str(package.metadata.get("etag") or package.metadata.get("last-modified") or now.strftime("%Y%m%dT%H%M%SZ"))
                source_hashes[adapter.source_id] = hashlib.sha256(package.payload).hexdigest()
                source_state.update({"etag": package.metadata.get("etag"), "last_modified": package.metadata.get("last-modified"), "current_sha256": source_hashes[adapter.source_id]})
                results[adapter.source_id] = {"status": "VALIDATED", "incoming_count": len(incoming)}
                self._record_source_health(adapter, "success", package=package, latency=time.monotonic() - started, incoming_count=len(incoming))
            except Exception as exc:  # noqa: BLE001 - provider/parser isolation boundary
                results[adapter.source_id] = {"status": "FAILED", "error": str(exc)}
                source_state.update({"state": "FAILED", "error": str(exc)[:512]})
                self._record_source_health(adapter, "failure", latency=time.monotonic() - started, error=str(exc))
            finally:
                if download_workspace is not None:
                    self.store.discard_download_artifact(download_workspace)
        self._save_state(state)
        required_failures = [
            adapter.source_id
            for adapter in raw_adapters
            if adapter.policy.required and results.get(adapter.source_id, {}).get("status") == "FAILED"
        ]
        if required_failures:
            results["_compilation"] = {
                "status": "REJECTED",
                "reason": "required source failure",
                "required_sources": required_failures,
                "active_definitions_unchanged": True,
            }
            return results
        if not incoming_by_source:
            setup_pending = [source_id for source_id, result in results.items() if result.get("status") == "SETUP_REQUIRED_FREE"]
            results["_compilation"] = {
                "status": "NO_CHANGE",
                "reason": (
                    "free community source setup is required before those feeds can download"
                    if setup_pending else "no enabled source produced a validated update"
                ),
                **({"setup_required_sources": setup_pending} if setup_pending else {}),
            }
            return results

        refreshed_sources = set(incoming_by_source)
        retained: list[ThreatDefinition] = []
        for item in previous:
            provenance = tuple(entry for entry in item.provenance if entry.source_id not in refreshed_sources)
            if provenance:
                retained.append(replace(item, provenance=provenance))
        incoming_all = [item for items in incoming_by_source.values() for item in items]
        combined, conflicts = deduplicate((*retained, *incoming_all))
        validation = self.validator.validate(combined)
        if not validation.accepted:
            for source_id in incoming_by_source:
                source_states[source_id].update({"state": "FAILED", "error": "combined definition bundle failed validation"})
                results[source_id] = {"status": "FAILED", "error": "combined definition bundle failed validation"}
            self._save_state(state)
            results["_compilation"] = {"status": "REJECTED", "validation": validation.to_dict()}
            return results

        bundle_version = self._next_version()
        manifest = self.store.stage(
            bundle_version, combined, source_versions=source_versions, source_hashes=source_hashes,
            source_policies=self._source_policies(), signer=signer,
        )
        for source_id, incoming in incoming_by_source.items():
            source_states[source_id].update({
                "state": "STAGED", "last_success": now.isoformat(), "version": bundle_version,
                "definition_count": len(incoming), "error": "",
            })
            results[source_id].update({"status": "STAGED", "version": bundle_version, "combined_definition_count": len(combined)})
        state["last_successful_update"] = now.isoformat()
        activation = None
        if activate:
            activation = self.activate(bundle_version)
            for source_id in incoming_by_source:
                source_states[source_id]["state"] = "ACTIVE"
                results[source_id]["status"] = "ACTIVE"
        self._save_state(state)
        results["_compilation"] = {
            "status": "ACTIVE" if activation else "STAGED",
            "version": bundle_version,
            "contributing_sources": sorted(incoming_by_source),
            "definition_count": len(combined),
            "cross_source_conflicts": conflicts,
            "manifest": manifest,
            "activation": activation,
        }
        self.store._record("DEF_UPDATE_SUCCESS", bundle_version, f"Combined release accepted {len(combined)} definitions from {len(incoming_by_source)} source(s).")
        return results

    def activate(self, version: str) -> dict[str, Any]:
        with self.update_lock:
            return self._activate(version)

    def _activate(self, version: str) -> dict[str, Any]:
        try:
            definitions = self.store.definitions(version)
        except (BundleError, OSError, ValueError):
            staged = self.store.staged_dir / version
            if staged.is_dir() and not staged.is_symlink():
                self.store.reject_staged(version, "Pre-activation release integrity or signature validation failed.")
            raise
        validation = self.validator.validate(definitions)
        if not validation.accepted:
            self.store.reject_staged(version, "Pre-activation definition validation failed.")
            raise UpdateRejected("staged bundle no longer passes pre-activation validation")
        result = self.store.activate(version, reload_callback=self.reload_callback)
        result["pruned_releases"] = self.store.prune_releases(self.policy.retained_release_count)
        state = self._state()
        state.update({"last_successful_update": utc_now().isoformat(), "validation_state": ValidationState.VALID.value, "rollback_active": False})
        self._save_state(state)
        return result

    def rollback(self) -> dict[str, Any]:
        with self.update_lock:
            result = self.store.rollback(reload_callback=self.reload_callback)
            state = self._state()
            state.update({"rollback_active": True, "last_successful_update": utc_now().isoformat()})
            self._save_state(state)
            return result

    def import_offline(self, archive: Path, *, activate: bool = False) -> dict[str, Any]:
        with self.update_lock:
            return self._import_offline(archive, activate=activate)

    def _import_offline(self, archive: Path, *, activate: bool = False) -> dict[str, Any]:
        result = self.store.import_bundle(archive)
        definitions = self.store.definitions(str(result["version"]))
        validation = self.validator.validate(definitions)
        if not validation.accepted:
            self.store.reject_staged(str(result["version"]), "Signed offline content failed definition or YARA validation.")
            raise UpdateRejected("signed offline bundle failed definition or YARA validation")
        if activate:
            result["activation"] = self.activate(str(result["version"]))
        return result

    def verify(self, version: str | None = None) -> dict[str, Any]:
        directory = self.store.bundle_path(version) if version else self.store.active_bundle_path()
        if directory is None:
            raise UpdateRejected("no active definition release exists")
        manifest = self.store.verify_bundle(directory)
        definitions = self.store.definitions(str(manifest["bundle_version"]))
        validation = self.validator.validate(definitions)
        database_path = directory / "databases" / "threat_intelligence.sqlite3"
        database = MalwareIntelligenceDatabase(database_path, release_id=str(manifest["bundle_version"]))
        database_status = database.verify()
        desynchronized = self.reload_coordinator.desynchronized_sensors(str(manifest["bundle_version"]))
        return {
            "status": "VALID" if validation.accepted and not desynchronized else "DEGRADED",
            "release_id": manifest["bundle_version"], "manifest": manifest,
            "validation": validation.to_dict(), "database": database_status,
            "sensor_receipts": self.reload_coordinator.receipts().get("receipts", {}),
            "desynchronized_sensors": desynchronized,
        }

    def _active_database(self) -> MalwareIntelligenceDatabase:
        active = self.store.active_bundle_path()
        if active is None:
            raise UpdateRejected("no active malware definition release exists")
        manifest = self.store.verify_bundle(active)
        return MalwareIntelligenceDatabase(active / "databases" / "threat_intelligence.sqlite3", release_id=str(manifest["bundle_version"]))

    def lookup_sha256(self, value: str) -> dict[str, Any]:
        return self._active_database().lookup_sha256(value)

    def lookup_sha1(self, value: str) -> dict[str, Any]:
        return self._active_database().lookup_sha1(value)

    def lookup_md5(self, value: str) -> dict[str, Any]:
        return self._active_database().lookup_md5(value)

    def status(self) -> dict[str, Any]:
        try:
            payload = self._direct_status()
        except PermissionError:
            cached = self._cached_status()
            if cached:
                return {**cached, "status_source": "privileged_sanitized_cache"}
            health = DefinitionHealth(
                "PERMISSION_BLOCKED", DefinitionFreshness.UNKNOWN, None, None, 0, {},
                ValidationState.UNKNOWN,
                message="The definition store is root-restricted and no privileged status snapshot is available yet. Local sensors continue without a verified definition-health result.",
            )
            return {**health.to_dict(), "sources": [], "previous_version": None, "status_source": "permission_fallback"}
        if os.geteuid() == 0:
            self._write_status_cache(payload)
        return {**payload, "status_source": "direct_verified_store"}

    def _direct_status(self) -> dict[str, Any]:
        state = self._state()
        active = self.store.active_bundle_path()
        if active is None:
            updating = any(str(item.get("state", "")) == "UPDATING" for item in self.source_statuses())
            health = DefinitionHealth(
                DefinitionHealthState.UPDATING.value if updating else DefinitionHealthState.NEVER_UPDATED.value,
                DefinitionFreshness.UNKNOWN, None, None, 0, {}, ValidationState.UNKNOWN,
                _time(state.get("last_update_attempt")), _time(state.get("last_successful_update")),
                "No validated definition release is active. Configure an approved source or import a signed offline release; local non-definition sensors continue operating.",
            )
            return {**health.to_dict(), "sources": self.source_statuses(), "previous_version": self.store._pointer(self.store.previous_dir).get("version")}
        desynchronized: list[str] = []
        try:
            manifest = self.store.verify_bundle(active)
            activated = _time(self.store._pointer(self.store.active_dir).get("activated_at"))
            freshness = _freshness(activated or _time(manifest.get("created_at")))
            age = utc_now() - (activated or _time(manifest.get("created_at")) or utc_now())
            if state.get("rollback_active"):
                health_state = DefinitionHealthState.ROLLBACK_ACTIVE.value
            elif age.total_seconds() <= self.policy.warning_stale_seconds:
                health_state = DefinitionHealthState.HEALTHY.value
            elif age.total_seconds() <= self.policy.degraded_stale_seconds:
                health_state = DefinitionHealthState.STALE.value
            else:
                health_state = DefinitionHealthState.DEGRADED.value
            if health_state == DefinitionHealthState.HEALTHY.value:
                message = "Definitions are validated and current."
            elif health_state == DefinitionHealthState.ROLLBACK_ACTIVE.value:
                message = "The previous known-good release is active after rollback. Protection continues while the rejected release remains quarantined for diagnostics."
            else:
                critical = " Critical staleness threshold exceeded." if age.total_seconds() > self.policy.critical_stale_seconds else ""
                message = "Threat intelligence is stale. Local protection remains operational using the last validated definition release." + critical
            desynchronized = self.reload_coordinator.desynchronized_sensors(str(manifest.get("bundle_version")))
            if desynchronized:
                health_state = DefinitionHealthState.DEGRADED.value
                message += f" Sensor release desynchronization detected: {', '.join(desynchronized)}."
            health = DefinitionHealth(
                health_state, freshness, str(manifest.get("bundle_version")), activated,
                int(manifest.get("definition_count", 0)), {
                    **{str(key): int(value) for key, value in manifest.get("counts_by_type", {}).items()},
                    "YARA_RULE": int(manifest.get("yara_rule_count", manifest.get("counts_by_type", {}).get("YARA_RULE", 0))),
                    "SHA256": int(manifest.get("sha256_count", manifest.get("counts_by_type", {}).get("SHA256", 0))),
                    "SHA1": int(manifest.get("sha1_count", manifest.get("counts_by_type", {}).get("SHA1", 0))),
                    "MD5": int(manifest.get("md5_count", manifest.get("counts_by_type", {}).get("MD5", 0))),
                },
                ValidationState.VALID, _time(state.get("last_update_attempt")), _time(state.get("last_successful_update")), message,
            )
        except (BundleError, OSError, ValueError):
            health = DefinitionHealth("FAILED", DefinitionFreshness.UNKNOWN, active.name, None, 0, {}, ValidationState.REJECTED, message="The active definition bundle failed integrity validation. Sensors must not reload it.")
        return {
            **health.to_dict(), "sources": self.source_statuses(),
            "previous_version": self.store._pointer(self.store.previous_dir).get("version"),
            "rollback_available": bool(self.store._pointer(self.store.previous_dir).get("version")),
            "sensor_receipts": self.reload_coordinator.receipts().get("receipts", {}),
            "desynchronized_sensors": desynchronized,
        }

    def _cached_status(self) -> dict[str, Any]:
        path = self.status_cache_path
        try:
            info = path.lstat()
            if path.is_symlink() or not path.is_file() or info.st_size > 2 * 1024 * 1024:
                return {}
            document = json.loads(path.read_text(encoding="utf-8"))
            return document if isinstance(document, dict) and document.get("schema_version") == "1.0" else {}
        except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
            return {}

    def _write_status_cache(self, payload: dict[str, Any]) -> None:
        public_sources: list[dict[str, Any]] = []
        for source in payload.get("sources", []):
            if not isinstance(source, dict):
                continue
            # Provider exceptions may contain authenticated URLs or local paths.
            # The GUI needs operational state, never the privileged error text.
            public_sources.append({
                key: source.get(key)
                for key in (
                    "source_id", "state", "enabled", "last_attempt",
                    "last_success", "version", "definition_count",
                )
            } | {
                **{
                    key: (source.get("policy") or {}).get(key)
                    for key in ("display_name", "trust_level", "required", "minimum_interval_seconds", "update_interval_seconds")
                },
                "health": {
                    key: (source.get("health") or {}).get(key)
                    for key in (
                        "last_http_status", "failure_count", "rules_accepted", "rules_rejected",
                        "indicators_accepted", "indicators_rejected", "average_latency",
                    )
                },
            })
        try:
            from .credentials import automatic_abuse_ch_credential_status

            automatic_credential = automatic_abuse_ch_credential_status().to_dict()
        except Exception:  # noqa: BLE001 - credential health must never block cache publication
            automatic_credential = {
                "provider": "abuse.ch-automatic", "available": False,
                "configured": False, "source": "none",
                "message": "Automatic credential health is unavailable.",
            }
        sanitized = {
            "state": payload.get("state", "UNKNOWN"),
            "freshness": payload.get("freshness", "UNKNOWN"),
            "active_version": payload.get("active_version"),
            "activated_at": payload.get("activated_at"),
            "definition_count": int(payload.get("definition_count", 0)),
            "counts_by_type": payload.get("counts_by_type", {}),
            "validation_state": payload.get("validation_state", "UNKNOWN"),
            "last_update_attempt": payload.get("last_update_attempt"),
            "last_successful_update": payload.get("last_successful_update"),
            "message": payload.get("message", ""),
            "previous_version": payload.get("previous_version"),
            "rollback_available": bool(payload.get("rollback_available")),
            "sensor_receipts": payload.get("sensor_receipts", {}),
            "desynchronized_sensors": payload.get("desynchronized_sensors", []),
            "sources": public_sources,
            "provider_credentials": {"abuse_ch_automatic": automatic_credential},
            "schema_version": "1.0",
            "cached_at": utc_now().isoformat(),
            "status_source": "privileged_verified_store",
        }
        try:
            self.store._atomic_json(self.status_cache_path, sanitized)
            os.chmod(self.status_cache_path, 0o644)
        except OSError:
            # Cache publication must never alter definition activation state.
            return

    def _next_version(self) -> str:
        date = utc_now().strftime("%Y.%m.%d")
        existing = {path.name for root in (self.store.staged_dir, self.store.bundle_dir) if root.is_dir() for path in root.iterdir() if path.is_dir()}
        sequence = 1
        while f"{date}.{sequence}" in existing:
            sequence += 1
        return f"{date}.{sequence}"


def _time(value: Any):
    if not value:
        return None
    try:
        from datetime import datetime, timezone
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _freshness(timestamp) -> DefinitionFreshness:
    if timestamp is None:
        return DefinitionFreshness.UNKNOWN
    age = utc_now() - timestamp
    if age <= timedelta(days=1):
        return DefinitionFreshness.CURRENT
    if age <= timedelta(days=7):
        return DefinitionFreshness.AGING
    if age <= timedelta(days=30):
        return DefinitionFreshness.STALE
    return DefinitionFreshness.VERY_STALE


def default_registry(*, enabled_sources: set[str] | None = None, source_config_path: Path | None = None) -> SourceRegistry:
    explicit_path = source_config_path or os.environ.get("MSAA_DEFINITION_SOURCES_CONFIG", "")
    configured_path = str(explicit_path or (SYSTEM_SOURCE_CONFIG if SYSTEM_SOURCE_CONFIG.is_file() else "")).strip()
    if configured_path:
        return load_source_registry(Path(configured_path).expanduser())
    enabled = set(enabled_sources or ())
    use_public_defaults = enabled_sources is None
    registry = SourceRegistry()
    community_defaults = {"cisa_kev", "yara_forge", "threatfox", "urlhaus", "malwarebazaar"}
    enabled = community_defaults if use_public_defaults else enabled
    registry.register(CISAKEVAdapter(enabled="cisa_kev" in enabled))
    registry.register(SignedBundleAdapter(url=os.environ.get("MSAA_SIGNED_DEFINITION_BUNDLE_URL", "https://updates.invalid/msaa/definitions/latest.bundle"), enabled="msaa_signed_bundle" in enabled))
    registry.register(YaraForgeAdapter("core", url="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip", enabled="yara_forge" in enabled))
    # abuse.ch Community API access is free under provider fair-use terms but
    # requires a free Auth-Key. Enabled adapters report SETUP_REQUIRED_FREE
    # until the key is provisioned. Credentials are loaded from the invoking
    # user's macOS Keychain (or an ephemeral environment override), never from
    # definition releases, diagnostics, or update logs.
    registry.register(ThreatFoxAdapter(url=os.environ.get("MSAA_THREATFOX_EXPORT_URL", "https://threatfox-api.abuse.ch/v2/files/exports/AUTH-KEY-REQUIRED/recent.json"), enabled="threatfox" in enabled))
    registry.register(URLhausAdapter(url=os.environ.get("MSAA_URLHAUS_EXPORT_URL", "https://urlhaus-api.abuse.ch/v2/files/exports/AUTH-KEY-REQUIRED/recent.csv"), enabled="urlhaus" in enabled))
    registry.register(MalwareBazaarAdapter(url=os.environ.get("MSAA_MALWAREBAZAAR_METADATA_URL", "https://mb-api.abuse.ch/api/v1/"), enabled="malwarebazaar" in enabled))
    return registry


def default_manager(
    root: Path = DEFAULT_DEFINITION_ROOT, *, enabled_sources: set[str] | None = None,
    require_signatures: bool | None = None, source_config_path: Path | None = None,
) -> ThreatIntelligenceManager:
    root = Path(root)
    if require_signatures is None:
        require_signatures = os.environ.get("MSAA_REQUIRE_SIGNED_DEFINITIONS", "0") == "1"
    cache = Path("/Library/Application Support/MSAA/run/malware-definitions-status.json") if root == DEFAULT_DEFINITION_ROOT else root / "metadata" / "public-status.json"
    return ThreatIntelligenceManager(
        DefinitionStore(root, require_signatures=require_signatures),
        registry=default_registry(enabled_sources=enabled_sources, source_config_path=source_config_path),
        status_cache_path=cache,
    )


MalwareDefinitionUpdateManager = ThreatIntelligenceManager


__all__ = ["MalwareDefinitionUpdateManager", "ThreatIntelligenceManager", "UpdateRejected", "default_manager", "default_registry"]
