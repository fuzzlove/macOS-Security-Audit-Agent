from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .models import AnalysisRun, Candidate

SCHEMA_VERSION = 3


class AntiTyposquattingStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        # executescript is transaction-aware in SQLite, and every migration is
        # additive so an interrupted upgrade can be safely restarted.
        self.connection.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS anti_typosquatting_schema(version INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS protected_assets(
          id INTEGER PRIMARY KEY, asset_type TEXT NOT NULL, ecosystem TEXT NOT NULL DEFAULT '',
          canonical_name TEXT NOT NULL, normalized_name TEXT NOT NULL, display_name TEXT NOT NULL,
          owner_label TEXT NOT NULL DEFAULT '', business_criticality INTEGER NOT NULL DEFAULT 50,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(asset_type, ecosystem, normalized_name));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_runs(
          id TEXT PRIMARY KEY, protected_asset_id INTEGER, configuration_json TEXT NOT NULL,
          application_version TEXT NOT NULL, rule_set_version TEXT NOT NULL, unicode_version TEXT NOT NULL,
          cldr_version TEXT NOT NULL, confusables_data_version TEXT NOT NULL, started_at TEXT NOT NULL,
          completed_at TEXT NOT NULL, online_lookup_used INTEGER NOT NULL DEFAULT 0,
          result_count INTEGER NOT NULL, status TEXT NOT NULL, FOREIGN KEY(protected_asset_id) REFERENCES protected_assets(id));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_candidates(
          id TEXT PRIMARY KEY, run_id TEXT NOT NULL, display_name TEXT NOT NULL, normalized_name TEXT NOT NULL,
          ascii_name TEXT NOT NULL, categories_json TEXT NOT NULL, reasons_json TEXT NOT NULL,
          locale_profiles_json TEXT NOT NULL, scoring_json TEXT NOT NULL, lookup_status TEXT NOT NULL,
          lookup_evidence_json TEXT NOT NULL, recommendation TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(run_id) REFERENCES anti_typosquatting_runs(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS anti_typosquatting_watchlist(
          id INTEGER PRIMARY KEY, protected_asset_id INTEGER, candidate_name TEXT NOT NULL,
          normalized_name TEXT NOT NULL, ownership_state TEXT NOT NULL DEFAULT 'unverified', notes TEXT NOT NULL DEFAULT '',
          last_checked_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          UNIQUE(protected_asset_id, normalized_name), FOREIGN KEY(protected_asset_id) REFERENCES protected_assets(id));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_lookup_cache(
          provider TEXT NOT NULL, lookup_key TEXT NOT NULL, response_state TEXT NOT NULL,
          sanitized_response_json TEXT NOT NULL, fetched_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          PRIMARY KEY(provider, lookup_key));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_discovered_assets(
          id INTEGER PRIMARY KEY, registry_identity TEXT NOT NULL, ecosystem TEXT NOT NULL, provider TEXT NOT NULL,
          sanitized_metadata_json TEXT NOT NULL, metadata_checksum TEXT NOT NULL, first_observed TEXT NOT NULL,
          last_observed TEXT NOT NULL, UNIQUE(ecosystem,registry_identity));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_local_occurrences(
          id INTEGER PRIMARY KEY, project_reference TEXT NOT NULL, manifest_path TEXT NOT NULL, dependency_type TEXT NOT NULL,
          declared_identity TEXT NOT NULL, resolved_identity TEXT NOT NULL DEFAULT '', structured_location TEXT NOT NULL,
          production INTEGER NOT NULL, first_observed TEXT NOT NULL, last_observed TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS anti_typosquatting_investigations(
          id TEXT PRIMARY KEY, protected_asset_id INTEGER, discovered_asset_id INTEGER, status TEXT NOT NULL,
          assigned_reviewer TEXT NOT NULL DEFAULT '', machine_assessment_json TEXT NOT NULL DEFAULT '{}',
          human_disposition TEXT NOT NULL DEFAULT '', rationale TEXT NOT NULL DEFAULT '', opened_at TEXT NOT NULL,
          closed_at TEXT, FOREIGN KEY(protected_asset_id) REFERENCES protected_assets(id),
          FOREIGN KEY(discovered_asset_id) REFERENCES anti_typosquatting_discovered_assets(id));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_evidence(
          id INTEGER PRIMARY KEY, investigation_id TEXT NOT NULL, evidence_type TEXT NOT NULL, source TEXT NOT NULL,
          value TEXT NOT NULL, reliability TEXT NOT NULL, checksum TEXT NOT NULL, collected_at TEXT NOT NULL,
          reviewer_notes TEXT NOT NULL DEFAULT '', FOREIGN KEY(investigation_id) REFERENCES anti_typosquatting_investigations(id));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_investigation_audit(
          id INTEGER PRIMARY KEY, investigation_id TEXT NOT NULL, from_status TEXT NOT NULL, to_status TEXT NOT NULL,
          actor TEXT NOT NULL, rationale TEXT NOT NULL, changed_at TEXT NOT NULL,
          FOREIGN KEY(investigation_id) REFERENCES anti_typosquatting_investigations(id));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_product_families(
          id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, organization TEXT NOT NULL DEFAULT '',
          identities_json TEXT NOT NULL DEFAULT '{}', notes TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS anti_typosquatting_provider_cache(
          provider TEXT NOT NULL, lookup_key TEXT NOT NULL, response_state TEXT NOT NULL,
          sanitized_response_json TEXT NOT NULL, fetched_at TEXT NOT NULL, expiration_timestamp TEXT NOT NULL,
          entity_tag TEXT, last_modified TEXT, checksum TEXT NOT NULL DEFAULT '',
          PRIMARY KEY(provider, lookup_key));
        CREATE TABLE IF NOT EXISTS anti_typosquatting_registry_changes(
          id INTEGER PRIMARY KEY, watchlist_id INTEGER NOT NULL, change_type TEXT NOT NULL,
          previous_checksum TEXT NOT NULL DEFAULT '', current_checksum TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}',
          FOREIGN KEY(watchlist_id) REFERENCES anti_typosquatting_watchlist(id));
        COMMIT;
        """)
        self._ensure_columns("protected_assets", {
            "identifier_components_json": "TEXT NOT NULL DEFAULT '{}'",
            "product_family": "TEXT NOT NULL DEFAULT ''",
            "expected_namespace": "TEXT NOT NULL DEFAULT ''",
            "expected_repository": "TEXT NOT NULL DEFAULT ''",
            "visibility": "TEXT NOT NULL DEFAULT 'public'",
            "lifecycle_state": "TEXT NOT NULL DEFAULT 'production'",
        })
        self._ensure_columns("anti_typosquatting_watchlist", {
            "ecosystem": "TEXT NOT NULL DEFAULT ''",
            "monitoring_configuration_json": "TEXT NOT NULL DEFAULT '{}'",
            "last_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "next_eligible_check": "TEXT",
            "enabled": "INTEGER NOT NULL DEFAULT 1",
        })
        row = self.connection.execute("SELECT version FROM anti_typosquatting_schema LIMIT 1").fetchone()
        if row is None:
            self.connection.execute("INSERT INTO anti_typosquatting_schema(version) VALUES (?)", (SCHEMA_VERSION,))
        elif int(row[0]) in {1, 2}:
            self.connection.execute("UPDATE anti_typosquatting_schema SET version=?", (SCHEMA_VERSION,))
        elif int(row[0]) != SCHEMA_VERSION:
            raise RuntimeError("Unsupported Anti-Typosquatting database schema version.")
        self.connection.commit()

    def _ensure_columns(self, table: str, columns: dict) -> None:
        existing = {row[1] for row in self.connection.execute("PRAGMA table_info(%s)" % table)}
        with self.connection:
            for name, declaration in columns.items():
                if name not in existing:
                    self.connection.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, declaration))

    def save_run(self, run: AnalysisRun, app_version: str) -> None:
        asset = run.asset
        normalized = asset.canonical_name.lower()
        with self.connection:
            self.connection.execute("INSERT OR IGNORE INTO protected_assets(asset_type,ecosystem,canonical_name,normalized_name,display_name,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (asset.asset_type.value, asset.ecosystem.value if asset.ecosystem else "", asset.canonical_name, normalized, asset.canonical_name, run.generated_at, run.generated_at))
            asset_id = self.connection.execute("SELECT id FROM protected_assets WHERE asset_type=? AND ecosystem=? AND normalized_name=?", (asset.asset_type.value, asset.ecosystem.value if asset.ecosystem else "", normalized)).fetchone()[0]
            self.connection.execute("INSERT OR IGNORE INTO anti_typosquatting_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (run.run_id, asset_id, json.dumps(run.configuration.__dict__, sort_keys=True), app_version, run.data_versions["rule_set"], run.data_versions["unicode"], run.data_versions["cldr"], run.data_versions["confusables"], run.generated_at, run.generated_at, int(not run.configuration.offline_only), len(run.candidates), "completed"))
            for candidate in run.candidates:
                scoring = {"human": candidate.human_typo.total, "impersonation": candidate.impersonation.total, "closeness": candidate.name_closeness.total, "attacker_use_assumption": candidate.attacker_use_assumption.total, "risk_band": candidate.risk_band, "defensive": candidate.defensive_registration.total, "investigation": candidate.investigation.total}
                self.connection.execute("INSERT OR IGNORE INTO anti_typosquatting_candidates VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (candidate.candidate_id, run.run_id, candidate.display_name, candidate.normalized_name, candidate.ascii_name, json.dumps(candidate.categories), json.dumps([r.__dict__ for r in candidate.reasons], sort_keys=True), json.dumps(candidate.locale_profiles), json.dumps(scoring, sort_keys=True), candidate.lookup_status, json.dumps(candidate.lookup_evidence, sort_keys=True), candidate.recommended_action, run.generated_at))

    def add_watchlist(self, run: AnalysisRun, candidates: Iterable[Candidate]) -> int:
        normalized = run.asset.canonical_name.lower()
        asset_id = self.connection.execute("SELECT id FROM protected_assets WHERE asset_type=? AND ecosystem=? AND normalized_name=?", (run.asset.asset_type.value, run.asset.ecosystem.value if run.asset.ecosystem else "", normalized)).fetchone()
        if not asset_id:
            raise ValueError("Save the analysis before adding watchlist entries.")
        count = 0
        with self.connection:
            for candidate in candidates:
                cursor = self.connection.execute("INSERT OR IGNORE INTO anti_typosquatting_watchlist(protected_asset_id,candidate_name,normalized_name,created_at,updated_at) VALUES(?,?,?,?,?)", (asset_id[0], candidate.display_name, candidate.normalized_name, run.generated_at, run.generated_at))
                count += cursor.rowcount
        return count
