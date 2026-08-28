from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .models import CredentialFinding, CredentialScanReport


class CredentialStoreError(RuntimeError):
    pass


class LocalCredentialVault:
    """Encrypt stored passwords with a private, scanner-specific local key.

    The key and database are mode 0600. FileVault remains the recommended
    device-at-rest control; this layer prevents accidental plaintext database
    disclosure but is not a substitute for an enterprise secrets manager.
    """

    def __init__(self, key_path: Path) -> None:
        self.key_path = Path(key_path)

    def _key(self) -> bytes:
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.key_path.exists():
            if self.key_path.is_symlink() or not self.key_path.is_file() or self.key_path.stat().st_mode & 0o077:
                raise CredentialStoreError("Credential vault key must be a private regular file (mode 0600).")
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, key + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return key

    def encrypt(self, value: str) -> str:
        return Fernet(self._key()).encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            return Fernet(self._key()).decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise CredentialStoreError("Stored credential could not be decrypted; preserve the database and vault key for investigation.") from exc


class DefaultCredentialRepository:
    def __init__(self, database_path: Path, *, vault: LocalCredentialVault | None = None) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.vault = vault or LocalCredentialVault(self.database_path.with_suffix(".vault.key"))
        self.connection = sqlite3.connect(str(self.database_path))
        self.connection.row_factory = sqlite3.Row
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS default_credential_scans (
              scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
              authorization_reference TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL,
              nmap_version TEXT NOT NULL, target_count INTEGER NOT NULL, finding_count INTEGER NOT NULL,
              errors_json TEXT NOT NULL, payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS default_credential_findings (
              finding_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, detected_at TEXT NOT NULL,
              target_url TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, scheme TEXT NOT NULL,
              product TEXT NOT NULL, category TEXT NOT NULL, path TEXT NOT NULL, cpe TEXT NOT NULL,
              username TEXT NOT NULL, password_ciphertext TEXT NOT NULL, severity TEXT NOT NULL,
              confidence TEXT NOT NULL, status TEXT NOT NULL, source TEXT NOT NULL,
              recommendation TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES default_credential_scans(scan_id)
            );
            CREATE INDEX IF NOT EXISTS idx_default_credential_scan ON default_credential_findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_default_credential_status ON default_credential_findings(status, severity);
            """
        )
        self.connection.commit()

    def save(self, report: CredentialScanReport) -> None:
        safe_payload = report.to_dict(reveal_passwords=False)
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO default_credential_scans VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    report.scan_id, report.started_at, report.completed_at,
                    report.authorization_reference, report.fingerprint_sha256,
                    report.nmap_version, len(report.target_results), len(report.findings),
                    json.dumps(list(report.errors), sort_keys=True),
                    json.dumps(safe_payload, sort_keys=True),
                ),
            )
            for finding in report.findings:
                self.connection.execute(
                    "INSERT OR REPLACE INTO default_credential_findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        finding.finding_id, finding.scan_id, finding.detected_at,
                        finding.target_url, finding.host, finding.port, finding.scheme,
                        finding.product, finding.category, finding.path, finding.cpe,
                        finding.username, self.vault.encrypt(finding.password), finding.severity,
                        finding.confidence, finding.status, finding.source, finding.recommendation,
                    ),
                )

    def findings(self, *, status: str = "") -> list[CredentialFinding]:
        sql = "SELECT * FROM default_credential_findings"
        parameters: tuple[str, ...] = ()
        if status:
            sql += " WHERE status=?"
            parameters = (status,)
        sql += " ORDER BY detected_at DESC, target_url, product"
        output: list[CredentialFinding] = []
        for row in self.connection.execute(sql, parameters):
            output.append(CredentialFinding(
                row["finding_id"], row["scan_id"], row["detected_at"], row["target_url"],
                row["host"], int(row["port"]), row["scheme"], row["product"], row["category"],
                row["path"], row["cpe"], row["username"], self.vault.decrypt(row["password_ciphertext"]),
                row["severity"], row["confidence"], row["status"], row["source"], row["recommendation"],
            ))
        return output

    def set_status(self, finding_id: str, status: str) -> None:
        if status not in {"open", "remediated", "accepted_exception", "false_positive"}:
            raise ValueError("Unsupported finding disposition.")
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE default_credential_findings SET status=? WHERE finding_id=?", (status, finding_id),
            )
        if cursor.rowcount != 1:
            raise KeyError("Default credential finding was not found.")

    def close(self) -> None:
        self.connection.close()


__all__ = ["CredentialStoreError", "DefaultCredentialRepository", "LocalCredentialVault"]
