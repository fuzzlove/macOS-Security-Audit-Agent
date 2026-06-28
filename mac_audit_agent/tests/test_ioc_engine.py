from __future__ import annotations

import inspect
import json
from pathlib import Path

from mac_audit_agent.ioc_engine import OfflineIOCEngine, export_matches_json, parse_ioc_text
import mac_audit_agent.ioc_engine as ioc_engine


SHA256 = "a" * 64


def test_hash_ioc_matches_file_hash() -> None:
    indicators = parse_ioc_text(SHA256)
    report = OfflineIOCEngine().match(
        indicators,
        {
            "file_issues": [
                {
                    "path": "/tmp/tool",
                    "sha256": SHA256,
                    "signed_status": "unsigned",
                }
            ]
        },
    )

    assert report.local_only is True
    assert report.matches
    match = report.matches[0]
    assert match.indicator_type == "sha256"
    assert match.matched_value == SHA256
    assert match.source == "file_inventory"


def test_ip_ioc_matches_network_connection() -> None:
    report = OfflineIOCEngine().match(
        ["198.51.100.25"],
        {
            "ports": {
                "active_connections": [
                    {
                        "process_name": "curl",
                        "pid": 100,
                        "remote_address": "198.51.100.25:443",
                        "local_address": "127.0.0.1:50000",
                    }
                ],
                "listening": [],
                "suspicious_review_needed": [],
                "errors": [],
            }
        },
    )

    assert len(report.matches) == 1
    assert report.matches[0].indicator_type == "ip"
    assert report.matches[0].source == "network_connection"


def test_local_only_guarantee() -> None:
    source = inspect.getsource(ioc_engine)
    forbidden = ["requests.", "urllib.", "socket.", "subprocess.", "http://", "https://"]

    report = OfflineIOCEngine().match(["example.com"], {"reports": [{"summary": "example.com observed locally"}]})

    assert all(item not in source for item in forbidden)
    assert report.local_only is True
    assert report.upload_performed is False
    assert report.blocking_performed is False
    assert "does not upload" in " ".join(report.warnings).lower()
    assert "does not automatically block" in " ".join(report.warnings).lower()


def test_export_matches(tmp_path: Path) -> None:
    report = OfflineIOCEngine().match([SHA256], {"file_issues": [{"path": "/tmp/tool", "sha256": SHA256}]})
    output = export_matches_json(report, tmp_path / "matches.json")
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["match_count"] == 1
    assert payload["local_only"] is True
