from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_audit_agent.code_review.analyzer import CodeReviewAnalyzer
from mac_audit_agent.code_review.reporting import export_html, export_json, export_professional
from mac_audit_agent.code_review.severity import severity_for_score
from mac_audit_agent.code_review.vulnerability_db import load_knowledge, validate_cve
from mac_audit_agent.code_review.language_rules import supported_language_names


def _scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return CodeReviewAnalyzer().scan_project(tmp_path)


def test_command_injection_has_cwe_cvss_explanation_and_remediation(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "import subprocess\n"
        "def run(value):\n"
        "    return subprocess.run('tool ' + value, shell=True)\n",
    )
    finding = next(item for item in report.findings if item.cwe == "CWE-78")

    assert finding.severity == "critical"
    assert finding.cvss_score == 9.8
    assert finding.cvss_vector.startswith("CVSS:3.1/")
    assert finding.analyst_explanation
    assert finding.detection_reason
    assert finding.impact["integrity"]
    assert finding.remediation["immediate"]
    assert finding.cve is None
    assert all(reference["url"].startswith("https://") for reference in finding.references)


def test_sql_injection_and_hardcoded_secret_are_separate_findings(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "api_secret = 'production-secret-value'\n"
        "def lookup(cursor, name):\n"
        "    return cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
    )

    assert {item.cwe for item in report.findings} >= {"CWE-89", "CWE-798"}
    assert all(item.analyst_explanation for item in report.findings if item.severity in {"high", "critical"})


def test_crypto_tls_and_deserialization_detection(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "import hashlib, pickle, requests\n"
        "digest = hashlib.md5(b'data').hexdigest()\n"
        "obj = pickle.loads(payload)\n"
        "response = requests.get(url, verify=False)\n",
    )
    assert {item.cwe for item in report.findings} >= {"CWE-327", "CWE-502", "CWE-295"}


def test_unpinned_dependency_is_review_signal_not_fake_cve(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2.0\nflask==3.1.0\n", encoding="utf-8")
    report = CodeReviewAnalyzer().scan_project(tmp_path)
    finding = next(item for item in report.findings if item.cwe == "CWE-1395")

    assert finding.severity == "medium"
    assert finding.cve is None
    assert "not a claim" in finding.detection_reason


def test_offline_database_integrity_and_identifier_validation() -> None:
    knowledge = load_knowledge()

    assert "CWE-78" in knowledge.cwes
    assert knowledge.integrity
    assert validate_cve("CVE-2025-12345") == "CVE-2025-12345"
    with pytest.raises(ValueError):
        validate_cve("CVE-FAKE-1")


def test_cvss_severity_boundaries() -> None:
    assert severity_for_score(0.1) == "low"
    assert severity_for_score(4.0) == "medium"
    assert severity_for_score(7.0) == "high"
    assert severity_for_score(9.0) == "critical"


def test_professional_json_and_html_reports(tmp_path: Path) -> None:
    report = _scan(tmp_path, "password = 'real-looking-secret'\n")
    json_path = export_json(report, tmp_path / "report.json")
    html_path = export_html(report, tmp_path / "report.html")
    docx_path = export_professional(report, tmp_path / "report.docx")
    xlsx_path = export_professional(report, tmp_path / "report.xlsx")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["findings"][0]["remediation"]
    assert payload["findings"][0]["references"]
    rendered = html_path.read_text(encoding="utf-8")
    assert "Why this matters" in rendered
    assert "Official references" in rendered
    assert docx_path.is_file() and xlsx_path.is_file()


@pytest.mark.parametrize(
    ("filename", "source", "expected_cwe", "language"),
    [
        ("Runner.swift", 'let command = "tool " + userInput\nsystem(command)\n', "CWE-78", "Swift"),
        ("server.go", 'db.Query("SELECT * FROM users WHERE id=" + input)\n', "CWE-89", "Go"),
        ("native.c", 'void copy(char *dst, char *src) { strcpy(dst, src); }\n', "CWE-120", "C"),
        ("client.ts", 'const password = "production-secret";\nel.innerHTML = request.body\n', "CWE-798", "TypeScript"),
        ("transport.rs", 'let config = TlsConfig { InsecureSkipVerify: true };\n', "CWE-295", "Rust"),
    ],
)
def test_multi_language_security_review(
    tmp_path: Path, filename: str, source: str, expected_cwe: str, language: str
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")
    report = CodeReviewAnalyzer().scan_project(tmp_path)
    finding = next(item for item in report.findings if item.cwe == expected_cwe)
    assert finding.language == language
    assert finding.cve is None
    assert finding.analyst_explanation


def test_report_declares_supported_languages_and_static_analysis_limits(tmp_path: Path) -> None:
    (tmp_path / "clean.swift").write_text("let value = 1\n", encoding="utf-8")
    report = CodeReviewAnalyzer().scan_project(tmp_path)
    text = " ".join(report.limitations)
    assert "Swift" in text and "Objective-C" in text and "Rust" in text
    assert "does not prove" in text


def test_major_macos_development_languages_are_explicitly_supported() -> None:
    supported = set(supported_language_names())
    assert {"Python", "Swift", "Objective-C", "C", "C++", "Rust", "Go", "JavaScript", "TypeScript", "Shell"}.issubset(supported)


def test_repository_scan_excludes_virtualenv_and_bundled_vendor_trees(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    for directory in (".venv.broken", "MacRootKit", "nuclei"):
        path = tmp_path / directory; path.mkdir()
        (path / "unsafe.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
    report = CodeReviewAnalyzer().scan_project(tmp_path)
    assert report.files_reviewed == 1
    assert not report.findings
