from mac_audit_agent.ui.critical_results import PinnedCriticalResults, critical_findings


def finding(title: str, severity: str = "critical") -> dict[str, str]:
    return {"title": title, "category": "Fixture", "severity": severity, "evidence": f"evidence:{title}"}


def test_critical_results_ignore_noncritical_findings() -> None:
    assert [item["title"] for item in critical_findings([
        finding("critical"), finding("high", "high"), finding("severe", "severe")
    ])] == ["critical", "severe"]


def test_partial_refresh_cannot_hide_pinned_critical_result() -> None:
    pinned = PinnedCriticalResults()
    pinned.update([finding("must remain")], authoritative=True, scan_id="scan-1")

    current = pinned.update([], authoritative=False)

    assert [item["title"] for item in current] == ["must remain"]
    assert pinned.source_scan_id == "scan-1"


def test_completed_scan_authoritatively_clears_resolved_critical_result() -> None:
    pinned = PinnedCriticalResults()
    pinned.update([finding("resolved later")], authoritative=True, scan_id="scan-1")

    current = pinned.update([finding("ordinary", "low")], authoritative=True, scan_id="scan-2")

    assert current == ()
    assert pinned.source_scan_id == "scan-2"


def test_partial_refresh_merges_new_critical_without_duplicates() -> None:
    pinned = PinnedCriticalResults()
    pinned.update([finding("one")], authoritative=True, scan_id="scan-1")
    pinned.update([finding("one"), finding("two")], authoritative=False)

    assert [item["title"] for item in pinned.current()] == ["one", "two"]
