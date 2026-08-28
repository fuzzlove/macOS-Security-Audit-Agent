from mac_audit_agent.framework_coverage_catalog import framework_coverage_catalog


def test_framework_coverage_catalog_explains_capabilities_evidence_and_boundaries():
    catalog = framework_coverage_catalog()

    assert catalog["summary"]["frameworks_explained"] >= 6
    assert catalog["summary"]["capabilities_explained"] >= 10
    assert {item["status"] for item in catalog["capabilities"]} >= {
        "EVIDENCE-BACKED", "PARTIAL", "EXTERNAL / MANUAL",
    }
    assert all(item["evidence"] and item["limitations"] for item in catalog["capabilities"])
    assert all(item["remaining_responsibility"] for item in catalog["frameworks"])
    assert catalog["summary"]["coverage_sheet_entries"] == catalog["summary"]["capabilities_explained"]
    assert {item["capability"] for item in catalog["coverage_sheet"]} == {
        item["capability"] for item in catalog["capabilities"]
    }
    assert all(item["what_msaa_checks"] and item["recommended_next_step"] for item in catalog["coverage_sheet"])
    assert catalog["coverage_sheet_guide"]["reading_order"]


def test_framework_coverage_does_not_claim_certification_or_full_organization_coverage():
    catalog = framework_coverage_catalog()
    text = str(catalog).lower()

    assert "not certification" in catalog["qualification"].lower()
    assert "remain external" in text
    assert "100% covered" not in text


def test_beginner_coverage_sheet_uses_plain_labels_without_hiding_technical_statuses():
    catalog = framework_coverage_catalog()

    assert set(catalog["coverage_sheet_guide"]["status_labels"]) == {
        "EVIDENCE-BACKED", "PARTIAL", "EXTERNAL / MANUAL",
    }
    assert {item["coverage_label"] for item in catalog["coverage_sheet"]} == {
        "Strong local evidence", "Useful but limited", "Needs external review",
    }
    assert catalog["summary"]["status_counts"]["PARTIAL"] > 0
