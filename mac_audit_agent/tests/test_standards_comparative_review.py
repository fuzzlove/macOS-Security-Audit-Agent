from __future__ import annotations

from pathlib import Path

from mac_audit_agent.frameworks.source_registry import official_framework_sources


def test_comparative_review_documents_exist_and_handle_missing_adjacent_source() -> None:
    review = Path("docs/MACOS_SECURITY_COMPARATIVE_REVIEW.md")
    safety = Path("docs/MACOS_SECURITY_IP_SAFETY_REVIEW.md")
    compare = Path("docs/MSAA_VS_MACOS_SECURITY_COMPARE_CONTRAST.md")
    matrix = Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md")
    plan = Path("docs/MACOS_SECURITY_DERIVED_IMPLEMENTATION_PLAN.md")

    for path in [review, safety, compare, matrix, plan]:
        assert path.exists()

    review_text = review.read_text(encoding="utf-8")
    assert "../macos_security" in review_text
    assert "not found" in review_text.lower()
    assert "No implementation, assets, report templates, UI text, tests, or documentation were copied" in review_text
    assert "current MSAA checkout" in compare.read_text(encoding="utf-8")


def test_ip_safety_review_blocks_copying_and_matrix_has_standards_mappings() -> None:
    safety_text = Path("docs/MACOS_SECURITY_IP_SAFETY_REVIEW.md").read_text(encoding="utf-8")
    matrix_text = Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md").read_text(encoding="utf-8")

    assert "Copied code" in safety_text
    assert "Copied assets" in safety_text
    assert "Direct function, class, or module cloning" in safety_text
    assert "plagiarism_guardrail_notes" in matrix_text
    assert "official_source_ids" in matrix_text
    assert "mapping_confidence" in matrix_text
    assert "accepted_for_implementation" in matrix_text
    assert "NIST" in matrix_text
    assert "CISA" in matrix_text
    assert "CMMC" in matrix_text
    assert "NSA" in matrix_text
    assert "PCI" in matrix_text
    assert "MITRE" in matrix_text


def test_expanded_source_registry_includes_public_standards_families() -> None:
    sources = official_framework_sources()
    frameworks = {source.framework for source in sources}
    assert {"NIST", "CISA", "CMMC", "NSA", "PCI", "DFARS", "MITRE"}.issubset(frameworks)
    assert all(source.source_type for source in sources)
    assert any(source.source_type == "industry_standard" and source.framework == "PCI" for source in sources)
    assert any(source.source_type == "public_reference" and source.framework == "MITRE" for source in sources)


def test_accepted_derived_ideas_have_design_specs_and_mappings() -> None:
    matrix_text = Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md").read_text(encoding="utf-8")
    accepted = []
    for line in matrix_text.splitlines():
        if line.startswith("| SDI-") and "| yes |" in line.lower():
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            accepted.append(cells)
    assert accepted

    for cells in accepted:
        idea_id = cells[0]
        official_source_ids = cells[5]
        mapping_confidence = cells[6]
        guardrails = cells[13]
        assert official_source_ids
        assert mapping_confidence in {"direct", "partial", "supporting_evidence", "manual_review_required", "not_applicable"}
        assert guardrails
        assert list(Path("docs/derived_features").glob(f"{idea_id}_*.md"))
