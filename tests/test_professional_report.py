from __future__ import annotations

import zipfile

from mac_audit_agent.professional_report import (
    PROFESSIONAL_REPORT_FILTER,
    ReportSection,
    ReportTable,
    selected_report_path,
    write_professional_report,
)


def _document(tmp_path, suffix):
    return write_professional_report(
        tmp_path / f"report{suffix}",
        title="MSAA Test Report",
        sections=(ReportSection("Summary", ("Static professional report.",)),),
        tables=(ReportTable("Findings", ("Finding", "Suggested Fix"), (("XSS", "Encode output"), ("Formula", "=unsafe"))),),
        qualification="Evidence-backed decision support; not a guarantee.",
    )


def test_professional_report_filter_and_suffix_resolution():
    assert {"*.html", "*.docx", "*.xlsx"} <= set(PROFESSIONAL_REPORT_FILTER.replace("(", " ").replace(")", " ").split())
    assert selected_report_path("report", "Word Report (*.docx)").suffix == ".docx"
    assert selected_report_path("report", "Excel Workbook (*.xlsx)").suffix == ".xlsx"
    assert selected_report_path("report.html", "Word Report (*.docx)").suffix == ".html"


def test_dependency_free_html_docx_and_xlsx_are_valid_static_packages(tmp_path):
    html_path = _document(tmp_path, ".html")
    assert "Suggested Fix" in html_path.read_text(encoding="utf-8")

    docx_path = _document(tmp_path, ".docx")
    with zipfile.ZipFile(docx_path) as archive:
        names = set(archive.namelist())
        assert {"[Content_Types].xml", "word/document.xml", "word/styles.xml"} <= names
        document = archive.read("word/document.xml").decode()
        assert "Suggested Fix" in document and "Encode output" in document
        assert "vbaProject" not in " ".join(names)

    xlsx_path = _document(tmp_path, ".xlsx")
    with zipfile.ZipFile(xlsx_path) as archive:
        names = set(archive.namelist())
        assert {"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet2.xml"} <= names
        worksheet = archive.read("xl/worksheets/sheet2.xml").decode()
        assert "Suggested Fix" in worksheet and "&#x27;=unsafe" in worksheet
        assert "<f>" not in worksheet and "vbaProject" not in " ".join(names)
