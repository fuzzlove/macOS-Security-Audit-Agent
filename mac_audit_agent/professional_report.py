"""Dependency-free HTML, Word, and Excel report rendering.

The Office outputs are deliberately static Open XML packages: no macros,
formulas, scripts, external relationships, or embedded executables.
"""

from __future__ import annotations

import html
import os
import re
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


PROFESSIONAL_REPORT_FILTER = "HTML Report (*.html);;Word Report (*.docx);;Excel Workbook (*.xlsx)"
PROFESSIONAL_REPORT_SUFFIXES = {".html", ".docx", ".xlsx"}


@dataclass(frozen=True)
class ReportSection:
    title: str
    paragraphs: tuple[str, ...]


@dataclass(frozen=True)
class ReportTable:
    title: str
    headers: tuple[str, ...]
    rows: tuple[tuple[object, ...], ...]


def selected_report_path(value: str | Path, selected_filter: str = "", *, default_suffix: str = ".html") -> Path:
    path = Path(value)
    if path.suffix.lower() in PROFESSIONAL_REPORT_SUFFIXES:
        return path
    inferred = ".docx" if "Word" in selected_filter else ".xlsx" if "Excel" in selected_filter else default_suffix
    return path.with_suffix(inferred)


def write_professional_report(
    destination: str | Path,
    *,
    title: str,
    sections: Sequence[ReportSection] = (),
    tables: Sequence[ReportTable] = (),
    qualification: str = "",
) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix == ".html":
        _write_html(path, title, sections, tables, qualification)
    elif suffix == ".docx":
        _write_docx(path, title, sections, tables, qualification)
    elif suffix == ".xlsx":
        _write_xlsx(path, title, sections, tables, qualification)
    else:
        raise ValueError("Professional reports support .html, .docx, and .xlsx")
    return path


def structured_payload_report(
    destination: str | Path,
    *,
    title: str,
    payload: dict,
    qualification: str = "",
) -> Path:
    summary_rows: list[tuple[object, ...]] = []
    tables: list[ReportTable] = []
    for key, value in payload.items():
        label = str(key).replace("_", " ").title()
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            headers = tuple(dict.fromkeys(str(field) for item in value for field in item))
            rows = tuple(tuple(_display(item.get(field, "")) for field in headers) for item in value)
            tables.append(ReportTable(label, headers, rows))
        elif isinstance(value, dict):
            for child_key, child_value in value.items():
                summary_rows.append((f"{label}: {str(child_key).replace('_', ' ').title()}", _display(child_value)))
        else:
            summary_rows.append((label, _display(value)))
    if summary_rows:
        tables.insert(0, ReportTable("Report Summary", ("Field", "Value"), tuple(summary_rows)))
    return write_professional_report(destination, title=title, tables=tables, qualification=qualification)


def _display(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_display(child)}" for key, child in value.items())
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_display(item) for item in value)
    return str(value)


def _safe_spreadsheet_text(value: object) -> str:
    text = _display(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def _clean_xml_text(value: object) -> str:
    text = _display(value)
    return "".join(character for character in text if character in "\t\n\r" or ord(character) >= 0x20)


def _xml(value: object) -> str:
    return html.escape(_clean_xml_text(value), quote=True)


def _write_html(path: Path, title: str, sections: Sequence[ReportSection], tables: Sequence[ReportTable], qualification: str) -> None:
    section_markup = "".join(
        f"<section><h2>{html.escape(section.title)}</h2>"
        + "".join(f"<p>{html.escape(paragraph)}</p>" for paragraph in section.paragraphs)
        + "</section>"
        for section in sections
    )
    table_markup = ""
    for table in tables:
        headers = "".join(f"<th>{html.escape(value)}</th>" for value in table.headers)
        rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(_display(value))}</td>" for value in row) + "</tr>"
            for row in table.rows
        ) or f'<tr><td colspan="{max(1, len(table.headers))}">No records.</td></tr>'
        table_markup += f"<section><h2>{html.escape(table.title)}</h2><table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table></section>"
    qualification_markup = f'<p class="qualification">{html.escape(qualification)}</p>' if qualification else ""
    document = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font:14px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:1200px;margin:36px auto;padding:0 22px;color:#172033}"
        "h1{color:#123A63}h2{margin-top:28px;color:#244B70}table{border-collapse:collapse;width:100%;table-layout:auto}"
        "th,td{border:1px solid #CBD5E1;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#EAF1F8}"
        ".qualification{margin-top:28px;padding:12px;background:#F1F5F9;border-left:4px solid #64748B}</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{section_markup}{table_markup}{qualification_markup}</body></html>"
    )
    path.write_text(document, encoding="utf-8")


def _paragraph_xml(text: object, *, style: str = "Normal") -> str:
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr><w:r><w:t xml:space="preserve">{_xml(text)}</w:t></w:r></w:p>'


def _table_xml(table: ReportTable) -> str:
    def row_xml(values: Iterable[object], *, header: bool = False) -> str:
        cells = []
        for value in values:
            bold = "<w:rPr><w:b/></w:rPr>" if header else ""
            cells.append(f'<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr><w:p><w:r>{bold}<w:t xml:space="preserve">{_xml(value)}</w:t></w:r></w:p></w:tc>')
        return "<w:tr>" + "".join(cells) + "</w:tr>"
    rows = row_xml(table.headers, header=True) + "".join(row_xml(row) for row in table.rows)
    if not table.rows:
        rows += row_xml(("No records.",) + tuple("" for _ in table.headers[1:]))
    borders = "".join(f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>' for side in ("top", "left", "bottom", "right", "insideH", "insideV"))
    return f'<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>{borders}</w:tblBorders></w:tblPr>{rows}</w:tbl>'


def _atomic_zip(path: Path, entries: Sequence[tuple[str, str]]) -> None:
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(prefix=path.name + ".", suffix=".tmp", dir=path.parent, delete=False) as handle:
            temporary_name = handle.name
        with zipfile.ZipFile(temporary_name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries:
                archive.writestr(name, content.encode("utf-8"))
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _core_properties(title: str) -> str:
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f'<dc:title>{_xml(title)}</dc:title><dc:creator>macOS Security Audit Agent</dc:creator>'
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{generated}</dcterms:created>'
        '</cp:coreProperties>'
    )


def _write_docx(path: Path, title: str, sections: Sequence[ReportSection], tables: Sequence[ReportTable], qualification: str) -> None:
    body = [_paragraph_xml(title, style="Title")]
    for section in sections:
        body.append(_paragraph_xml(section.title, style="Heading1"))
        body.extend(_paragraph_xml(paragraph) for paragraph in section.paragraphs)
    for table in tables:
        body.append(_paragraph_xml(table.title, style="Heading1"))
        body.append(_table_xml(table))
    if qualification:
        body.extend((_paragraph_xml("Qualification", style="Heading1"), _paragraph_xml(qualification)))
    body.append('<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr>')
    document = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + "".join(body) + "</w:body></w:document>"
    styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:sz w:val="20"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="34"/><w:color w:val="123A63"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="244B70"/></w:rPr></w:style></w:styles>'
    entries = (
        ("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>'),
        ("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>'),
        ("docProps/core.xml", _core_properties(title)),
        ("docProps/app.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>macOS Security Audit Agent</Application><AppVersion>1.0</AppVersion></Properties>'),
        ("word/document.xml", document),
        ("word/styles.xml", styles),
        ("word/_rels/document.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'),
    )
    _atomic_zip(path, entries)


def _worksheet_xml(rows: Sequence[Sequence[object]]) -> str:
    row_markup = []
    for row_number, row in enumerate(rows, start=1):
        cells = []
        for column_number, value in enumerate(row, start=1):
            column = ""
            number = column_number
            while number:
                number, remainder = divmod(number - 1, 26)
                column = chr(65 + remainder) + column
            reference = f"{column}{row_number}"
            style = ' s="1"' if row_number == 1 else ""
            cells.append(f'<c r="{reference}" t="inlineStr"{style}><is><t xml:space="preserve">{_xml(_safe_spreadsheet_text(value))}</t></is></c>')
        row_markup.append(f'<row r="{row_number}">' + "".join(cells) + "</row>")
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>' + "".join(row_markup) + "</sheetData></worksheet>"


def _sheet_name(value: str, used: set[str]) -> str:
    base = re.sub(r"[\\/*?:\[\]]", " ", value).strip()[:31] or "Report"
    candidate = base
    index = 2
    while candidate.lower() in used:
        suffix = f" {index}"
        candidate = base[: 31 - len(suffix)] + suffix
        index += 1
    used.add(candidate.lower())
    return candidate


def _write_xlsx(path: Path, title: str, sections: Sequence[ReportSection], tables: Sequence[ReportTable], qualification: str) -> None:
    overview_rows: list[tuple[object, ...]] = [(title, "")]
    for section in sections:
        overview_rows.append((section.title, ""))
        overview_rows.extend(("", paragraph) for paragraph in section.paragraphs)
    if qualification:
        overview_rows.extend((("Qualification", ""), ("", qualification)))
    used: set[str] = set()
    worksheets: list[tuple[str, Sequence[Sequence[object]]]] = [(_sheet_name("Overview", used), overview_rows)]
    for table in tables:
        worksheets.append((_sheet_name(table.title, used), (table.headers, *table.rows)))
    sheets_xml = "".join(f'<sheet name="{_xml(name)}" sheetId="{index}" r:id="rId{index}"/>' for index, (name, _rows) in enumerate(worksheets, start=1))
    rels_xml = "".join(f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>' for index in range(1, len(worksheets) + 1))
    rels_xml += f'<Relationship Id="rId{len(worksheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    overrides = "".join(f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for index in range(1, len(worksheets) + 1))
    entries: list[tuple[str, str]] = [
        ("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' + overrides + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>'),
        ("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>'),
        ("docProps/core.xml", _core_properties(title)),
        ("docProps/app.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>macOS Security Audit Agent</Application></Properties>'),
        ("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + sheets_xml + "</sheets></workbook>"),
        ("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + rels_xml + "</Relationships>"),
        ("xl/styles.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Aptos"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Aptos"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF244B70"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs></styleSheet>'),
    ]
    entries.extend((f"xl/worksheets/sheet{index}.xml", _worksheet_xml(rows)) for index, (_name, rows) in enumerate(worksheets, start=1))
    _atomic_zip(path, entries)


__all__ = [
    "PROFESSIONAL_REPORT_FILTER", "PROFESSIONAL_REPORT_SUFFIXES", "ReportSection", "ReportTable",
    "selected_report_path", "structured_payload_report", "write_professional_report",
]
