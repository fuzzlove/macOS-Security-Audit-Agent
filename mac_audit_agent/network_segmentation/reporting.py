from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .models import EgressRun


HEADERS=("run_id","provider_id","target_scope","authorization_reference","port","protocol","status","latency_ms","error_code","resolved_addresses","evidence_sha256")


def _rows(run:EgressRun)->list[dict]:
    return [{"run_id":run.run_id,"provider_id":run.provider.provider_id,"target_scope":run.target_scope,"authorization_reference":run.authorization_reference,"port":item.port,"protocol":item.protocol,"status":item.status,"latency_ms":item.latency_ms,"error_code":item.error_code,"resolved_addresses":", ".join(item.resolved_addresses),"evidence_sha256":item.evidence_sha256} for item in run.results]


def export_report(run:EgressRun,path:Path)->Path:
    suffix=path.suffix.lower();path.parent.mkdir(parents=True,exist_ok=True)
    if suffix==".json":path.write_text(json.dumps(run.to_dict(),indent=2,sort_keys=True)+"\n",encoding="utf-8")
    elif suffix==".csv":
        with path.open("w",newline="",encoding="utf-8") as handle:
            writer=csv.DictWriter(handle,fieldnames=HEADERS);writer.writeheader();writer.writerows(_rows(run))
    elif suffix==".txt":
        lines=["MSAA Network Segmentation — Egress Validation",f"Run: {run.run_id}",f"Provider: {run.provider.name} ({run.provider.hostname})",f"Scope: {run.target_scope}",f"Authorization: {run.authorization_reference}",""]+[f"TCP/{row['port']}: {row['status']} latency={row['latency_ms']} error={row['error_code']} evidence={row['evidence_sha256']}" for row in _rows(run)]+["","Limitations:",*[f"- {item}" for item in run.limitations]];path.write_text("\n".join(lines)+"\n",encoding="utf-8")
    elif suffix==".html":
        body="".join("<tr>"+"".join(f"<td>{html.escape(str(row[key]))}</td>" for key in HEADERS)+"</tr>" for row in _rows(run));limits="".join(f"<li>{html.escape(item)}</li>" for item in run.limitations);path.write_text(f"<!doctype html><meta charset='utf-8'><title>MSAA Egress Validation</title><h1>Network Segmentation — Egress Validation</h1><p><b>Run:</b> {html.escape(run.run_id)}<br><b>Provider:</b> {html.escape(run.provider.name)}<br><b>Scope:</b> {html.escape(run.target_scope)}<br><b>Authorization:</b> {html.escape(run.authorization_reference)}</p><table border='1'><thead><tr>{''.join(f'<th>{html.escape(key)}</th>' for key in HEADERS)}</tr></thead><tbody>{body}</tbody></table><h2>Limitations</h2><ul>{limits}</ul>",encoding="utf-8")
    elif suffix==".xlsx":_export_xlsx(run,path)
    elif suffix==".docx":_export_docx(run,path)
    elif suffix==".pdf":_export_pdf(run,path)
    else:raise ValueError("supported report formats: json, csv, txt, html, xlsx, docx, pdf")
    return path


def _export_xlsx(run:EgressRun,path:Path)->None:
    try:from openpyxl import Workbook
    except ImportError as exc:raise RuntimeError("XLSX export requires the MSAA office export dependency: openpyxl") from exc
    book=Workbook();sheet=book.active;sheet.title="Egress Results";sheet.append(list(HEADERS))
    for row in _rows(run):sheet.append([row[key] for key in HEADERS])
    notes=book.create_sheet("Run Evidence");notes.append(["Field","Value"]);notes.append(["Run ID",run.run_id]);notes.append(["Provider",run.provider.name]);notes.append(["Scope",run.target_scope]);notes.append(["Authorization",run.authorization_reference]);[notes.append(["Limitation",item]) for item in run.limitations];book.save(path)


def _export_docx(run:EgressRun,path:Path)->None:
    try:from docx import Document
    except ImportError as exc:raise RuntimeError("DOCX export requires the MSAA office export dependency: python-docx") from exc
    doc=Document();doc.add_heading("MSAA Network Segmentation — Egress Validation",0);doc.add_paragraph(f"Run: {run.run_id}\nProvider: {run.provider.name}\nScope: {run.target_scope}\nAuthorization: {run.authorization_reference}");table=doc.add_table(rows=1,cols=len(HEADERS));table.style="Table Grid"
    for index,key in enumerate(HEADERS):table.rows[0].cells[index].text=key
    for row in _rows(run):
        cells=table.add_row().cells
        for index,key in enumerate(HEADERS):cells[index].text=str(row[key])
    doc.add_heading("Limitations",1);[doc.add_paragraph(item,style="List Bullet") for item in run.limitations];doc.save(path)


def _export_pdf(run:EgressRun,path:Path)->None:
    try:
        from reportlab.lib.pagesizes import landscape,letter
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        _export_basic_pdf(run,path)
        return
    styles=getSampleStyleSheet();story=[Paragraph("MSAA Network Segmentation — Egress Validation",styles["Title"]),Paragraph(f"Run: {html.escape(run.run_id)}<br/>Provider: {html.escape(run.provider.name)}<br/>Scope: {html.escape(run.target_scope)}<br/>Authorization: {html.escape(run.authorization_reference)}",styles["BodyText"]),Spacer(1,12)];data=[list(HEADERS)]+[[str(row[key]) for key in HEADERS] for row in _rows(run)];table=Table(data,repeatRows=1);table.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.5,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),6)]));story.append(table);story.append(Spacer(1,12));story.extend(Paragraph("• "+html.escape(item),styles["BodyText"]) for item in run.limitations);SimpleDocTemplate(str(path),pagesize=landscape(letter)).build(story)


def _export_basic_pdf(run:EgressRun,path:Path)->None:
    """Dependency-free text PDF fallback for minimal MSAA installations."""
    lines=["MSAA Network Segmentation - Egress Validation",f"Run: {run.run_id}",f"Provider: {run.provider.name} ({run.provider.hostname})",f"Scope: {run.target_scope}",f"Authorization: {run.authorization_reference}",""]
    lines.extend(f"TCP/{item.port}  {item.status}  latency={item.latency_ms}  error={item.error_code}  sha256={item.evidence_sha256}" for item in run.results)
    lines.extend(["","Limitations:",*["- "+item for item in run.limitations]])
    wrapped=[]
    for line in lines:
        while len(line)>105:wrapped.append(line[:105]);line=line[105:]
        wrapped.append(line)
    pages=[wrapped[index:index+48] for index in range(0,len(wrapped),48)] or [[]]
    objects=[];font_id=3+len(pages)*2
    page_ids=[]
    for index,page in enumerate(pages):
        page_id=3+index*2;content_id=page_id+1;page_ids.append(page_id)
        escaped=[line.replace("\\","\\\\").replace("(","\\(").replace(")","\\)") for line in page]
        stream="BT /F1 9 Tf 42 570 Td 11 TL "+" ".join(f"({line}) Tj T*" for line in escaped)+" ET"
        objects.append((page_id,f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 792 612] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode()))
        objects.append((content_id,f"<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream".encode()))
    all_objects=[(1,b"<< /Type /Catalog /Pages 2 0 R >>"),(2,f"<< /Type /Pages /Kids [{' '.join(f'{item} 0 R' for item in page_ids)}] /Count {len(page_ids)} >>".encode()),*objects,(font_id,b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")]
    all_objects.sort();payload=bytearray(b"%PDF-1.4\n%MSAA\n");offsets={}
    for object_id,body in all_objects:offsets[object_id]=len(payload);payload.extend(f"{object_id} 0 obj\n".encode()+body+b"\nendobj\n")
    xref=len(payload);maximum=max(offsets);payload.extend(f"xref\n0 {maximum+1}\n0000000000 65535 f \n".encode())
    for object_id in range(1,maximum+1):payload.extend(f"{offsets[object_id]:010d} 00000 n \n".encode())
    payload.extend(f"trailer << /Size {maximum+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode());path.write_bytes(payload)
