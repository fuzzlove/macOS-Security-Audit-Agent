from __future__ import annotations
import csv,html,json
from pathlib import Path

from mac_audit_agent.professional_report import ReportSection, ReportTable, write_professional_report

def export_ingress(record:dict,path:Path)->Path:
    suffix=path.suffix.lower()
    if suffix==".json":path.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    elif suffix==".csv":
        with path.open("w",newline="",encoding="utf-8") as handle:
            writer=csv.DictWriter(handle,fieldnames=["target","protocol","port","scanner_state","reason","segmentation_result"]);writer.writeheader();writer.writerows(record.get("results",[]))
    elif suffix==".html":
        rows="".join("<tr>"+"".join(f"<td>{html.escape(str(item.get(key,'')))}</td>" for key in ("target","protocol","port","scanner_state","reason","segmentation_result"))+"</tr>" for item in record.get("results",[]))
        limitations="".join(f"<li>{html.escape(str(item))}</li>" for item in record.get("limitations",[]))
        document=f"<!doctype html><html><head><meta charset='utf-8'><title>MSAA Ingress Segmentation Evidence</title></head><body><h1>Ingress Network Segmentation</h1><p>Profile: {html.escape(str(record.get('profile_id','')))}</p><p>Authorization reference: {html.escape(str(record.get('authorization_reference','')))}</p><p>Raw XML SHA-256: {html.escape(str(record.get('xml_sha256','')))}</p><table><thead><tr><th>Target</th><th>Protocol</th><th>Port</th><th>Nmap state</th><th>Reason</th><th>Interpretation</th></tr></thead><tbody>{rows}</tbody></table><h2>Limitations</h2><ul>{limitations}</ul><p>Supporting technical evidence only; this report does not certify compliance.</p></body></html>"
        path.write_text(document,encoding="utf-8")
    elif suffix in {".docx", ".xlsx"}:
        fields=("target","protocol","port","scanner_state","reason","segmentation_result")
        write_professional_report(path,title="MSAA Ingress Network Segmentation Evidence",sections=(ReportSection("Scope",(f"Profile: {record.get('profile_id','')}",f"Authorization reference: {record.get('authorization_reference','')}",f"Raw XML SHA-256: {record.get('xml_sha256','')}")),),tables=(ReportTable("Results",tuple(value.replace("_"," ").title() for value in fields),tuple(tuple(item.get(key,"") for key in fields) for item in record.get("results",[]))),),qualification="Supporting technical evidence only; this report does not certify compliance. " + "; ".join(str(item) for item in record.get("limitations",[])))
    else:raise ValueError("Ingress evidence supports JSON, CSV, HTML, DOCX, or XLSX")
    return path
