from pathlib import Path
import pytest
from mac_audit_agent.network_segmentation.ingress_reporting import export_ingress

@pytest.mark.parametrize("suffix",[".json",".csv",".html",".docx",".xlsx"])
def test_ingress_evidence_exports_supported_formats(tmp_path:Path,suffix:str):
    record={"profile_id":"safe_tcp_common","authorization_reference":"SOW-1","xml_sha256":"a"*64,"results":[{"target":"10.0.0.1","protocol":"tcp","port":443,"scanner_state":"closed","reason":"reset","segmentation_result":"INFERRED_ALLOWED"}],"limitations":["Destination observer unavailable."]}
    path=export_ingress(record,tmp_path/("report"+suffix))
    if suffix in {".docx", ".xlsx"}:
        import zipfile
        with zipfile.ZipFile(path) as archive: text="".join(archive.read(name).decode("utf-8", "ignore") for name in archive.namelist() if name.endswith(".xml"))
    else:text=path.read_text()
    assert "safe_tcp_common" in text or suffix==".csv"
    assert "INFERRED_ALLOWED" in text
