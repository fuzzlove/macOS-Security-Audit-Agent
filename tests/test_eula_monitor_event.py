import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog

from mac_audit_agent import app
from mac_audit_agent.mission_governance import EULAAcceptanceStore
from mac_audit_agent.ui.eula_acceptance import EULA_VERSION, require_current_eula_acceptance


class _Database:
    def __init__(self): self.events=[]
    def record_monitor_event(self,event,dedupe_window_seconds=300): self.events.append((event,dedupe_window_seconds));return True


class _Window:
    def __init__(self): self.db=_Database()


def test_each_launch_acceptance_is_recorded_as_monitor_event(monkeypatch):
    monkeypatch.setattr(app,"local_user_reference",lambda:"local-user-pseudonym")
    window=_Window();app._record_eula_monitor_event(window)
    assert len(window.db.events)==1
    event,dedupe=window.db.events[0]
    assert event.event_type=="governance_eula_accepted"
    assert event.source=="mission_governance"
    assert event.notification_decision=="governance_log_only"
    assert "local-user-pseudonym" in event.metadata_json
    assert "password" not in event.metadata_json.lower()
    assert dedupe==0


def test_eula_is_required_and_recorded_on_every_launch(tmp_path,monkeypatch):
    application=QApplication.instance() or QApplication([])
    def accept(dialog): dialog.confirm.setChecked(True);return QDialog.Accepted
    monkeypatch.setattr("mac_audit_agent.ui.eula_acceptance.EULAAcceptanceDialog.exec",accept)
    database=tmp_path/"governance.sqlite3"
    assert require_current_eula_acceptance(database=database,user_reference="pseudonym")
    assert require_current_eula_acceptance(database=database,user_reference="pseudonym")
    history=EULAAcceptanceStore(database).acceptance_history("pseudonym")
    assert len(history)==2 and all(item["eula_version"]==EULA_VERSION for item in history)
    application.processEvents()
