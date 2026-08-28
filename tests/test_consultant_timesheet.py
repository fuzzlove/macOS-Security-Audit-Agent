from datetime import datetime, timezone

from mac_audit_agent.consultant_timesheet import ConsultantTimesheetRepository, export_timesheet, range_bounds
from mac_audit_agent.storage import AuditDatabase


def test_clock_notes_stop_and_event_history(tmp_path):
    db=AuditDatabase(tmp_path/"audit.sqlite3"); repo=ConsultantTimesheetRepository(db)
    entry=repo.start("Analyst One","Client Assessment",timestamp="2026-07-20T10:00:00+00:00")
    entry=repo.save_notes(entry.entry_id,work_notes="Reviewed DNS",goals="Validate scope",completed="Exported evidence",struggles="Client response pending",tools_used="Approved ticketing tool",standards_focus="NIST CSF Detect")
    stopped=repo.stop(entry.entry_id,timestamp="2026-07-20T12:30:00+00:00")
    assert stopped.duration_seconds==9000 and repo.active() is None
    assert stopped.tools_used=="Approved ticketing tool"
    event_types=[event.event_type for event in db.recent_background_monitor_events(limit=20)]
    assert {"consultant_timesheet_started","consultant_timesheet_notes_saved","consultant_timesheet_stopped"}.issubset(event_types)
    db.close()


def test_only_one_active_timer_and_required_identity(tmp_path):
    db=AuditDatabase(tmp_path/"audit.sqlite3"); repo=ConsultantTimesheetRepository(db)
    try: repo.start("","engagement")
    except ValueError: pass
    else: raise AssertionError("blank contractor was accepted")
    repo.start("Consultant","Engagement")
    try: repo.start("Other","Other")
    except ValueError: pass
    else: raise AssertionError("second timer was accepted")
    db.close()


def test_text_and_html_exports_and_ranges(tmp_path):
    db=AuditDatabase(tmp_path/"audit.sqlite3"); repo=ConsultantTimesheetRepository(db); entry=repo.start("Consultant","Engagement",timestamp="2026-07-20T10:00:00+00:00"); repo.stop(entry.entry_id,timestamp="2026-07-20T11:00:00+00:00"); entries=repo.list_entries()
    assert export_timesheet(entries,tmp_path/"sheet.txt").is_file(); assert export_timesheet(entries,tmp_path/"sheet.html").is_file(); assert "Total hours: 1.00" in (tmp_path/"sheet.txt").read_text()
    start,end=range_bounds("Weekly",datetime(2026,7,22,tzinfo=timezone.utc)); assert start.startswith("2026-07-20") and end.startswith("2026-07-27"); db.close()
