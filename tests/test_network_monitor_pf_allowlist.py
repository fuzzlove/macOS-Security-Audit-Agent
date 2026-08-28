import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.firewall.ip_anchor import parse_ip_list, render_ip_anchor
from mac_audit_agent.ui.network_monitor_page import NetworkMonitorPage


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_network_monitor_exposes_pf_allowlist_action(monkeypatch) -> None:
    _app()
    monkeypatch.setattr("mac_audit_agent.ui.network_monitor_page.QTimer.singleShot", lambda *_args: None)
    page = NetworkMonitorPage()
    calls = []
    monkeypatch.setattr(page, "_apply_selected_pf_policy", lambda *, action: calls.append(action))
    page.allow_button.click()
    assert calls == ["pass"]
    assert "PF Allowlist" in page.allow_button.text()
    assert "security exception" in page.allow_button.toolTip()


def test_allowlist_uses_bounded_pf_pass_quick_rule() -> None:
    imported = parse_ip_list("203.0.113.10\n2001:db8::10\n")
    rendered = render_ip_anchor("network-monitor-allow-test", imported, action="pass", direction="out", log=True)
    assert "pass out log quick inet to" in rendered
    assert "pass out log quick inet6 to" in rendered
    assert "203.0.113.10/32" in rendered
    assert "2001:db8::10/128" in rendered
