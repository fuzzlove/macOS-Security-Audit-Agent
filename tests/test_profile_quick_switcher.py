from __future__ import annotations

import os
import subprocess
import sys


def test_profile_quick_switcher_shows_identity_and_actions() -> None:
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["MSAA_ALLOW_EXPERIMENTAL_PY314_GUI"] = "1"
    code = (
        "from PySide6.QtWidgets import QApplication; "
        "from mac_audit_agent.ui.profile_panel import ProfileQuickSwitcher; "
        "from mac_audit_agent.user_profiles import current_profile; "
        "app=QApplication.instance() or QApplication([]); "
        "widget=ProfileQuickSwitcher(); profile=current_profile(); "
        "assert profile.display_name in widget.text(); "
        "assert ('@' + profile.username) in widget.text(); "
        "assert widget.property('utilityPlacement') == 'bottom_left'; "
        "assert not widget.icon().isNull(); "
        "assert 'switch' in widget.toolTip().lower(); widget.close()"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_profile_panel_renders_every_allowed_action_as_its_own_row() -> None:
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["MSAA_ALLOW_EXPERIMENTAL_PY314_GUI"] = "1"
    code = (
        "from PySide6.QtWidgets import QApplication,QLabel; "
        "import mac_audit_agent.ui.profile_panel as panel_module; "
        "from mac_audit_agent.user_profiles import ProfileRole,UserProfile,ROLE_PERMISSIONS; "
        "app=QApplication.instance() or QApplication([]); "
        "profile=UserProfile('admin',501,'Admin','',ProfileRole.ADMINISTRATOR,'test'); "
        "panel_module.current_profile=lambda: profile; "
        "widget=panel_module.ProfileSettingsPanel(); "
        "labels=widget.permissions.findChildren(QLabel); "
        "assert len(labels)==len(ROLE_PERMISSIONS[ProfileRole.ADMINISTRATOR]); "
        "rendered={label.text().lstrip('• ').lower().replace(' ','_') for label in labels}; "
        "assert rendered==set(ROLE_PERMISSIONS[ProfileRole.ADMINISTRATOR]); "
        "assert widget.permissions.sizeHint().height()>labels[0].sizeHint().height(); widget.close()"
    )
    result = subprocess.run([sys.executable,"-c",code],capture_output=True,text=True,env=environment,timeout=30,check=False)
    assert result.returncode == 0, result.stdout + result.stderr
