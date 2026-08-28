from mac_audit_agent.runtime.support_matrix import classify_runtime


def test_python314_is_headless_safe():
    support = classify_runtime((3, 14))
    assert support.headless_allowed and support.doctor_allowed
    assert not support.gui_allowed
