from mac_audit_agent.runtime.support_matrix import RuntimeTier, classify_runtime


def test_supported_matrix():
    legacy = classify_runtime((3, 9))
    assert legacy.tier is RuntimeTier.DOCTOR
    assert legacy.doctor_allowed and not legacy.headless_allowed and not legacy.gui_allowed
    for minor in range(10, 14):
        assert classify_runtime((3, minor)).tier is RuntimeTier.FULL
    assert classify_runtime((3, 14)).tier is RuntimeTier.HEADLESS
    assert not classify_runtime((3, 14)).gui_allowed
    assert classify_runtime((3, 15)).tier is RuntimeTier.EXPERIMENTAL
