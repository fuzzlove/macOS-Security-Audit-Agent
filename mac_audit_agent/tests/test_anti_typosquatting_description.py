from mac_audit_agent.ui.anti_typosquatting_page import ANTI_TYPOSQUATTING_DESCRIPTION
from mac_audit_agent.help.topic_registry import TOPICS


def test_anti_typosquatting_description_covers_roles_supply_chain_fraud_and_sdlc() -> None:
    text = ANTI_TYPOSQUATTING_DESCRIPTION.lower()
    for phrase in ("developers", "administrators", "defenders", "incident responders", "security testers", "software supply chains", "fraud", "sdlc", "ci/cd", "defensive registrations"):
        assert phrase in text
    assert "not proof of malicious intent" in text


def test_anti_typosquatting_help_has_lifecycle_guidance_and_safety_limits() -> None:
    topic = TOPICS["anti_typosquatting"]
    rendered = str(topic).lower()
    for phrase in ("design", "develop", "build", "operate", "respond", "defensive registration"):
        assert phrase in rendered
    assert "not automatically malicious" in rendered
