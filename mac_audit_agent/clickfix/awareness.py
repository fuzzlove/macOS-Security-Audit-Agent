from __future__ import annotations

from dataclasses import dataclass
from html import escape


@dataclass(frozen=True)
class ClickFixPresentation:
    presentation_id: str
    title: str
    technique: str
    scenario: str
    red_flags: tuple[str, ...]
    safe_response: tuple[str, ...]
    takeaway: str

    def render(self, number: int, total: int) -> str:
        return "\n\n".join(
            (
                f"CLICKFIX AWARENESS {number} OF {total}\n{self.title}",
                f"Technique\n{self.technique}",
                f"Benign scenario\n{self.scenario}",
                "Red flags\n• " + "\n• ".join(self.red_flags),
                "Safe response\n• " + "\n• ".join(self.safe_response),
                f"Remember\n{self.takeaway}",
                "EDUCATIONAL SIMULATION — no command, download, clipboard content, or executable action is included.",
            )
        )

    def render_html(self, number: int, total: int) -> str:
        """Render a readable, non-interactive awareness slide."""

        red_flags = "".join(f"<li>{escape(value)}</li>" for value in self.red_flags)
        safe_response = "".join(f"<li>{escape(value)}</li>" for value in self.safe_response)
        return f"""
        <article>
          <p style="color:#64748B; font-size:12px; font-weight:700; letter-spacing:1px;">
            CLICKFIX AWARENESS {number} OF {total}
          </p>
          <h1 style="font-size:24px; margin:4px 0 14px 0;">{escape(self.title)}</h1>
          <h2 style="font-size:15px; margin-bottom:4px;">Technique</h2>
          <p>{escape(self.technique)}</p>
          <h2 style="font-size:15px; margin-bottom:4px;">Scenario</h2>
          <p>{escape(self.scenario)}</p>
          <h2 style="font-size:15px; margin-bottom:4px;">Red flags</h2>
          <ul>{red_flags}</ul>
          <h2 style="font-size:15px; margin-bottom:4px;">Safe response</h2>
          <ul>{safe_response}</ul>
          <div style="margin-top:14px; padding:12px; border:1px solid #64748B;">
            <b>Remember:</b> {escape(self.takeaway)}
          </div>
          <p style="margin-top:14px; color:#64748B; font-size:11px;">
            EDUCATIONAL SIMULATION — no command, download, clipboard content, or executable action is included.
          </p>
        </article>
        """


CLICKFIX_PRESENTATIONS: tuple[ClickFixPresentation, ...] = (
    ClickFixPresentation("fake_captcha", "Fake CAPTCHA Verification", "A page claims human verification requires opening Terminal and pasting instructions.", "A familiar CAPTCHA-style box reports a verification error and presents an urgent manual fix.", ("A CAPTCHA asks you to leave the browser", "Terminal or Run instructions appear", "The page claims pasted text is a verification token"), ("Close the tab", "Do not copy or paste the offered text", "Reopen the service from a trusted bookmark and report the page"), "Real CAPTCHA checks do not require shell commands."),
    ClickFixPresentation("urgent_browser_update", "Urgent Browser Update", "A fake update banner uses urgency and browser branding to prompt manual execution.", "A full-screen notice says the browser is unsafe until an emergency update is installed immediately.", ("Countdown or account-loss pressure", "Update arrives outside the browser's normal updater", "Instructions bypass the App Store or vendor settings"), ("Dismiss the page", "Check updates from the browser's own About or Settings screen", "Verify the vendor domain independently"), "Urgency is not evidence that an update is genuine."),
    ClickFixPresentation("missing_codec", "Missing Codec or Media Fix", "A video or audio lure claims a special repair is needed before content can play.", "A streaming page says a codec failed and offers a manual system repair.", ("Unexpected system-level instructions", "The fix is unrelated to normal media controls", "A download is described as a verification or repair tool"), ("Leave the site", "Use supported media software from a trusted source", "Ask IT before installing codecs or helpers"), "A media error should not require Terminal."),
    ClickFixPresentation("security_check", "Fake Security Check", "A verification page impersonates a security provider and asks the user to remediate the Mac.", "A branded interstitial claims suspicious traffic was detected and manual cleanup is mandatory.", ("A website diagnoses the entire Mac", "The page requests elevated or Terminal actions", "Fear language replaces verifiable evidence"), ("Capture the URL for reporting without interacting further", "Close the page", "Run approved MSAA or organizational checks"), "Web pages cannot be trusted to prescribe privileged remediation."),
    ClickFixPresentation("meeting_access", "Meeting Access Failure", "A fake conferencing error turns time pressure into a copy-and-run request.", "Minutes before a meeting, the join page claims audio access requires a manual compatibility fix.", ("Deadline pressure", "A meeting link asks for system commands", "The organizer identity is not independently verified"), ("Use the official meeting application", "Contact the organizer through a known channel", "Join from a trusted calendar entry"), "A missed meeting is safer than executing untrusted instructions."),
    ClickFixPresentation("document_repair", "Document Repair Prompt", "A document lure claims corruption or encryption can be fixed with a pasted instruction.", "A shared invoice or document says protected content needs a local repair step.", ("Viewing a document requires Terminal", "The sender creates urgency", "The repair step is hidden behind copy buttons"), ("Do not open the repair flow", "Verify the sender", "Use the application's built-in repair or preview features"), "Documents do not need shell access to prove they are safe."),
    ClickFixPresentation("account_recovery", "Account Recovery Impersonation", "A fake recovery workflow asks for local execution to restore access.", "A sign-in page says the account is locked and a device command will restore the session.", ("Recovery moves from the browser to Terminal", "The page requests secrets or recovery codes", "Support contact details differ from the vendor"), ("Navigate to the provider directly", "Use the official recovery page", "Report the impersonation"), "Account recovery should stay within verified provider channels."),
    ClickFixPresentation("it_support", "Fake IT Support", "An attacker impersonates help desk staff and supplies a quick command-based fix.", "An unsolicited message says monitoring found an issue and demands immediate cooperation.", ("Unsolicited support contact", "Remote-control or Terminal instructions", "Requests to weaken security tools"), ("Stop the conversation", "Call the help desk using a known number", "Create a normal support ticket"), "Identity must be verified outside the suspicious conversation."),
    ClickFixPresentation("antivirus_fix", "Fake Antivirus Remediation", "A scare alert claims malware was found and offers a manual cleanup action.", "A pop-up reports multiple infections without showing trustworthy local evidence.", ("Browser pop-up claims device-wide detection", "Payment or execution is demanded", "Closing the alert is discouraged"), ("Close the browser", "Review approved security alerts", "Run an authorized local scan"), "A frightening pop-up is not a trusted malware finding."),
    ClickFixPresentation("vpn_update", "VPN or Remote-Access Update", "A fake access gateway claims a manual update is required to connect.", "A remote-work portal says the VPN certificate expired and offers a fast repair.", ("Certificate repair is delivered by a webpage", "Normal device management is bypassed", "The page requests administrator action"), ("Open the approved VPN client directly", "Check organizational status notices", "Contact IT through a known channel"), "Managed access changes should come through managed channels."),
    ClickFixPresentation("password_manager", "Password Manager Sync Error", "A fake vault warning asks the user to run a local synchronization fix.", "A page says stored passwords may be lost unless the device is repaired now.", ("Loss-of-data pressure", "Vault recovery requires a system command", "The prompt asks for master credentials outside the app"), ("Lock the vault", "Open the official application directly", "Contact vendor support from its verified site"), "Never troubleshoot a password vault from an untrusted page."),
    ClickFixPresentation("developer_dependency", "Developer Dependency Fix", "A repository or forum post disguises execution as a missing dependency solution.", "A build error discussion offers a one-step fix that skips review of the package and publisher.", ("Blind copy-and-paste instructions", "Unknown package or publisher", "The fix disables verification or security controls"), ("Read and understand each proposed change", "Verify package provenance", "Test in an isolated development environment"), "Developer workflows still require source and command review."),
    ClickFixPresentation("issue_comment", "Compromised Issue or Forum Comment", "A trusted-looking community account posts a malicious troubleshooting shortcut.", "A recent comment claims all other solutions are obsolete and only its manual fix works.", ("New or edited account", "Unreviewed one-line fix", "Pressure to ignore maintainer guidance"), ("Check official documentation", "Review account and edit history", "Wait for maintainer confirmation"), "A familiar platform does not make every comment trustworthy."),
    ClickFixPresentation("package_manager", "Fake Package Manager Repair", "A site claims a package manager is broken and must be reinstalled from an unverified source.", "A developer tool page offers a custom bootstrap after reporting a false installation failure.", ("Installer source differs from the official project", "Signature checking is discouraged", "The repair requires broad privileges"), ("Use the package manager's official diagnostics", "Verify checksums and publisher identity", "Ask a maintainer or administrator"), "Bootstrap instructions deserve the same scrutiny as software installers."),
    ClickFixPresentation("gatekeeper", "Fake Gatekeeper Error", "A download page frames macOS protections as a nuisance that must be bypassed.", "An app page says macOS damaged the file and presents a mandatory workaround.", ("Security controls are blamed without evidence", "The publisher cannot be verified", "The workaround removes quarantine or trust checks"), ("Do not bypass Gatekeeper", "Obtain a signed notarized build", "Contact the publisher through a verified channel"), "A legitimate publisher should fix signing—not ask users to disable trust checks."),
    ClickFixPresentation("extension_update", "Browser Extension Update", "A fake extension warning asks for a separate local installer or repair.", "A browser page says an extension expired and must be reactivated outside the extension store.", ("The update leaves the browser store", "Permissions expand unexpectedly", "A local command is presented as activation"), ("Remove or disable the extension", "Review it in the official store", "Check requested permissions"), "Extension updates should not require Terminal."),
    ClickFixPresentation("wallet_recovery", "Wallet or Digital Asset Recovery", "A fake wallet error uses fear of asset loss to drive local execution.", "A support page claims the wallet database needs immediate device repair.", ("Seed phrases or recovery secrets are requested", "The page promises guaranteed recovery", "Local execution is required"), ("Disconnect from the suspicious workflow", "Never disclose recovery phrases", "Use verified wallet support and preserve evidence"), "Possession of a recovery phrase grants control; never share it."),
    ClickFixPresentation("invoice_signature", "Invoice or E-Signature Access", "A business document lure claims signing requires a compatibility command.", "An expected-looking invoice or signature request fails and offers a manual browser repair.", ("Sender domain is subtly different", "Document access requires local execution", "Payment urgency discourages verification"), ("Verify the request by phone or a known channel", "Open the vendor portal directly", "Report suspicious billing changes"), "Business context and urgency can be forged."),
    ClickFixPresentation("ai_plugin", "AI Tool or Plugin Activation", "A fake productivity plugin claims a local helper must be activated manually.", "A site promises enhanced AI features after a quick device configuration step.", ("Unofficial plugin source", "Broad permissions for a simple feature", "Activation requires Terminal or security changes"), ("Use approved extension marketplaces", "Review publisher and permissions", "Ask IT before installing workplace AI tools"), "Popular technology themes are routinely used as lures."),
    ClickFixPresentation("update_chain", "Multi-Stage Urgent Update", "A sequence of verification, download, and repair screens gradually normalizes unsafe actions.", "Each screen appears harmless, but the final step asks the user to execute something locally.", ("Instructions escalate across several pages", "Earlier steps are used to create trust", "The final action differs from the stated task"), ("Stop when the workflow changes context", "Review the full chain, not only the last screen", "Report all related URLs and messages"), "Attack chains often build compliance one small step at a time."),
)


__all__ = ["CLICKFIX_PRESENTATIONS", "ClickFixPresentation"]
