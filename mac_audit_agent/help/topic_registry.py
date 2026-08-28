from __future__ import annotations

from functools import lru_cache

from mac_audit_agent.help.navigation_tree import HELP_CATEGORIES
from mac_audit_agent.help.topic_models import HelpTopic
from mac_audit_agent.help.troubleshooting_guides import TROUBLESHOOTING_GUIDES


def _topic(
    topic_id: str,
    title: str,
    category: str,
    summary: str,
    explanation: str,
    matters: list[str],
    actions: list[str],
    advanced: str,
    related: list[str],
    glossary: list[str],
    troubleshooting: list[str] | None = None,
    safety: list[str] | None = None,
) -> HelpTopic:
    return HelpTopic(
        topic_id=topic_id,
        title=title,
        category=category,
        short_summary=summary,
        user_friendly_explanation=explanation,
        when_this_matters=matters,
        what_you_should_do=actions,
        advanced_details=advanced,
        related_topics=related,
        glossary_terms=glossary,
        troubleshooting_steps=troubleshooting or [],
        safety_notes=safety or [],
    )


TOPICS: dict[str, HelpTopic] = {
    "security_research_device": _topic(
        "security_research_device", "Security Research Device", "Integrity & Trust",
        "A one-task-at-a-time macOS hardening and evidence wizard for authorized security research.",
        "Choose Theft Prevention, Sensitive Security Research, or CISA / DoD Submission Readiness. MSAA runs bounded read-only checks where supported and gives manual validation, impact, remediation, and rollback guidance for every other task. The result is an assessment record—not certification, authorization, or a guarantee against compromise.",
        ["A Mac stores valuable security research or intellectual property.", "An engagement needs documented device-hardening evidence.", "A researcher is preparing an authorized coordinated disclosure or government submission."],
        ["Choose the least profile that matches the authorized work.", "Run Read-Only Checks.", "Complete each manual check and preserve evidence outside sensitive free-form notes.", "Review impact and rollback before applying changes through System Settings or approved MDM.", "Export and have the system owner or authorizing official review unresolved items."],
        "Automatic validation currently covers FileVault, Secure Boot where macOS reports it, SIP, and the application firewall. Other controls remain manual because organizational scope, data classification, identity policy, disclosure channels, and recovery effectiveness cannot be inferred safely. INTERPOL material informs reporting awareness; it is not a macOS hardening baseline and does not authorize access.",
        ["zero_trust_endpoint", "not_signed", "firewall", "dns_assurance", "incident_response"],
        ["evidence snapshot", "integrity", "baseline"],
        safety=["Do not weaken SIP, Secure Boot, or the signed system volume merely to satisfy a research workflow.", "Never store recovery keys, credentials, export-controlled details, classified content, or unpublished vulnerability payloads in wizard evidence.", "Government mappings require current source validation and authorizing-official review."],
    ),
    "consultant_timesheet": _topic("consultant_timesheet","Consultant Timesheet","Reports & Exports","Clock assessment time, keep structured engagement notes, and export professional daily, weekly, or monthly records.","The timesheet records explicit clock-in, clock-out, notes, goals, completed work, struggles, external tools, and standards focus in MSAA's local SQL database. Events show when the user recorded an action; they do not independently prove continuous activity or client acceptance.",["You perform billable consulting or assessment work.","A client needs a readable record of hours and outcomes."],["Enter contractor and engagement names.","Select Start Assessment.","Record notes, goals, completed work, blockers, and other approved tools.","Save during the engagement and select Stop Assessment when finished.","Review the history, choose a period and format, then export."],"Exports support XLSX, DOCX, PDF, TXT, and HTML when their optional dependencies are installed. Standards suggestions are reminders, not compliance conclusions. Clock and note events are written to the normal local event log.",["reports_exports","zero_trust_endpoint"],["evidence snapshot"],safety=["Review and correct entries before billing.","Do not place credentials, classified content, or unnecessary personal information in notes."]),
    "dns_assurance": _topic("dns_assurance","DNS Configuration Assurance","Network Intelligence","Compare observed DNS resolvers with client-approved scope and preserve a reviewable report.","DNS Assurance collects resolver IPs from Network Intelligence, normalizes them, compares them with the client-approved list, and remains Concern until the client validates scope. Provenance-backed threat-intelligence imports can produce a red flag, but never prove compromise by themselves.",["A Zero Trust Approved DNS control needs evidence.","An unfamiliar resolver appears.","A client needs to validate current DNS scope."],["Enter the client-approved resolver IPs.","Collect the current DNS configuration.","Export the report and have the client review it.","Mark Evidence collected only after preservation, then record client validation when received.","For a red flag, notify the client promptly and independently validate the cited intelligence source."],"The intelligence import is bounded local JSON with source name, retrieval time, references, and explicit indicators. MSAA does not bundle or invent an INTERPOL blocklist. Status is not collected, concern, validated, or red flag.",["network_intelligence","network_monitor","zero_trust_endpoint"],["evidence snapshot"],safety=["Do not change DNS solely because an address is unfamiliar.","Threat-intelligence matches require independent confirmation."]),
    "add_remove_programs": _topic("add_remove_programs","Add/Remove Programs","Integrity & Trust","Inventory applications and perform reviewed, reversible removal or eligible system-application containment.","The page previews affected paths, processes, persistence, remnants, dependency uncertainty, and protected-system boundaries before an action.",["Unwanted software needs reviewed removal.","A system-installed application needs containment during an authorized incident."],["Refresh the application inventory.","Select an application and review the preview.","Read every dependency and protected-item warning.","Confirm only an authorized reversible action.","Review the receipt and validate dependent workflows."],"Ordinary user applications move to a dedicated Trash location. Eligible top-level /Applications system software can move to root-controlled quarantine through an approved privileged workflow. SIP, authenticated root, the sealed system volume, and critical components are not bypassed.",["not_signed","integrity_verification"],["integrity"],safety=["Preserve evidence before removal.","Test rollback and dependencies before system containment."]),
    "zero_trust_posture": _topic("zero_trust_posture","Zero Trust Endpoint Posture","Integrity & Trust", "Validate endpoint controls using current automatic evidence and explicit manual review.", "This is the contextual-help route for the Zero Trust page. Automatic results, manual evidence collection, and client approval remain separate states.",["You are assessing endpoint trust."],["Select Verify Device.","Review every Concern and Not validated row.","Use How to Verify for beginner and technical steps.","Export evidence before marking it collected."],"See the full Zero Trust Endpoint Validation documentation and the Zero Trust Endpoint help topic for collector details.",["zero_trust_endpoint","dns_assurance","not_signed"],["evidence snapshot"]),
    "anti_ransomware": _topic("anti_ransomware","Anti-Ransomware","Alerts & Security Events","Understand behavioral ransomware monitoring, sensor installation, health, simulation, and platform limitations.","Anti-Ransomware separates in-memory definition tests, bounded disposable-file validation, System Monitor development observation, entitled Endpoint Security visibility, and active containment readiness.",["Protection is degraded.","The development sensor is not installed.","You need to run a safe validation.","You need to verify which behavioral definitions generate a detection."],["Use Simulation Lab to run one or all 16 in-memory definition scenarios.","Use Run Harmless Detection Test separately for bounded disposable-file and observer validation.","Open Sensor Installation and review the numbered plan.","Install the development observer through the reviewed headless administrator bootstrap.","Reopen MSAA normally and verify the daemon heartbeat and observer state.","Do not describe a simulation pass or development observation as full active protection."],"The 16-scenario suite invokes the checked-in transition, sabotage, burst, behavior, and risk functions without executing the modeled commands or touching files. It does not validate external YARA/hash matches, Endpoint Security delivery, or containment. The development observer is hosted inside the existing System Monitor LaunchDaemon and provides delayed metadata plus optional local YARA observation. Full visibility still requires supported Apple entitlements, signing, installation, privacy approval, and live verification.",["operational_health","incident_response"],["ransomware"],safety=["Never run the Qt GUI as root.","Use the unsigned development bootstrap only on an authorized isolated development Mac.","Never use production files or actual malware as a ransomware test fixture."]),
    "incident_response": _topic("incident_response","Incident Response","Live Response","Preserve evidence, investigate safely, contain with authorization, and verify recovery.","Incident-response views organize evidence and defensive actions without turning an alert into proof or granting authorization.",["A material alert requires investigation.","A controlled containment or recovery workflow is needed."],["Confirm scope and authorization.","Preserve volatile and durable evidence.","Review confidence, sensor health, and alternative explanations.","Use the least disruptive approved containment.","Verify recovery and document the outcome."],"Consequential actions require human approval. Sensor gaps and failed collection remain visible.",["flight_recorder","live_response"],["evidence snapshot"],safety=["Do not destroy evidence or exceed engagement scope."]),
    "zero_trust_endpoint": _topic(
        "zero_trust_endpoint", "Zero Trust Endpoint Posture", "Integrity & Trust",
        "How MSAA automatically checks endpoint controls and records manual evidence collection without confusing collection with proof.",
        "Each control links to its authoritative MSAA evidence view. FileVault, Secure Boot, SIP, and firewall checks use bounded read-only macOS collectors. Software provenance comes from Not Signed. Network scope and connection approval require analyst and client review. Missing telemetry stays unknown, while a concerning observation stays Concern until its underlying evidence is resolved.",
        ["You need a repeatable endpoint assessment.", "An auditor needs to understand how a control was checked.", "Network connections require client scope validation."],
        ["Use Validate Now for the control's registered automatic collector.", "Use How to Verify for exact manual steps and evidence fields.", "Export running-software or network evidence before client review.", "Set Evidence to collected only after preserving the referenced material; this records a timestamped event but does not make the control pass."],
        "FileVault uses fdesetup status; SIP uses csrutil status; Secure Boot uses an allowlisted system_profiler JSON field and remains unknown when unavailable; firewall uses socketfilterfw global state. Not Signed counts unsigned, unknown, ad hoc, invalid, and revoked provenance separately. Network approval is an organizational scope decision and cannot be inferred by MSAA.",
        ["not_signed", "network_monitor", "network_intelligence", "firewall", "reports_exports"],
        ["evidence snapshot", "integrity", "false positive"],
        safety=["An evidence-collected assertion is not independent proof of effectiveness or client approval.", "Do not treat unknown-developer software or an unfamiliar connection as malicious without corroborating evidence."],
    ),
    "help_center": _topic(
        "help_center",
        "MSAA Help Center",
        "Getting Started",
        "A structured guide to MSAA features, terms, troubleshooting, and next steps.",
        "The Help Center is the central knowledge base for MSAA. It groups product guidance by workflow so you can learn what a feature means, why it matters, and what to do next without reading developer notes or raw logs.",
        ["You are new to MSAA.", "You need one place to understand alerts, health, integrity, exposure, reports, and response workflows."],
        ["Start with Getting Started if you are new.", "Use search for specific terms such as integrity, KEV, baseline, or LaunchAgent.", "Open contextual Help from a screen when you need guidance for the thing you are viewing."],
        "Help topics are registered through HelpCenter and topic_registry. UI code should link to topic IDs instead of embedding scattered help text.",
        ["how_msaa_works", "alert_severity", "troubleshooting"],
        ["evidence snapshot", "alert severity levels"],
    ),
    "how_msaa_works": _topic(
        "how_msaa_works",
        "How MSAA Works",
        "Getting Started",
        "Plain-language explanation of scans, monitor events, alerts, findings, reports, and snapshots.",
        "MSAA collects local security information, normalizes it into findings and events, and helps you review risk. Scans show current state. Background monitoring shows change over time. Reports and snapshots preserve or share what was observed.",
        ["You need to know whether a result is a live alert, a scan finding, or preserved evidence.", "You are deciding whether to run a scan, export a report, or collect a snapshot."],
        ["Use scans for current state.", "Use monitor events for ongoing change.", "Use evidence snapshots before repair or cleanup when a finding may matter."],
        "MSAA stores findings, settings, events, and reports locally. Severity scoring and feature-specific models help group evidence without claiming a single signal proves compromise.",
        ["dashboard", "alert_severity", "reports_exports"],
        ["evidence snapshot", "baseline", "false positive"],
    ),
    "dashboard": _topic(
        "dashboard",
        "Dashboard",
        "Getting Started",
        "The dashboard is the starting view for scan state, security score, exposure, health, and integrity signals.",
        "The Dashboard gives a current orientation point. It summarizes important areas so you can decide what to review first.",
        ["You need a quick status check.", "You want to prioritize before opening detailed feature pages."],
        ["Run a safe scan on a new Mac.", "Review HIGH or CRITICAL indicators first.", "Open the feature page behind any card before changing settings."],
        "Dashboard cards combine scan results, health checks, exposure data, severity counts, and integrity status. They are triage summaries, not final determinations.",
        ["how_msaa_works", "alert_severity", "operational_health"],
        ["alert severity levels", "integrity", "evidence snapshot"],
    ),
    "alert_severity": _topic(
        "alert_severity",
        "Alert Severity Guide",
        "Alerts & Security Events",
        "Definitions for INFO, LOW, MEDIUM, HIGH, and CRITICAL alerts and how to respond.",
        "Alert severity tells you how quickly to review an event. INFO is informational, LOW is low-risk context, MEDIUM should be reviewed, HIGH needs prompt review, and CRITICAL needs immediate attention.",
        ["You see an alert and need to decide whether to pause, preserve evidence, or continue normal work.", "You are tuning alert thresholds."],
        ["Treat HIGH and CRITICAL as review prompts, not automatic proof.", "Lower thresholds only if you can tolerate more alerts.", "For unexplained high-risk alerts, preserve evidence before repair."],
        "Canonical severity names are INFO, LOW, MEDIUM, HIGH, and CRITICAL. Events may be logged without visible notification when below threshold, suppressed by policy, grouped, or useful only as evidence.",
        ["operational_health", "troubleshooting", "flight_recorder"],
        ["alert severity levels", "false positive", "evidence snapshot"],
        ["alerts_not_appearing"],
    ),
    "intrusion_detection": _topic(
        "intrusion_detection",
        "Intrusion Detection",
        "Alerts & Security Events",
        "How intrusion signals are grouped into reviewable security events.",
        "Intrusion Detection organizes suspicious local behaviors into findings that can be reviewed with context, confidence, severity, and recommended action.",
        ["You need to understand why a behavior was flagged.", "You are deciding whether to collect evidence or mark activity expected."],
        ["Read the explanation and evidence summary first.", "Check whether the activity matches known software or administration.", "Preserve evidence before changing files or services."],
        "Detection output should summarize evidence rather than dump raw logs. Technical evidence belongs in reports and evidence views with redaction where appropriate.",
        ["alert_severity", "live_response", "reports_exports"],
        ["false positive", "evidence snapshot", "MITRE ATT&CK"],
    ),
    "flight_recorder": _topic(
        "flight_recorder",
        "Flight Recorder",
        "Alerts & Security Events",
        "A timeline view for surrounding activity and correlated patterns.",
        "Flight Recorder helps you understand what happened around an event by showing nearby activity and related signals.",
        ["You need timeline context for an alert.", "You are checking whether several low-level signals form a pattern."],
        ["Review surrounding events before acting.", "Use snapshots or reports for high-risk timelines.", "Avoid assuming correlation means causation without evidence."],
        "Timeline views should present normalized event summaries and linked evidence, not raw debug streams.",
        ["alert_severity", "live_response", "reports_exports"],
        ["evidence snapshot", "false positive"],
    ),
    "operational_health": _topic(
        "operational_health",
        "Operational Health",
        "System Health",
        "How to interpret healthy, degraded, broken, and critical MSAA component states.",
        "Operational Health tells you whether MSAA itself can scan, monitor, alert, store data, keep settings consistent, and export reports.",
        ["A feature appears empty or unreliable.", "Alerts are missing.", "A daemon, notifier, storage, export, or settings check reports trouble."],
        ["Refresh health before an investigation.", "Repair MSAA components before changing unrelated macOS settings.", "If health is critical, fix monitoring or notifier delivery before relying on alert coverage."],
        "Health states are healthy, degraded, broken, and critical. They describe MSAA component reliability, not whether the Mac is compromised.",
        ["settings", "integrity_verification", "troubleshooting"],
        ["daemon", "notifier", "drift", "integrity"],
        ["daemon_not_running", "alerts_not_appearing"],
    ),
    "settings": _topic(
        "settings",
        "Settings",
        "System Health",
        "How licensing, monitor, notifier, event priority, health, and appearance settings affect MSAA.",
        "Settings show signed product-license status and control monitoring, notification thresholds, event priorities, appearance, and selected diagnostic behavior.",
        ["You are importing or activating a signed product license.", "You are changing how much MSAA alerts.", "You are repairing monitor deployment or notification behavior."],
        ["Use only licenses issued by the approved MSAA authority.", "Document threshold changes.", "Keep developer-mode controls disabled during normal use.", "Use Operational Health repair actions when component checks fail."],
        "Without a valid signed license, Demo Preview keeps navigation, help, details, and awareness presentations visible while disabling operational GUI controls. A license can be purchased through configured Stripe Checkout or imported as an offline document. Existing background safety and preserved evidence are not deleted or stopped. Settings can affect visible alerts without deleting stored evidence. Developer synthetic events are for validation and should not be treated as real security findings.",
        ["operational_health", "alert_severity", "troubleshooting"],
        ["product licensing", "activation", "offline license", "Stripe Checkout", "notifier", "daemon", "alert severity levels"],
        ["usb_bluetooth_not_detected", "daemon_not_running"],
    ),
    "integrity_verification": _topic(
        "integrity_verification",
        "Integrity Verification",
        "Integrity & Trust",
        "How trusted manifests and SHA-256 hashes detect modified, stale, unknown, verified, or draft installs.",
        "Integrity Verification compares protected MSAA files with a trusted manifest. It helps detect unexpected application changes while ignoring files expected to change, such as reports, logs, settings, caches, and databases.",
        ["MSAA reports modified, stale, unknown, draft, or verified state.", "You are checking whether the installed app still matches the trusted build."],
        ["Do not overwrite an unexplained mismatch.", "Export the integrity report and create an evidence snapshot.", "After a trusted update, use the matching trusted manifest."],
        "Integrity states are verified, modified, stale, unknown, and draft. SHA-256 hashes are used for file comparison. This check protects MSAA application trust, not every file on macOS.",
        ["operational_health", "live_response", "troubleshooting"],
        ["integrity", "trusted manifest", "evidence snapshot", "baseline"],
        ["integrity_warnings"],
        ["If integrity changed unexpectedly, preserve evidence before repair or reinstall."],
    ),
    "network_intelligence": _topic(
        "network_intelligence",
        "Network Intelligence",
        "Network Intelligence",
        "How MSAA reviews connections, listeners, DNS, gateway, VPN/proxy changes, baseline drift, and visibility mismatch.",
        "Network Intelligence summarizes local network posture. It helps you review listening services, current or recent connections, DNS and gateway settings, VPN or proxy changes, and drift from a known baseline.",
        ["You see unusual listeners or external connections.", "DNS, gateway, VPN, or proxy settings changed.", "Network data looks missing or inconsistent."],
        ["Review listeners and unusual external connections first.", "Check process path, user, signature, and expected business purpose.", "Verify network configuration drift before assuming compromise."],
        "A listener accepts incoming connections. A connection is active or recent communication. Visibility mismatch means collection sources disagree because of permissions, timing, or system limits.",
        ["live_response", "reports_exports", "troubleshooting"],
        ["baseline", "drift", "false positive"],
        ["network_data_missing"],
    ),
    "network_segmentation": _topic(
        "network_segmentation",
        "Network Segmentation",
        "Network Intelligence",
        "How to run scoped ingress and egress segmentation tests and preserve reviewable evidence.",
        "Network Segmentation has separate Egress Tests and Ingress Tests tabs. Egress uses approved public providers. Ingress uses fixed, defensive Nmap profiles within an explicitly entered authorized CIDR. Scanner-only results remain inferred or indeterminate until corroborated by a healthy destination observer.",
        ["You need to validate an approved ingress or egress policy.", "A PCI CDE or government segment requires technical boundary evidence.", "A client requires evidence that unnecessary inbound or outbound paths are restricted."],
        ["Obtain written authorization, rules of engagement, source vantage, exact target, CIDR scope, and change window.", "Choose a fixed profile; never expand scope merely because a tool can scan it.", "Start with Safe TCP Common, then add UDP, DNS path, ICMP/ICMPv6, or extended protocols only when approved.", "Export and hash the result, then corroborate unexpected states with firewall logs and a destination observer.", "Treat closed as reachable, open|filtered or timeout without observer evidence as indeterminate, and IPv4/IPv6 as separate coverage."],
        "A destination-observed packet, TCP RST, or destination ICMP rejection proves the network path was reachable even when a service is closed. Timeouts without a healthy destination observer are indeterminate. Probe enrollment and passive capture are not operational in this build and are never simulated.",
        ["network_intelligence", "network_monitor", "firewall", "reports_exports"],
        ["egress filtering", "ingress testing", "CDE segmentation", "network segmentation", "firewall policy", "Nmap XML", "evidence snapshot"],
        safety=["Test only authorized scope and approved time windows.", "Public egress services receive the source IP and connection metadata.", "Full TCP, UDP, ICMP, ICMPv6, DNS path, and IP-protocol profiles require explicit authorization and operational-impact review.", "MSAA supplies technical evidence and does not certify PCI DSS, NIST, CISA, or DoD compliance.", "Do not use evasion, spoofing, decoys, fragmentation, brute force, exploit scripts, or tunneled exfiltration content."],
    ),
    "persistence_intelligence": _topic(
        "persistence_intelligence",
        "Persistence Intelligence",
        "Persistence Intelligence",
        "How MSAA reviews LaunchAgents, LaunchDaemons, login items, scheduled jobs, browser persistence, and baseline changes.",
        "Persistence Intelligence reviews mechanisms that can restart software after login, reboot, schedule, browser launch, or service reload. Legitimate management tools and unwanted software can both use persistence.",
        ["A new startup item appears.", "A persistence item has unusual owner, path, schedule, signature, or baseline status."],
        ["Review owner, path, signature, schedule, parent app, and purpose.", "Preserve evidence before deleting plists, scripts, or executables.", "Mark expected tools as reviewed instead of treating every new item as malicious."],
        "Persistence terms are standardized around persistence, daemon, LaunchAgent, LaunchDaemon, baseline, and drift. New since baseline means absent from the comparison snapshot.",
        ["integrity_verification", "live_response", "glossary"],
        ["persistence", "LaunchAgent", "LaunchDaemon", "baseline", "daemon"],
    ),
    "keylogger_detection": _topic(
        "keylogger_detection",
        "Keylogger Detection",
        "Keylogger Detection",
        "How MSAA detects keyboard-observation capabilities without collecting what you type.",
        "Keylogger Detection enumerates enabled keyboard event taps and reviews Input Monitoring and Accessibility grants. It correlates scope, process path, signing, and trust evidence. A permission or event tap can be legitimate, so MSAA reports capability and evidence rather than declaring malware from one signal.",
        ["MSAA reports a possible keylogger.", "An unfamiliar application has Input Monitoring or Accessibility access.", "You suspect unauthorized keyboard monitoring."],
        ["Review the process path, publisher, PID, and detection signals.", "Confirm whether the application needs its privacy permission.", "Preserve evidence and correlate persistence and network activity before removing software."],
        "Quartz keyboard event taps can observe key-up or key-down metadata. Global scope, active filtering, unsigned code, and execution from writable locations increase risk. TCC database access may require Full Disk Access; restricted coverage must not be interpreted as clean.",
        ["persistence_intelligence", "alert_severity", "live_response"],
        ["false positive", "persistence", "daemon"],
        safety=["MSAA never records keystrokes or creates an event tap during this scan.", "Do not remove accessibility software solely because it holds an expected permission."],
    ),
    "code_review": _topic(
        "code_review",
        "Code Review",
        "Security Analysis",
        "How to review source-code weakness findings, CVSS severity, CWE classifications, evidence, and remediation guidance.",
        "Code Review performs bounded multi-language static analysis for Python, Swift, Objective-C, C/C++, Rust, Go, Java/Kotlin, JavaScript/TypeScript, shell, Ruby, PHP, Perl, C#, Lua, and SQL. It enriches review candidates with official weakness classifications, modeled severity, attack context, and secure-development guidance. A finding indicates code that requires analyst review; it does not prove that untrusted data reaches the operation or that exploitation succeeded.",
        ["You are reviewing a software project before release.", "A HIGH or CRITICAL code weakness needs technical and business-impact context.", "You need a report for a developer remediation workflow."],
        ["Review the affected line and detection reason.", "Confirm whether attacker-controlled input reaches the flagged operation.", "Apply the immediate mitigation and long-term secure coding recommendation.", "Rescan after the change and preserve the report for review."],
        "MSAA maps findings to MITRE CWE and displays a CVSS v3.1 score and vector. CVE identifiers remain empty unless separately matched to authoritative advisory evidence. Offline reference files are integrity checked before use.",
        ["reports_exports", "alert_severity", "integrity_verification"],
        ["false positive", "evidence snapshot"],
        safety=["Do not treat a static-analysis match as confirmed exploitation without validating data flow and runtime context."],
    ),
    "clickfix_guard": _topic(
        "clickfix_guard", "ClickFix Guard", "Alerts & Security Events",
        "How MSAA reviews suspicious clipboard-to-terminal social-engineering activity.",
        "ClickFix Guard identifies a suspicious interaction sequence without treating clipboard text alone as proof of compromise.",
        ["A ClickFix warning appears."],
        ["Do not paste or run unfamiliar commands.", "Preserve the event and review related process and persistence activity."],
        "Detection confidence increases when launcher activity, clipboard content, and command execution evidence correlate.",
        ["alert_severity", "live_response"], ["false positive", "evidence snapshot"],
    ),
    "clickfix_awareness": _topic(
        "clickfix_awareness", "ClickFix Awareness", "Security Education",
        "How to use MSAA's benign ClickFix presentations and recognize common social-engineering lures.",
        "ClickFix Awareness provides 20 non-executable lessons covering fake CAPTCHAs, urgent updates, support impersonation, document lures, and related techniques. Training completion is recorded separately from security findings.",
        ["You want to recognize ClickFix instructions before they reach Terminal.", "You are conducting user awareness training with safe examples."],
        ["Select a lesson and choose Start Presentation.", "Review the scenario, red flags, and safe response.", "Mark the lesson complete when finished."],
        "Presentation content contains no runnable command, download, clipboard payload, or executable action.",
        ["clickfix_guard", "alert_severity"], ["false positive"],
        safety=["Do not recreate live attacker commands for awareness testing.", "Use the separate ClickFix Guard view for detections and enforcement policy."],
    ),
    "not_signed": _topic(
        "not_signed", "Not Signed", "Integrity & Trust",
        "How to distinguish Apple, App Store, Developer ID, ad hoc, unsigned, invalid, and unknown software trust states.",
        "Not Signed inventories software provenance without equating third-party software with malware.",
        ["An unfamiliar application or process needs publisher review."],
        ["Review its path, signature evidence, publisher, persistence, and activity before removal."],
        "Cryptographic classification and user trust disposition remain separate evidence fields.",
        ["integrity_verification", "live_response"], ["false positive", "integrity"],
    ),
    "firewall": _topic(
        "firewall", "Firewall", "Network Intelligence",
        "How MSAA builds and validates isolated PF anchor policies.",
        "Firewall manages only MSAA-owned PF anchors and previews changes before privileged activation.",
        ["You need to review or block network traffic."],
        ["Validate the policy, review connectivity impact, and keep rollback protection enabled."],
        "MSAA does not replace the complete pf.conf or modify third-party anchors.",
        ["network_intelligence", "live_response"], ["evidence snapshot", "false positive"],
    ),
    "network_monitor": _topic(
        "network_monitor", "Network Monitor", "Network Intelligence",
        "How to review application-owned network connections and submit selected remote addresses to an MSAA PF blocklist.",
        "Network Monitor groups live connections by owning process so administrators can distinguish expected application traffic from endpoints requiring investigation.",
        ["An application connects to an unfamiliar address.", "You need to identify the process behind a connection."],
        ["Review process identity and destination first.", "Preserve evidence before blocking.", "Use the isolated MSAA firewall workflow for reviewed addresses."],
        "Connection snapshots are time-sensitive and incomplete when macOS permissions restrict process ownership visibility.",
        ["network_intelligence", "firewall", "live_response"], ["false positive", "evidence snapshot"],
    ),
    "default_credential_scanner": _topic(
        "default_credential_scanner", "Default Credential Scanner", "Network Intelligence",
        "How to validate documented vendor-default HTTP credentials on an explicit, authorized server list.",
        "The scanner invokes Nmap's http-default-accounts NSE script with validated NNdefaccts fingerprints against only the HTTP(S) targets entered by the operator. It does not discover networks, enumerate adjacent hosts, or brute-force arbitrary passwords.",
        ["A blue team needs to confirm whether an appliance still accepts a vendor-default credential.", "An authorized assessment requires repeatable HTTP management-plane evidence."],
        ["Record the ticket, statement of work, or owner approval.", "List each approved HTTP(S) server explicitly.", "Install Nmap and the validated fingerprint data if readiness is incomplete.", "Run during the approved window and review product lockout policy first.", "Rotate accepted credentials and verify that the old credential is rejected.", "Protect or securely delete plaintext remediation exports."],
        "Fingerprint data is downloaded from Default HTTP Login Hunter / NNdefaccts over verified HTTPS, checked for size and expected structure, and stored privately. Findings are encrypted in the scanner's local database. General findings contain only a redacted credential reference; password reveal and plaintext export require separate confirmation.",
        ["network_monitor", "network_intelligence", "reports_exports"],
        ["default credential", "authorized testing", "Nmap"],
        safety=["Authentication attempts can create logs or lockouts on poorly configured products. Validate the approved window and product behavior first.", "Never scan a server without explicit ownership or written authorization.", "An accepted default credential proves exposure at collection time; it does not prove compromise or prior use."],
    ),
    "apple_exposure": _topic(
        "apple_exposure",
        "Apple Exposure Assessment",
        "Apple Exposure",
        "How MSAA reviews Apple security exposure, data freshness, CVEs, and CISA KEV indicators.",
        "Apple Exposure Assessment helps you decide whether this Mac may need Apple security updates based on local version context, checked-date freshness, CVEs, and KEV indicators.",
        ["You are planning updates.", "A CVE or KEV indicator appears.", "The assessment is stale or missing."],
        ["Refresh before relying on the assessment.", "Use System Settings or managed update tooling to patch.", "Verify the installed version after update and reboot if required."],
        "CVE entries identify disclosed vulnerabilities. KEV means known exploitation is documented in the CISA catalog. Applicability still depends on local product and version context.",
        ["reports_exports", "troubleshooting", "alert_severity"],
        ["CVE", "CISA KEV", "KEV", "false positive"],
        ["apple_exposure_not_updating"],
    ),
    "reports_exports": _topic(
        "reports_exports",
        "Reports and Exports",
        "Reports & Exports",
        "How HTML, JSON, Word, Excel, evidence bundles, and report detail levels should be used.",
        "Reports turn local findings into shareable summaries, analyst detail, or evidence packages. They should explain what was found and what to do without forcing users to read raw logs.",
        ["You need to share results.", "You need a durable record for review, remediation, or case tracking."],
        ["Choose executive reports for leadership and technical reports for analysts.", "Protect exports because they may contain sensitive local context.", "Open the reports folder to confirm where files were saved."],
        "Reports may include structured evidence tables and technical appendices, but Help pages should not render raw JSON, debug output, or system log dumps.",
        ["live_response", "how_msaa_works", "troubleshooting"],
        ["evidence snapshot", "false positive"],
        ["reports_not_generating"],
    ),
    "live_response": _topic(
        "live_response",
        "Live Response Collection",
        "Live Response",
        "How evidence snapshots collect read-only artifacts and export bundles without destructive actions.",
        "Live Response creates read-only snapshots of selected local artifacts so you or an analyst can review what existed at a point in time.",
        ["A high-risk or unexplained finding appears.", "You need before-and-after evidence around remediation."],
        ["Collect a snapshot before repair, reinstall, or cleanup.", "Export bundles only to trusted storage.", "Use snapshots to verify remediation."],
        "Collection can include system state, process and network details, persistence paths, logs, settings, hashes, and report metadata. The collection flow does not delete, quarantine, block, or wipe artifacts.",
        ["integrity_verification", "reports_exports", "network_intelligence"],
        ["evidence snapshot", "baseline", "integrity"],
        [],
        ["Evidence bundles may contain sensitive local paths and case context."],
    ),
    "family_safety": _topic(
        "family_safety",
        "Family & Safety Center",
        "Family & Safety Center",
        "How family, caregiver, school, research, government, clinical, health, and legal use contexts can receive scoped safety guidance.",
        "Family & Safety Center organizes local guidance into practical categories without hiding that restrictions can affect accessibility, education, remote support, clinical availability, legal confidentiality, or authorized research. A selected use-context label is self-declared and does not prove professional identity, government ownership, regulated scope, authorization, or compliance.",
        ["You are reviewing a shared, family, school, research, public-sector, clinical, health, or legal Mac.", "You need practical guidance without advanced security jargon."],
        ["Choose the closest use context under Who uses this Mac.", "Run the audit and review its role-specific recommendations.", "Use the detailed wizard when you need a reviewable profile preview.", "Have the asset owner, privacy/security personnel, clinical owner, counsel, or authorizing official validate requirements before operational changes."],
        "Research guidance emphasizes provenance, authorization, network scope, evidence, and disclosure. Government guidance emphasizes approved baselines and authorization boundaries. Clinical guidance emphasizes privacy, availability, shared sessions, vendor support, and patient-safety change control without collecting patient content. Legal guidance emphasizes client confidentiality, privilege boundaries, retention, secure communications, and access control without collecting client content. These are readiness prompts, not compliance determinations.",
        ["reports_exports", "operational_health", "glossary"],
        ["false positive"],
    ),
    "troubleshooting": _topic(
        "troubleshooting",
        "Troubleshooting Hub",
        "Troubleshooting",
        "Actionable fixes for common MSAA visibility, health, alerting, integrity, exposure, network, device, and export issues.",
        "Troubleshooting is organized by symptom. Each guide explains the likely cause, fix steps, and verification steps without exposing raw debug logs in Help.",
        ["A feature does not behave as expected.", "You need a next step before changing settings or collecting support information."],
        ["Start with the symptom closest to what you see.", "Refresh Operational Health when the cause is unclear.", "Verify the fix using the steps listed in the guide."],
        "Detailed diagnostic data can be exported from feature views when needed, but Help content remains summarized and user-readable.",
        ["operational_health", "alert_severity", "integrity_verification"],
        ["daemon", "notifier", "integrity", "drift"],
        list(TROUBLESHOOTING_GUIDES),
    ),
    "glossary": _topic(
        "glossary",
        "Glossary",
        "Glossary",
        "Searchable definitions for common MSAA, macOS, and security terms.",
        "The glossary provides one consistent definition for terms used across MSAA so alerts, reports, and Help topics use the same language.",
        ["You see an unfamiliar term.", "A report or alert uses security vocabulary you want to verify."],
        ["Use simple definitions first.", "Open related topics for workflow guidance.", "Slow down before taking disruptive action when a term is unfamiliar."],
        "Glossary entries include simple definitions, technical definitions, examples, and related terms. Topic pages link to glossary entries by term.",
        ["help_center", "alert_severity", "persistence_intelligence"],
        ["alert severity levels", "integrity", "trusted manifest", "baseline", "persistence", "daemon", "LaunchAgent", "CVE", "KEV", "MITRE ATT&CK", "false positive", "evidence snapshot"],
    ),
    "anti_typosquatting": _topic(
        "anti_typosquatting",
        "Anti-Typosquatting Protection",
        "Software Supply Chain",
        "Find realistic lookalike domains and package names before they become supply-chain, phishing, fraud, or brand-impersonation infrastructure.",
        "Developers and testers can validate proposed package coordinates and dependency changes; administrators can protect organizational namespaces; defenders can maintain lookalike watchlists; and incident responders can investigate suspicious domains, packages, publishers, download links, or update channels. MSAA models typing errors, keyboard adjacency, omitted, repeated, or transposed characters, separator and registry-normalization collisions, namespace confusion, misleading affixes, internationalized names, and Unicode visual impersonation. Generation is local. Optional registry checks disclose selected candidate names only after consent and never visit websites or install packages.",
        ["You are designing or launching a product, domain, package, publisher namespace, or update channel.", "A manifest, pull request, build, deployment, email, alert, or support case references a confusingly similar name.", "You need to prioritize defensive registration, continuous monitoring, fraud prevention, or investigation of an existing lookalike."],
        ["Design: inventory canonical product, organization, domain, publisher, and package identities and assign accountable owners.", "Develop and review: scan proposed names, manifests, lockfiles, and dependency changes; confirm exact registry coordinates and publisher identity.", "Build and release: gate CI/CD on approved names, ownership evidence, provenance, and package allowlists.", "Operate: monitor prioritized lookalikes and reassess when products, registries, locales, or threat intelligence change.", "Respond: preserve registry and local evidence, correlate with downloads, execution, credentials, and communications, then coordinate authorized registrar, registry, legal, fraud, or takedown action.", "Where appropriate, have authorized brand and legal owners consider defensive registration before an attacker uses a high-risk available variant."],
        "Anti-Typosquatting is a preventive and detective SDLC control, not a one-time naming exercise. Human typo likelihood, impersonation similarity, defensive-registration priority, and investigation priority remain separate and explainable. A similar or already registered name is not automatically malicious, and RDAP or registry not-found responses do not prove availability, ownership, abuse, or legal entitlement. Confirm conclusions with authoritative registry, publisher, provenance, legal, and incident evidence.",
        ["reports_exports", "integrity_verification", "troubleshooting"],
        ["typosquatting", "Unicode confusable", "RDAP", "package normalization"],
        safety=["Use only for identities you own, administer, test, or are authorized to protect.", "Do not contact, visit, download from, accuse, or disrupt a candidate solely because it is similar.", "Defensive registration must be approved by the relevant brand, legal, procurement, registrar, registry, and security owners.", "MSAA does not prove availability or malicious intent, provide legal advice, register domains, publish packages, visit candidate sites, or install candidate software."],
    ),
    "about_msaa": _topic(
        "about_msaa",
        "About MSAA",
        "Glossary",
        "Product, version, license, privacy, local-first design, and disclaimer information.",
        "MSAA is the macOS Security Audit Agent. It is designed as a local-first defensive audit and investigation tool.",
        ["You need version, build, privacy, or license information.", "You are sharing a bug report or evaluation note."],
        ["Check installed version when reporting bugs.", "Review exported files before sharing.", "Use professional incident response support for high-risk or regulated incidents."],
        "MSAA does not replace professional incident response, legal advice, or vendor-supported remediation. Exported artifacts remain local unless the user shares them.",
        ["help_center", "reports_exports", "troubleshooting"],
        ["evidence snapshot", "false positive"],
    ),
    "pre_uat_audit": _topic(
        "pre_uat_audit",
        "Pre-UAT Audit",
        "Glossary",
        "How developers and release testers use the pre-user-acceptance audit.",
        "Pre-UAT Audit checks whether MSAA is ready for user acceptance testing by reviewing UI controls, settings, daemon and notifier behavior, alert pipeline, scans, exports, and release readiness.",
        ["You are validating a build before release.", "You need regression-oriented quality evidence."],
        ["Run the full audit before a release candidate.", "Fix blockers before handing the app to users.", "Export the audit report for regression tracking."],
        "Pre-UAT output is quality evidence for maintainers and testers. It should not be mixed into user Help pages as raw diagnostic output.",
        ["operational_health", "reports_exports", "troubleshooting"],
        ["notifier", "daemon", "alert severity levels"],
    ),
    "framework_coverage": _topic(
        "framework_coverage", "Framework Coverage Overview", "Governance & Compliance",
        "How to interpret MSAA mappings and turn them into a client-specific implementation and assessment work plan.",
        "Framework Coverage shows where MSAA checks can contribute technical evidence. A mapping is not proof that every requirement is met, and a blank mapping is not automatically a control failure. Applicability, assessment scope, inherited controls, policies, people, processes, and client contract terms must also be evaluated.",
        ["You are new to a framework.", "You are defining client scope or preparing for an internal, third-party, or government assessment.", "You need to distinguish automated evidence from management and process evidence."],
        ["Confirm the authoritative framework version and client-required assessment type.", "Document systems, users, data, facilities, service providers, and exclusions in scope.", "Assign an owner to every applicable outcome or requirement.", "For each requirement record implementation, objective evidence, test method, exceptions, gaps, and remediation date.", "Have the client and qualified assessor validate conclusions before making certification or compliance claims."],
        "Use the matrix as a crosswalk and evidence index. Build a responsibility matrix covering client, MSP/MSSP, cloud provider, and inherited controls. Preserve dated, attributable evidence and record whether it was examined, tested, or supported by interview. Official starting points: https://www.nist.gov/cyberframework, https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final, https://attack.mitre.org/resources/, and https://dodcio.defense.gov/CMMC/.",
        ["framework_nist_csf","framework_mitre_attack","framework_nist_800_53","framework_cmmc_dod","framework_evidence_expectations"], ["MITRE ATT&CK", "evidence snapshot", "baseline"],
        safety=["MSAA does not certify an organization or replace a contracting officer, C3PAO, DIBCAC, authorizing official, legal counsel, or qualified assessor."]
    ),
    "framework_nist_csf": _topic(
        "framework_nist_csf", "NIST CSF 2.0 Implementation Guidance", "Governance & Compliance",
        "Use Govern, Identify, Protect, Detect, Respond, and Recover outcomes to build Current and Target Organizational Profiles.",
        "CSF 2.0 is outcome-oriented and risk-based. Start with mission, stakeholders, risk appetite, legal obligations, and current practices. A Current Profile records achieved outcomes; a Target Profile records prioritized desired outcomes. Gaps become an improvement plan with owners, resources, dependencies, and measures.",
        ["A client requests a CSF assessment or roadmap.", "Leadership needs a risk-based improvement plan rather than a technical checklist."],
        ["Agree on Organizational Profile scope and stakeholders.", "Determine applicable Core outcomes and document current evidence.", "Define a Target Profile informed by threats, business impact, requirements, and Community Profiles.", "Prioritize gaps and measurable actions.", "Use Tiers only as context for governance rigor; NIST states they are not maturity levels."],
        "MSAA mappings contribute endpoint observations but cannot establish organization-wide outcomes alone. Validate governance, supply-chain, workforce, incident, recovery, and third-party practices. Official resources: https://www.nist.gov/cyberframework, https://www.nist.gov/cyberframework/profiles, and https://www.nist.gov/cyberframework/quick-start-guides.",
        ["framework_coverage","framework_evidence_expectations"], ["baseline", "drift", "evidence snapshot"]
    ),
    "framework_mitre_attack": _topic(
        "framework_mitre_attack", "MITRE ATT&CK Matrix Guidance", "Governance & Compliance",
        "Use ATT&CK to describe adversary behavior, threat-informed priorities, detections, and validation—not as a compliance checklist.",
        "ATT&CK techniques describe observed adversary behaviors. Coverage should distinguish visibility, analytic logic, alerting, investigation procedure, prevention, and validated response. One rule mapped to a technique does not cover every procedure, platform, data source, or evasion variant.",
        ["You are building a threat-informed detection program.", "A client asks for ATT&CK coverage percentages or Navigator layers."],
        ["Select relevant platforms, threat groups, software, and techniques from defensible threat intelligence.", "For each technique record required data sources, analytic assumptions, blind spots, test procedure, owner, and last validation date.", "Test safely with authorized emulation and retain expected-versus-observed results.", "Prioritize meaningful detection quality instead of pursuing 100 percent matrix coverage."],
        "Report separate states such as mapped, telemetry available, analytic implemented, alert verified, response exercised, partial, and not applicable. Official ATT&CK guidance explicitly cautions against trying to achieve complete coverage: https://attack.mitre.org/resources/.",
        ["framework_coverage","framework_evidence_expectations","keylogger_detection"], ["MITRE ATT&CK", "false positive", "evidence snapshot"]
    ),
    "framework_nist_800_53": _topic(
        "framework_nist_800_53", "NIST SP 800-53 and 800-53A Guidance", "Governance & Compliance",
        "Select, tailor, implement, document, and assess controls using the applicable RMF context and SP 800-53A procedures.",
        "SP 800-53 is a control catalog, not a universal checklist. The organization selects an applicable baseline and tailors it based on categorization, overlays, risk, law, policy, and authorizing guidance. SP 800-53A supplies customizable assessment objectives and examine, interview, and test methods.",
        ["A federal client, authorizing official, or contract references SP 800-53.", "You are preparing an SSP, assessment plan, or control assessment report."],
        ["Confirm system categorization, baseline, overlays, tailoring decisions, organization-defined parameters, and common controls.", "Document implementation statements with who, what, where, when, and how.", "Trace each assessment objective to evidence and an examine, interview, or test procedure.", "Record findings, risk, compensating controls, remediation, continuous-monitoring frequency, and authorization decisions."],
        "MSAA endpoint output may support selected technical objectives but cannot establish design, operating effectiveness, or organization-wide implementation without the full assessment procedure. Use current normative publications and derivative data: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final and https://csrc.nist.gov/pubs/sp/800/53/a/r5/final.",
        ["framework_coverage","framework_evidence_expectations"], ["evidence snapshot", "baseline", "drift"]
    ),
    "framework_cmmc_dod": _topic(
        "framework_cmmc_dod", "CMMC and DoD Assessment Guidance", "Governance & Compliance",
        "Prepare evidence for the contractually required CMMC level while preserving the exact FCI/CUI assessment scope and official assessment method.",
        "CMMC requirements depend on the solicitation or contract, information handled, assessment scope, and required status. Level 1 addresses FCI basic safeguarding. Level 2 addresses CUI requirements aligned to the program's specified NIST SP 800-171 revision. Level 3 adds selected enhanced requirements and government assessment. Always verify current DoD rules and contract language because implementation phases and program guidance can change.",
        ["A DoD contractor or subcontractor handles FCI or CUI.", "A client is preparing for a self-assessment, C3PAO assessment, or DIBCAC assessment."],
        ["Obtain the contract clauses and required CMMC level before defining scope.", "Create diagrams and inventories for in-scope assets, CUI data flows, security protection assets, specialized assets, external service providers, and out-of-scope boundaries.", "Build an SSP and requirement-by-requirement evidence matrix using the official Assessment Guide methods: examine, interview, and test.", "Ensure evidence demonstrates persistent implementation, not a screenshot-only point in time.", "Track permitted POA&Ms separately and verify restrictions and deadlines; do not assume every unmet requirement is eligible.", "Use an authorized C3PAO or DIBCAC where the required assessment type demands it, and have an authorized affirming official review submissions."],
        "MSAA is preparation support only and cannot produce CMMC status or submit to SPRS/eMASS. Verify current sources at https://dodcio.defense.gov/CMMC/About/ and https://dodcio.defense.gov/cmmc/Resources-Documentation/. Contract terms, 32 CFR part 170, DFARS, scoping guides, and the applicable official Assessment Guide control.",
        ["framework_coverage","framework_evidence_expectations","framework_nist_800_53"], ["evidence snapshot", "baseline", "drift"],
        safety=["Do not label MSAA readiness output as CMMC certification, a C3PAO conclusion, a DIBCAC score, or an SPRS submission."]
    ),
    "framework_evidence_expectations": _topic(
        "framework_evidence_expectations", "Evidence and Client Expectation Guidance", "Governance & Compliance",
        "Create an assessment-ready evidence package that is scoped, attributable, current, reproducible, protected, and tied to each criterion.",
        "Good evidence explains what requirement it supports, which asset and boundary it covers, who owns it, when it was collected, how it was produced, and what limitation remains. Client expectations should be agreed in writing before testing begins.",
        ["You are planning evidence requests, testing, interviews, or client deliverables.", "A technical check is mapped but the client still needs policy, process, or operating-effectiveness evidence."],
        ["Agree on framework version, scope, assessment type, deliverables, sampling period, data handling, retention, and acceptance criteria.", "Maintain a request list and responsibility matrix.", "For each criterion collect authoritative documents, configurations, records, interviews, and repeatable test results as applicable.", "Record source, timestamp, custodian, integrity hash where appropriate, redactions, exceptions, and limitations.", "Separate met, partially met, not met, not applicable, inherited, and not tested conclusions.", "Perform quality review and obtain client acceptance without overstating assurance."],
        "A useful evidence index includes requirement ID, implementation statement, asset/scope, evidence ID, examine/interview/test method, result, assessor notes, owner, collection date, validity period, gap, POA&M reference, and retest outcome. Protect CUI, credentials, personal data, and sensitive architecture throughout collection and transfer.",
        ["framework_coverage","reports_exports","live_response"], ["evidence snapshot", "integrity", "baseline"],
        safety=["Collect only authorized evidence and follow the client's data classification, chain-of-custody, retention, and secure-transfer requirements."]
    ),
}

_ANTI_TYPOSQUATTING_HELP = {
    "anti_typosquatting_domains": ("Protecting Internet Domains", "RDAP and DNS metadata do not prove that a name is available or abusive."),
    "anti_typosquatting_npm": ("Protecting npm Packages", "Review package and organization scope separately; MSAA never downloads or installs a package."),
    "anti_typosquatting_pypi": ("Protecting Python Packages", "PyPA separator and case normalization is applied before comparison and lookup."),
    "anti_typosquatting_rust": ("Protecting Rust Crates", "Cargo registry identity and Rust underscore import projection remain distinct."),
    "anti_typosquatting_ruby": ("Protecting Ruby Gems", "Gem registry identity and common require path remain distinct."),
    "anti_typosquatting_nuget": ("Protecting NuGet Packages", "NuGet identifiers are compared case-insensitively and publisher prefix evidence is contextual."),
    "anti_typosquatting_maven": ("Protecting Maven Coordinates", "Maven group and artifact identifiers are modeled as separate coordinate components."),
    "anti_typosquatting_go": ("Protecting Go Modules", "Module host, path, subdirectory, and semantic import major version are reviewed separately."),
    "anti_typosquatting_composer": ("Protecting Composer Packages", "Packagist vendor and package components are distinct namespace identities."),
    "anti_typosquatting_project_audit": ("Auditing Local Dependencies", "Manifest parsing is local, bounded, read-only, and never invokes package managers."),
    "anti_typosquatting_investigations": ("Investigating Existing Lookalikes", "Similarity is a lead; human disposition and authoritative evidence are required for fraud conclusions."),
    "anti_typosquatting_scores": ("Understanding Anti-Typosquatting Risk Scores", "Human typo, namespace, visual, reachability, ownership, investigation, and defensive priorities remain explainable."),
    "anti_typosquatting_reporting": ("Registry Reporting and Legal Limitations", "MSAA prepares local evidence but never submits reports or provides legal advice."),
    "anti_typosquatting_privacy": ("Online Lookup Privacy", "Names are disclosed only after consent to allowlisted metadata providers."),
    "anti_typosquatting_go_privacy": ("Go Module Privacy", "Paths matching private patterns must never be sent to public proxies or checksum services."),
    "anti_typosquatting_executive_reports": ("Executive and Investor Reports", "Portfolio summaries redact private paths and distinguish evidence from machine assessment."),
}
for _topic_id, (_title, _details) in _ANTI_TYPOSQUATTING_HELP.items():
    TOPICS[_topic_id] = _topic(_topic_id, _title, "Software Supply Chain", _details, _details, ["You are protecting or reviewing an authorized namespace."], ["Review normalized identity, evidence, limitations, and ownership before acting."], _details, ["anti_typosquatting", "reports_exports"], ["typosquatting", "package normalization"])


@lru_cache(maxsize=1)
def all_topics() -> dict[str, HelpTopic]:
    return dict(TOPICS)


def get_topic(topic_id: str) -> HelpTopic | None:
    return all_topics().get(topic_id)


def list_topics() -> list[HelpTopic]:
    topics = all_topics()
    ordered: list[HelpTopic] = []
    seen: set[str] = set()
    for topic_ids in HELP_CATEGORIES.values():
        for topic_id in topic_ids:
            topic = topics.get(topic_id)
            if topic is not None:
                ordered.append(topic)
                seen.add(topic_id)
    ordered.extend(topic for topic_id, topic in topics.items() if topic_id not in seen)
    return ordered


def search_topics(query: str) -> list[HelpTopic]:
    normalized = query.strip().lower()
    topics = list_topics()
    if not normalized:
        return topics
    results: list[tuple[int, HelpTopic]] = []
    for topic in topics:
        haystack_parts = [
            topic.title,
            topic.short_summary,
            topic.user_friendly_explanation,
            " ".join(topic.when_this_matters),
            " ".join(topic.what_you_should_do),
            topic.advanced_details,
            " ".join(topic.glossary_terms),
            " ".join(topic.related_topics),
            topic.category,
        ]
        haystack = "\n".join(haystack_parts).lower()
        if normalized in haystack:
            score = haystack.count(normalized)
            if normalized in topic.title.lower():
                score += 10
            if normalized in topic.short_summary.lower():
                score += 5
            if normalized in topic.category.lower():
                score += 3
            results.append((score, topic))
    return [topic for _score, topic in sorted(results, key=lambda item: (-item[0], item[1].title))]
