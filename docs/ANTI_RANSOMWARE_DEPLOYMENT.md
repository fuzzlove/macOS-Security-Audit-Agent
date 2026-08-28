# Anti-Ransomware Deployment

## Development sensor: streamlined administrator installation

In **Anti-Ransomware → Sensor Installation**, select **Review Install Plan**, then **Open Terminal for Administrator Install**. MSAA opens Apple Terminal with one fixed, visible, absolute-path command. The command invokes the existing headless protection installer; the GUI does not run as root. Review the command before continuing and enter the administrator password only into the macOS `sudo` prompt. MSAA does not receive, store, or log that password.

The elevation is consequential: the installer writes root-owned files under `/Library`, registers the existing System Monitor LaunchDaemon, and enables boot-persistent monitoring. Use it only on a Mac you are authorized to administer. The installation is recorded as a redacted local audit event, without the command or password.

If Terminal automation is unavailable, select **Copy Exact Install Command** and paste the displayed command into Terminal. The copied command uses absolute shell-quoted paths and contains no credential. After it completes, select **Verify Sensor Installation**. A running development observer is still `DEGRADED_OBSERVATION_ONLY`; it is not a substitute for an Apple-entitled Endpoint Security system extension.

## Advisory and detection updates

MSAA does not convert government prose into executable rules. Allowlisted CISA advisories that publish explicitly named YARA rules can be downloaded with bounded HTTPS handling, staged, compiled against an inert fixture, hashed, and then activated only after named human approval. CISA KEV and NIST NVD data support vulnerability prioritization/correlation; they do not prove execution. FBI, public DoD, and INTERPOL publications are analyst guidance unless a separately approved, provenance-validated indicator package is available. Feed failure or staleness must be reported as degraded intelligence and must not stop local behavioral observation.

The privileged sensor does not perform unrestricted Internet retrieval. Review the **Advisory Update Policy** tab for source roles and limitations. MSAA makes no government endorsement, certification, or comprehensive-detection claim.

MSAA currently ships a development Endpoint Security client boundary and native containment-helper boundary. It is **not** a production Apple system extension until the extension target is bundled in a signed host app, uses the Apple-approved Endpoint Security entitlement, passes notarization, and is activated through the operating system.

The GUI must remain unprivileged. Installation must use a signed package and Apple's trusted authorization UI. Never type an administrator password into MSAA, pipe a password to `sudo`, disable TCC/SIP/Gatekeeper, or treat an installed file as a running service.

Production readiness requires verified Team ID, signing identifier, CDHash, entitlement, system-extension registration/load, live Endpoint Security client, subscribed events, live validation event, fresh heartbeat, Full Disk Access, signed policy/rules, authenticated helper, live containment validation, and valid MSAA integrity.

MDM templates are placeholders. Replace all identifiers from signed release evidence, assign new payload UUIDs, sign the profile through organizational MDM, test on disposable managed hosts, and never deploy the template verbatim.
