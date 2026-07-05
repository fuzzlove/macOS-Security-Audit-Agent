# Persistence Intelligence Feature Matrix

| macOS Persistence Radar feature | current MSAA equivalent | gap exists yes/no | integration plan | implementation status | tests added yes/no |
|---|---|---:|---|---|---:|
| scan | Safe Scan/Admin & Persistence | yes | Native `PersistenceIntelligenceEngine.scan()` | implemented | yes |
| scan --debug | diagnostics panels | partial | Persistence diagnostics output | implemented | yes |
| scan --json | JSON exports | partial | CLI `persistence scan` JSON | implemented | yes |
| scan --all | scanner registry | partial | CLI `persistence scan --all` | implemented | yes |
| scan --module launchd | launch item review | yes | CLI `--module launchd` and `LaunchdScanner` | implemented | yes |
| scan --module browser_extensions | limited command registry | yes | `BrowserPersistenceScanner` | implemented | yes |
| coverage | Monitoring Coverage | yes | Persistence coverage records | implemented | yes |
| chains | Evidence Graph/Workflow | yes | structured chain view | implemented | yes |
| posture | Security Assessment | yes | persistence posture score | implemented | yes |
| timeline export | Security Timeline | partial | persistence timeline JSON/HTML/Markdown | implemented | yes |
| malware-kb | IOC matching | yes | local pattern correlation KB | implemented | yes |
| doctor | Operational Health/diagnostics | partial | Persistence diagnostics | implemented | yes |
| baseline create | Baseline Drift/Fleet Baseline | partial | Persistence baseline manager | implemented | yes |
| baseline compare | Baseline Drift | partial | added/removed/modified/hash/permission/signature comparison | implemented | yes |
| watch mode | Background monitor | partial | read-only baseline diff event helper | initial helper | partial |
| export html/json/md | reports | partial | persistence report adapter | implemented | yes |
| LaunchAgents | Admin/Persistence scan | partial | plist scanner | implemented | yes |
| LaunchDaemons | Admin/Persistence scan | partial | plist scanner | implemented | yes |
| launchctl print | monitor readiness | yes | status enrichment future step | planned | no |
| launchctl print-disabled | none | yes | disabled-state enrichment future step | planned | no |
| Background Task Management | none | yes | readable indicators | implemented | no |
| SMAppService records | none | yes | readable indicators | partial | no |
| Login Items | startup review | partial | BackgroundItemsScanner | partial | no |
| Background Items | none | yes | BackgroundItemsScanner | partial | no |
| Reopened Applications/session restore | none | yes | Saved Application State inventory | implemented | no |
| cron jobs | command registry | partial | ScheduledJobsScanner | implemented | no |
| at jobs | none | yes | ScheduledJobsScanner | implemented | no |
| periodic scripts | none | yes | ScheduledJobsScanner | implemented | no |
| /Library/Scripts | none | yes | ScheduledJobsScanner | implemented | no |
| shell startup files | history indicators | partial | ShellStartupScanner with redaction | implemented | yes |
| authorization plugins | none | yes | AuthorizationPluginScanner | implemented | no |
| Safari/Chrome/Chromium/Edge/Brave/Firefox extensions | limited path review | yes | BrowserPersistenceScanner | implemented | yes |
| browser native messaging hosts | command registry | partial | BrowserPersistenceScanner | implemented | yes |
| configuration profiles | privacy/security review | partial | ProfileAndManagedPreferencesScanner | implemented | no |
| managed preferences | none | yes | ProfileAndManagedPreferencesScanner | implemented | no |
| certificate trust stores | none | yes | CertificateTrustScanner | implemented | no |
| system/network/DNS/VPN/content filter/Endpoint Security extensions | none | yes | ExtensionInventoryScanner | partial | no |
| privileged helper tools | launch/persistence review | partial | PrivilegedHelperScanner | implemented | no |
| PATH hijack indicators | file issues | partial | PathHijackScanner | implemented | no |
| support-directory hunt | file issues | partial | bounded scanner | implemented | no |
| local users and groups | user snapshots | partial | UserGroupPersistenceScanner | implemented | no |
| readable TCC indicators | privacy review | partial | TCCIndicatorScanner | implemented | no |
| risk scoring | finding severity | partial | Persistence risk scoring | implemented | yes |
| trust/reputation scoring | confidence/review state | yes | Trust score and labels | implemented | yes |
| baseline comparison | Baseline Drift | partial | Persistence baselines | implemented | yes |
| timeline | Security Timeline | partial | persistence timeline | implemented | yes |
| chain view | Evidence Graph | partial | structured chain relationships | implemented | yes |
| posture score | Security Assessment | partial | persistence posture score | implemented | yes |
| heat map | dashboards | yes | mechanism/severity summary future UI | planned | no |
| scanner coverage/diagnostics | Monitoring Coverage | partial | coverage and diagnostics adapters | implemented | yes |
| MITRE ATT&CK mapping | framework mapping | partial | persistence mapping table | implemented | yes |
| malware library correlation | IOC matching | yes | local KB pattern correlation | implemented | yes |
| HTML/JSON/Markdown reports | reporting | partial | persistence report adapter | implemented | yes |
| Word/Excel/SARIF persistence sections | exporters | yes | integrate into office/SARIF exporters | planned | no |
