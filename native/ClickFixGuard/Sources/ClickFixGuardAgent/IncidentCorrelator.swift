import AppKit
import Foundation

final class IncidentCorrelator {
    private struct Lease { let incidentID: String; let expires: Date }
    private var leases: [Lease] = []
    private let queue = DispatchQueue(label: "com.msaa.clickfix.correlation")
    private let journal: EventJournal
    private let terminalBundleIDs: Set<String> = ["com.apple.Terminal", "com.googlecode.iterm2", "dev.warp.Warp-Stable", "org.alacritty", "net.kovidgoyal.kitty", "com.github.wez.wezterm"]

    init(journal: EventJournal) {
        self.journal = journal
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(launched(_:)), name: NSWorkspace.didLaunchApplicationNotification, object: nil)
    }
    func begin(incidentID: String, seconds: TimeInterval = 120) { queue.async { self.leases.append(Lease(incidentID: incidentID, expires: Date().addingTimeInterval(seconds))) } }
    @objc private func launched(_ notification: Notification) {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
              let bundleID = app.bundleIdentifier, terminalBundleIDs.contains(bundleID) else { return }
        queue.async {
            let now = Date(); self.leases.removeAll { $0.expires < now }
            for lease in self.leases {
                let recordID = "cfx-correlation-\(UUID().uuidString.lowercased())"
                let payload = ["incident_id": lease.incidentID, "application_bundle_id": bundleID, "observed_at_utc": ISO8601DateFormatter().string(from: now), "evidence_strength": "APPLICATION_LAUNCH_ONLY", "endpoint_security_execution_confirmed": "false"]
                try? self.journal.append(type: "correlation", id: recordID, occurredAt: now, payload: payload)
            }
        }
    }
}
