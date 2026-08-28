import Foundation
import ClickFixGuardShared

private struct NativeHealthSnapshot: Codable {
    let clickfix_guard_installed: Bool
    let clickfix_guard_running: Bool
    let clickfix_guard_signature_valid: Bool
    let clickfix_guard_version: String
    let event_tap_active: Bool
    let event_tap_mode: String
    let input_monitoring_granted: Bool
    let accessibility_granted: Bool
    let clipboard_access_state: String
    let clipboard_classifier_loaded: Bool
    let classifier_signature_valid: Bool
    let classifier_version: String
    let xpc_listener_ready: Bool
    let xpc_authenticated: Bool
    let last_heartbeat_utc: String
    let event_queue_drops: UInt64
    let protect_mode_active: Bool
    let clipboard_quarantine_enabled: Bool
    let endpoint_security_correlation_available: Bool
    let development_demo: Bool

    var dictionary: [String: Any] {
        guard let data = try? JSONEncoder().encode(self),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return value
    }
}

let policy = GuardPolicy.fromEnvironment()
let developmentDemo = ProcessInfo.processInfo.environment["MSAA_CLICKFIX_DEVELOPER_MODE"] == "1"
let home = FileManager.default.homeDirectoryForCurrentUser
let directory = home.appendingPathComponent("Library/Application Support/MacAuditAgent/ClickFixGuard", isDirectory: true)
let journalURL = directory.appendingPathComponent("events.jsonl")

do {
    let journal = try EventJournal(url: journalURL)
    let replay = ShortcutReplayController()
    let classifierBundle = Bundle.module.url(forResource: "clickfix-rules", withExtension: "json", subdirectory: "Resources") ?? Bundle.module.url(forResource: "clickfix-rules", withExtension: "json")
    let classifierSignature = Bundle.module.url(forResource: "clickfix-rules", withExtension: "sig", subdirectory: "Resources") ?? Bundle.module.url(forResource: "clickfix-rules", withExtension: "sig")
    let classifier = ClipboardClassifier(ruleBundleURL: classifierBundle, signatureURL: classifierSignature)
    let shortcutQueue = BoundedShortcutQueue()
    var eventTapActive = false
    var xpcAuthenticated = false
    var lastHeartbeat = Date()
    let healthSnapshot: () -> NativeHealthSnapshot = {
        let permissions = PermissionMonitor.current()
        return NativeHealthSnapshot(
            clickfix_guard_installed: true, clickfix_guard_running: true,
            clickfix_guard_signature_valid: true, clickfix_guard_version: "1.0.0",
            event_tap_active: eventTapActive, event_tap_mode: policy.mode.rawValue,
            input_monitoring_granted: permissions.inputMonitoring == "INPUT_MONITORING_GRANTED",
            accessibility_granted: permissions.accessibility == "ACCESSIBILITY_GRANTED",
            clipboard_access_state: permissions.clipboard, clipboard_classifier_loaded: true,
            classifier_signature_valid: classifier.signatureValid, classifier_version: ClipboardClassifier.version,
            xpc_listener_ready: true, xpc_authenticated: xpcAuthenticated,
            last_heartbeat_utc: ISO8601DateFormatter().string(from: lastHeartbeat),
            event_queue_drops: shortcutQueue.drops, protect_mode_active: policy.mode == .protect,
            clipboard_quarantine_enabled: policy.quarantine, endpoint_security_correlation_available: false,
            development_demo: developmentDemo
        )
    }
    let health: () -> [String: Any] = { healthSnapshot().dictionary }
    let quarantine = ClipboardQuarantine()
    let service = ClickFixXPCService(journal: journal, quarantine: quarantine, health: health)
    let xpcDelegate = SecureXPCListenerDelegate(expectedTeamID: policy.teamIdentifier, service: service, onAccepted: { xpcAuthenticated = true }) {
        try? journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.xpcAuthenticationFailed.rawValue])
    }
    let listener = NSXPCListener(machServiceName: ClickFixProtocol.machServiceName)
    listener.delegate = xpcDelegate; listener.resume()
    if !classifier.signatureValid {
        try journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.classifierSignatureInvalid.rawValue, "generic_fallback_active": "true"])
    }
    let processor = EventProcessor(policy: policy, queue: shortcutQueue, journal: journal, replay: replay, classifier: classifier, quarantine: quarantine)
    if !PermissionMonitor.current().inputMonitoring.contains("GRANTED") {
        PermissionMonitor.requestInputMonitoring()
    }
    let tap = ClickFixEventTap(mode: policy.mode, replayMarker: replay.marker, queue: shortcutQueue) { code in
        eventTapActive = false
        try? journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": code.rawValue])
    }
    eventTapActive = tap.start()
    if !eventTapActive {
        try journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.inputMonitoringDenied.rawValue])
    }
    processor.start()
    func publishHealth() {
        lastHeartbeat = Date()
        // TCC approval is normally granted after the LaunchAgent has already
        // started. Recover in place instead of requiring the user to discover
        // and perform a manual launchctl restart.
        if !eventTapActive && PermissionMonitor.current().inputMonitoring == "INPUT_MONITORING_GRANTED" {
            eventTapActive = tap.start()
        }
        _ = try? journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: lastHeartbeat, payload: healthSnapshot())
    }
    publishHealth()
    let heartbeat = Timer(timeInterval: 10, repeats: true) { _ in publishHealth() }
    RunLoop.main.add(heartbeat, forMode: .common)
    RunLoop.main.run()
} catch {
    FileHandle.standardError.write(Data("MSAA ClickFix Guard failed safely: CFX014_EVIDENCE_PERSISTENCE_FAILED\n".utf8))
    exit(78)
}
