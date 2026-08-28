import CryptoKit
import CoreGraphics
import Foundation
import ClickFixGuardShared

final class EventProcessor {
    private let policy: GuardPolicy
    private let queue: BoundedShortcutQueue
    private let journal: EventJournal
    private let replay: ShortcutReplayController
    private let inspector = ClipboardInspector()
    private let classifier: ClipboardClassifier
    private let quarantine: ClipboardQuarantine
    private let notifications = NativeNotificationController()
    private let correlator: IncidentCorrelator
    private let worker = DispatchQueue(label: "com.msaa.clickfix.processor", qos: .userInitiated)
    private let clipboardQueue = DispatchQueue(label: "com.msaa.clickfix.clipboard", qos: .userInitiated)
    private var running = true
    private var reportedDrops: UInt64 = 0

    init(policy: GuardPolicy, queue: BoundedShortcutQueue, journal: EventJournal, replay: ShortcutReplayController, classifier: ClipboardClassifier, quarantine: ClipboardQuarantine) {
        self.policy = policy; self.queue = queue; self.journal = journal; self.replay = replay; self.classifier = classifier
        self.quarantine = quarantine
        self.correlator = IncidentCorrelator(journal: journal)
    }
    func start() { notifications.requestAuthorization { _ in }; worker.async { self.loop() } }
    func stop() { running = false; queue.available.signal() }

    private func loop() {
        while running {
            _ = queue.available.wait(timeout: .now() + .seconds(1))
            if queue.drops > reportedDrops {
                let newlyDropped = queue.drops - reportedDrops; reportedDrops = queue.drops
                try? journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.eventQueueOverflow.rawValue, "newly_dropped": String(newlyDropped), "total_dropped": String(reportedDrops)])
            }
            while let record = queue.dequeue() { process(record) }
        }
    }
    private func process(_ record: ShortcutRecord) {
        let detected = Date(); let eventID = "cfx-event-\(UUID().uuidString.lowercased())"
        var snapshot: ClipboardSnapshot?
        let group = DispatchGroup(); group.enter()
        clipboardQueue.async { snapshot = self.inspector.inspect(); group.leave() }
        let clipboardTimedOut = group.wait(timeout: .now() + .milliseconds(100)) == .timedOut
        let permissions = PermissionMonitor.current()
        var envelope = EventEnvelope(eventID: eventID, detectedAtUTC: detected, monotonicTimestampNS: record.timestampNS, keyCode: record.keyCode, modifierFlags: record.flags, physicalEvent: record.physical, replayEvent: false, sensorMode: policy.mode.rawValue)
        envelope.inputMonitoringState = permissions.inputMonitoring; envelope.accessibilityState = permissions.accessibility
        envelope.spotlightSuppressed = policy.mode == .protect
        let application = FrontmostApplicationCollector.collect()
        envelope.foregroundPID = application.pid; envelope.foregroundBundleID = application.bundleID
        envelope.foregroundSigningIdentifier = application.signingIdentifier; envelope.foregroundTeamIdentifier = application.teamIdentifier
        var risky = false; var unavailable = clipboardTimedOut || (!classifier.signatureValid && policy.failurePolicy == .failClosed)
        if let snapshot, !clipboardTimedOut {
            envelope.clipboardAccessState = snapshot.accessState; envelope.clipboardChangeCount = snapshot.changeCount
            envelope.clipboardByteLength = snapshot.bytes?.count
            if let bytes = snapshot.bytes { envelope.clipboardSHA256 = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
            let classification = classifier.classify(snapshot)
            envelope.clipboardClassification = classification.classification; envelope.classifierVersion = classification.classifierVersion
            envelope.confidence = classification.confidence; envelope.matchedCategories = classification.matchedCategories; envelope.redactedPreview = classification.redactedPreview
            risky = classification.commandLike || classification.scriptLike || classification.classification == "SOURCE_CODE_FRAGMENT"
            unavailable = classification.classification == "CLASSIFICATION_FAILED"
        } else {
            envelope.clipboardAccessState = clipboardTimedOut ? "CLIPBOARD_ACCESS_UNKNOWN" : "CLIPBOARD_ACCESS_DENIED"
            envelope.clipboardClassification = "CLASSIFICATION_FAILED"
        }
        let incidentID = risky ? "cfx-incident-\(UUID().uuidString.lowercased())" : nil
        envelope.incidentID = incidentID
        if risky { envelope.disposition = "POTENTIAL_CLICKFIX" }
        let quarantined = policy.quarantine && incidentID != nil && snapshot != nil && quarantine.preserveAndApply(snapshot: snapshot!, incidentID: incidentID!) != nil
        envelope.clipboardQuarantined = quarantined
        do {
            try journal.append(type: "shortcut", id: eventID, occurredAt: detected, payload: envelope)
            if let incidentID {
                let incident: [String: String] = ["incident_id": incidentID, "shortcut_event_id": eventID, "disposition": "POTENTIAL_CLICKFIX", "severity": "critical", "attack_mapping": "T1204.004", "created_at_utc": ISO8601DateFormatter().string(from: detected)]
                try journal.append(type: "incident", id: incidentID, occurredAt: detected, payload: incident)
                correlator.begin(incidentID: incidentID)
                if quarantined {
                    let quarantineRecord = ["incident_id": incidentID, "action": "CLIPBOARD_QUARANTINED", "original_sha256": envelope.clipboardSHA256 ?? "", "raw_content_persisted": "encrypted_policy_vault"]
                    try journal.append(type: "action", id: "cfx-quarantine-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: quarantineRecord)
                }
                notifications.critical(incidentID: incidentID) { success in
                    try? self.journal.append(type: "action", id: "cfx-notification-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["action": "NATIVE_NOTIFICATION_REQUEST", "incident_id": incidentID, "request_accepted": String(success), "user_visibility_confirmed": "false"])
                    if !success { try? self.journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.notificationDeliveryFailed.rawValue]) }
                }
            }
            if policy.mode == .protect && !risky {
                let shouldReplay = !unavailable || policy.failurePolicy == .failOpen
                if shouldReplay {
                    if replay.replay(flags: CGEventFlags(rawValue: record.flags)) {
                        try? journal.append(type: "action", id: "cfx-replay-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["action": "SHORTCUT_REPLAYED", "shortcut_event_id": eventID, "replay_marker_recorded": "true"])
                    } else {
                        try? journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.shortcutReplayFailed.rawValue])
                    }
                }
            }
        } catch {
            // Protect mode intentionally remains suppressed when durable persistence fails.
            try? journal.append(type: "health", id: "cfx-health-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: ["error_code": ClickFixErrorCode.evidencePersistenceFailed.rawValue])
        }
    }
}
