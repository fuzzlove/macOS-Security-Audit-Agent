import Foundation

public struct EventEnvelope: Codable, Sendable {
    public let schemaVersion: Int
    public let eventID: String
    public var incidentID: String?
    public let eventType: String
    public let detectedAtUTC: Date
    public let monotonicTimestampNS: UInt64
    public let keyCode: Int64
    public let modifierFlags: UInt64
    public let physicalEvent: Bool
    public let replayEvent: Bool
    public var foregroundPID: Int32?
    public var foregroundBundleID: String?
    public var foregroundSigningIdentifier: String?
    public var foregroundTeamIdentifier: String?
    public var clipboardChangeCount: Int?
    public var clipboardAccessState: String
    public var clipboardClassification: String
    public var clipboardSHA256: String?
    public var clipboardByteLength: Int?
    public var classifierVersion: String?
    public var confidence: Double?
    public var matchedCategories: [String]
    public var redactedPreview: String?
    public var sensorMode: String
    public var inputMonitoringState: String
    public var accessibilityState: String
    public var spotlightSuppressed: Bool
    public var shortcutReplayed: Bool
    public var clipboardQuarantined: Bool
    public var disposition: String
    public var testEvent: Bool

    public init(eventID: String, eventType: String = "CLICKFIX_SHORTCUT", detectedAtUTC: Date,
                monotonicTimestampNS: UInt64, keyCode: Int64, modifierFlags: UInt64,
                physicalEvent: Bool, replayEvent: Bool, sensorMode: String) {
        self.schemaVersion = ClickFixProtocol.schemaVersion; self.incidentID = nil
        self.eventID = eventID; self.eventType = eventType; self.detectedAtUTC = detectedAtUTC
        self.monotonicTimestampNS = monotonicTimestampNS; self.keyCode = keyCode
        self.modifierFlags = modifierFlags; self.physicalEvent = physicalEvent; self.replayEvent = replayEvent
        self.sensorMode = sensorMode; self.clipboardAccessState = "CLIPBOARD_ACCESS_UNKNOWN"
        self.clipboardClassification = "CLASSIFICATION_FAILED"; self.inputMonitoringState = "INPUT_MONITORING_UNKNOWN"
        self.accessibilityState = "ACCESSIBILITY_UNKNOWN"; self.matchedCategories = []
        self.spotlightSuppressed = false; self.shortcutReplayed = false; self.clipboardQuarantined = false
        self.disposition = "NONE"; self.testEvent = false
    }
}

public struct JournalBatch: Codable, Sendable {
    public let records: [Data]
    public let healthJSON: Data
}
