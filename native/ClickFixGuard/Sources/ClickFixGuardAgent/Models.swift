import Foundation

enum GuardMode: String { case observe = "OBSERVE"; case protect = "PROTECT" }
enum FailurePolicy: String { case failOpen = "FAIL_OPEN"; case failClosed = "FAIL_CLOSED" }

struct GuardPolicy {
    let mode: GuardMode
    let failurePolicy: FailurePolicy
    let quarantine: Bool
    let teamIdentifier: String

    static func fromEnvironment() -> GuardPolicy {
        let env = ProcessInfo.processInfo.environment
        let profile = env["MSAA_CLICKFIX_PROFILE"] ?? "WARN"
        let protect = profile == "PROTECT" || profile == "HIGH_ASSURANCE"
        return GuardPolicy(mode: protect ? .protect : .observe,
                           failurePolicy: profile == "HIGH_ASSURANCE" ? .failClosed : .failOpen,
                           quarantine: profile == "HIGH_ASSURANCE" || env["CLICKFIX_CLIPBOARD_QUARANTINE"] == "1",
                           teamIdentifier: env["MSAA_TEAM_IDENTIFIER"] ?? "")
    }
}

struct ShortcutRecord: Sendable {
    let timestampNS: UInt64
    let keyCode: Int64
    let flags: UInt64
    let physical: Bool
}

struct ClipboardSnapshot: Sendable {
    let accessState: String
    let changeCount: Int
    let contentType: String
    let bytes: Data?
    let text: String?
    let truncated: Bool
}

struct ClipboardClassification: Codable, Sendable {
    let classification: String
    let confidence: Double
    let languageCandidates: [String]
    let matchedCategories: [String]
    let commandLike: Bool
    let scriptLike: Bool
    let encodedContent: Bool
    let downloaderPresent: Bool
    let interpreterPresent: Bool
    let persistenceIndicators: Bool
    let credentialAccessIndicators: Bool
    let securityImpairmentIndicators: Bool
    let externalDestinationIndicators: Bool
    let redactedPreview: String?
    let classifierVersion: String
}
