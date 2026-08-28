import Foundation
import Security
import ClickFixGuardShared

@objc protocol ClickFixGuardXPCProtocol {
    func fetchRecords(afterSequence: NSNumber, limit: NSNumber, withReply reply: @escaping ([Data], Data) -> Void)
    func ping(withReply reply: @escaping (Data) -> Void)
    func restoreQuarantinedClipboard(incidentID: String, justification: String, withReply reply: @escaping (Bool, String) -> Void)
}

final class ClickFixXPCService: NSObject, ClickFixGuardXPCProtocol {
    let journal: EventJournal
    let health: () -> [String: Any]
    let quarantine: ClipboardQuarantine
    init(journal: EventJournal, quarantine: ClipboardQuarantine, health: @escaping () -> [String: Any]) { self.journal = journal; self.quarantine = quarantine; self.health = health }
    func fetchRecords(afterSequence: NSNumber, limit: NSNumber, withReply reply: @escaping ([Data], Data) -> Void) {
        let safeLimit = max(1, min(limit.intValue, 256))
        let healthData = (try? JSONSerialization.data(withJSONObject: health(), options: [.sortedKeys])) ?? Data("{}".utf8)
        reply(journal.records(after: afterSequence.uint64Value, limit: safeLimit), healthData)
    }
    func ping(withReply reply: @escaping (Data) -> Void) {
        reply((try? JSONSerialization.data(withJSONObject: health(), options: [.sortedKeys])) ?? Data("{}".utf8))
    }
    func restoreQuarantinedClipboard(incidentID: String, justification: String, withReply reply: @escaping (Bool, String) -> Void) {
        guard justification.trimmingCharacters(in: .whitespacesAndNewlines).count >= 8 else { reply(false, "Authorized justification is required."); return }
        guard let changeCount = quarantine.restore(incidentID: incidentID) else { reply(false, ClickFixErrorCode.clipboardQuarantineFailed.rawValue); return }
        let payload = ["action": "RESTORE_QUARANTINED_CLIPBOARD", "incident_id": incidentID, "justification": justification, "resulting_change_count": String(changeCount)]
        do { try journal.append(type: "action", id: "cfx-restore-\(UUID().uuidString.lowercased())", occurredAt: Date(), payload: payload); reply(true, "restored_and_audited") }
        catch { reply(false, ClickFixErrorCode.evidencePersistenceFailed.rawValue) }
    }
}

final class SecureXPCListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let expectedTeamID: String
    private let service: ClickFixXPCService
    private let developerMode: Bool
    private let onRejected: () -> Void
    private let onAccepted: () -> Void
    init(expectedTeamID: String, service: ClickFixXPCService, onAccepted: @escaping () -> Void, onRejected: @escaping () -> Void) {
        self.expectedTeamID = expectedTeamID; self.service = service; self.onRejected = onRejected
        self.onAccepted = onAccepted
        self.developerMode = ProcessInfo.processInfo.environment["MSAA_CLICKFIX_DEVELOPER_MODE"] == "1"
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard authenticate(pid: connection.processIdentifier) else { onRejected(); return false }
        onAccepted(); connection.exportedInterface = NSXPCInterface(with: ClickFixGuardXPCProtocol.self)
        connection.exportedObject = service; connection.resume(); return true
    }
    private func authenticate(pid: pid_t) -> Bool {
        if developerMode && expectedTeamID.isEmpty { return true }
        guard !expectedTeamID.isEmpty else { return false }
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return false }
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoTeamIdentifier as String] as? String == expectedTeamID,
              let identifier = values[kSecCodeInfoIdentifier as String] as? String else { return false }
        return identifier == "com.fuzzlove.macos-security-audit-agent" || identifier == "com.macos-security-audit-agent" || identifier.hasPrefix("com.macos-security-audit-agent.")
    }
}
