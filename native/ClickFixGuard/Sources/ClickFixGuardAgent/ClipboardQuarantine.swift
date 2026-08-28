import AppKit
import CryptoKit
import Foundation
import Security

final class ClipboardQuarantine {
    static let replacement = "MSAA blocked potentially unsafe command content from the clipboard.\nOpen the MSAA Alert Center to review the incident."

    private let vault: URL
    init(vault: URL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MacAuditAgent/ClickFixGuard/Quarantine", isDirectory: true)) {
        self.vault = vault
        try? FileManager.default.createDirectory(at: vault, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    func preserveAndApply(snapshot: ClipboardSnapshot, incidentID: String) -> Int? {
        guard let bytes = snapshot.bytes, let key = encryptionKey(),
              let sealed = try? AES.GCM.seal(bytes, using: key).combined else { return nil }
        let artifact = vault.appendingPathComponent(incidentID + ".cfxvault")
        do { try sealed.write(to: artifact, options: [.atomic, .completeFileProtection]); try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: artifact.path) }
        catch { return nil }
        let pasteboard = NSPasteboard.general
        guard pasteboard.changeCount == snapshot.changeCount else { return nil }
        pasteboard.clearContents()
        guard pasteboard.setString(Self.replacement, forType: .string) else { return nil }
        return pasteboard.changeCount
    }

    func restore(incidentID: String) -> Int? {
        guard incidentID.range(of: #"^cfx-incident-[a-z0-9-]+$"#, options: .regularExpression) != nil,
              let key = encryptionKey(), let combined = try? Data(contentsOf: vault.appendingPathComponent(incidentID + ".cfxvault")),
              combined.count <= 128 * 1024, let box = try? AES.GCM.SealedBox(combined: combined),
              let plaintext = try? AES.GCM.open(box, using: key), let text = String(data: plaintext, encoding: .utf8) else { return nil }
        let pasteboard = NSPasteboard.general; pasteboard.clearContents()
        return pasteboard.setString(text, forType: .string) ? pasteboard.changeCount : nil
    }

    private func encryptionKey() -> SymmetricKey? {
        let account = "com.macos-security-audit-agent.clickfix-quarantine-key"
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: account, kSecAttrAccount as String: NSUserName(), kSecReturnData as String: true]
        var result: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data, data.count == 32 { return SymmetricKey(data: data) }
        var bytes = Data(count: 32); let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { return nil }
        let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: account, kSecAttrAccount as String: NSUserName(), kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecValueData as String: bytes]
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { return nil }
        return SymmetricKey(data: bytes)
    }
}
