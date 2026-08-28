import AppKit
import Foundation
import Security

struct FrontmostApplicationEvidence {
    let pid: pid_t?
    let bundleID: String?
    let signingIdentifier: String?
    let teamIdentifier: String?
}

enum FrontmostApplicationCollector {
    static func collect() -> FrontmostApplicationEvidence {
        guard let app = NSWorkspace.shared.frontmostApplication else { return .init(pid: nil, bundleID: nil, signingIdentifier: nil, teamIdentifier: nil) }
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: app.processIdentifier)] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
            return .init(pid: app.processIdentifier, bundleID: app.bundleIdentifier, signingIdentifier: nil, teamIdentifier: nil)
        }
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any] else {
            return .init(pid: app.processIdentifier, bundleID: app.bundleIdentifier, signingIdentifier: nil, teamIdentifier: nil)
        }
        return .init(pid: app.processIdentifier, bundleID: app.bundleIdentifier,
                     signingIdentifier: values[kSecCodeInfoIdentifier as String] as? String,
                     teamIdentifier: values[kSecCodeInfoTeamIdentifier as String] as? String)
    }
}
