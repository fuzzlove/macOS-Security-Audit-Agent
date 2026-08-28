import CryptoKit
import Foundation

final class ClipboardClassifier {
    static let version = "clickfix-static-1.0.0"
    static let maximumInputBytes = 64 * 1024
    static let maximumDecodedBytes = 128 * 1024
    static let maximumDecodedLayers = 2
    static let maximumTokens = 4096

    private let signedBundleValid: Bool
    private static let interpreter = try! NSRegularExpression(pattern: #"(?i)(?:^|[\s;/|&])(sh|bash|zsh|fish|csh|tcsh|osascript|python3?|perl|ruby|php|node|deno|pwsh|powershell|swift|xcrun|make|cmake)(?:\s|$)"#)
    private static let chaining = try! NSRegularExpression(pattern: #"(\|\||&&|[|;]|`|\$\(|<<|>>|[0-9]?>|<\(|>\()"#)
    private static let download = try! NSRegularExpression(pattern: #"(?i)\b(curl|wget|fetch)\b|https?://"#)
    private static let persistence = try! NSRegularExpression(pattern: #"(?i)\b(launchagents?|launchdaemons?|crontab|login item)\b|\blaunchctl\s+(load|bootstrap|enable)\b|\.zshrc|\.bash_profile"#)
    private static let credential = try! NSRegularExpression(pattern: #"(?i)\bsecurity\s+(find|dump|export)|\.ssh/|keychain|cookies?|wallet|aws/credentials|gcloud"#)
    private static let impairment = try! NSRegularExpression(pattern: #"(?i)\b(spctl|csrutil|tccutil|pfctl)\b|xattr\s+[^\n]*-d\s+com\.apple\.quarantine|disable[^\n]*(firewall|logging|update)"#)
    private static let encoding = try! NSRegularExpression(pattern: #"(?i)\b(base64|xxd\s+-r|fromhex|charcode)\b"#)
    private static let simple = try! NSRegularExpression(pattern: #"(?i)^\s*(ls|whoami|id|pwd|uname|date)(?:\s+[^\n;|&]+)?\s*$"#)

    init(ruleBundleURL: URL? = nil, signatureURL: URL? = nil) {
        signedBundleValid = Self.verifyRuleBundle(bundleURL: ruleBundleURL, signatureURL: signatureURL)
    }

    var signatureValid: Bool { signedBundleValid }

    func classify(_ snapshot: ClipboardSnapshot, deadline: DispatchTime = .now() + .milliseconds(100)) -> ClipboardClassification {
        guard let original = snapshot.text else { return result("NOT_TEXT", 1, [], [], false, false, false, nil) }
        var text = original.precomposedStringWithCompatibilityMapping
        if text.utf8.count > Self.maximumInputBytes {
            text = String(decoding: Data(text.utf8.prefix(Self.maximumInputBytes)), as: UTF8.self)
        }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        var categories = Set<String>(); var languages = [String]()
        let interpreter = Self.interpreter.firstMatch(in: text, range: range) != nil
        if interpreter { categories.insert("INTERPRETER") }
        for name in ["sh","bash","zsh","fish","csh","tcsh","osascript","python","python3","perl","ruby","php","node","deno","pwsh","powershell","swift","xcrun","make","cmake"] where text.range(of: "\\b\(name)\\b", options: [.regularExpression, .caseInsensitive]) != nil { languages.append(name) }
        let chaining = Self.chaining.firstMatch(in: text, range: range) != nil
        if chaining { categories.insert("EXECUTION_CHAINING") }
        let downloader = Self.download.firstMatch(in: text, range: range) != nil
        if downloader { categories.insert("DOWNLOAD") }
        let persist = Self.persistence.firstMatch(in: text, range: range) != nil
        if persist { categories.insert("PERSISTENCE") }
        let creds = Self.credential.firstMatch(in: text, range: range) != nil
        if creds { categories.insert("CREDENTIAL_ACCESS") }
        let impair = Self.impairment.firstMatch(in: text, range: range) != nil
        if impair { categories.insert("SECURITY_IMPAIRMENT") }
        let encoded = Self.encoding.firstMatch(in: text, range: range) != nil
        if encoded { categories.insert("ENCODING") }
        let script = text.hasPrefix("#!") || (text.contains("\n") && interpreter)
        if script { categories.insert("SCRIPT_GRAMMAR") }
        let invisible = text.unicodeScalars.contains { scalar in
            (0x202A...0x202E).contains(scalar.value) || (0x2066...0x2069).contains(scalar.value) || [0x200B,0x200C,0x200D,0xFEFF].contains(scalar.value)
        }
        if invisible { categories.insert("INVISIBLE_UNICODE") }
        if downloader && (chaining || interpreter || text.range(of: #"(?i)\bchmod\b"#, options: .regularExpression) != nil) { categories.insert("DOWNLOAD_AND_EXECUTE") }
        let basicCommand = Self.simple.firstMatch(in: text, range: range) != nil
        let command = basicCommand || interpreter || chaining || persist || creds || impair || categories.contains("DOWNLOAD_AND_EXECUTE")
        let classification: String
        if DispatchTime.now() > deadline { classification = "CLASSIFICATION_FAILED" }
        else if impair { classification = "SECURITY_IMPAIRMENT" }
        else if creds { classification = "CREDENTIAL_ACCESS" }
        else if persist { classification = "PERSISTENCE_COMMAND" }
        else if categories.contains("DOWNLOAD_AND_EXECUTE") { classification = "DOWNLOAD_AND_EXECUTE" }
        else if encoded && command { classification = "ENCODED_COMMAND" }
        else if script { classification = "SCRIPT_LIKE" }
        else if command { classification = "COMMAND_LIKE" }
        else if text.range(of: #"\b(function|class|import|let|const|struct)\b|[{}()]"#, options: .regularExpression) != nil { classification = "SOURCE_CODE_FRAGMENT" }
        else { classification = "PLAIN_TEXT" }
        let confidence = command ? min(0.99, 0.55 + Double(categories.count) * 0.07) : 0.9
        return result(classification, confidence, languages, Array(categories).sorted(), command, script, encoded, Self.redact(text), downloader, interpreter, persist, creds, impair)
    }

    private func result(_ classification: String, _ confidence: Double, _ languages: [String], _ categories: [String], _ command: Bool, _ script: Bool, _ encoded: Bool, _ preview: String?, _ downloader: Bool = false, _ interpreter: Bool = false, _ persistence: Bool = false, _ credential: Bool = false, _ impairment: Bool = false) -> ClipboardClassification {
        ClipboardClassification(classification: classification, confidence: confidence, languageCandidates: languages, matchedCategories: categories, commandLike: command, scriptLike: script, encodedContent: encoded, downloaderPresent: downloader, interpreterPresent: interpreter, persistenceIndicators: persistence, credentialAccessIndicators: credential, securityImpairmentIndicators: impairment, externalDestinationIndicators: downloader, redactedPreview: preview, classifierVersion: Self.version)
    }

    private static func redact(_ text: String) -> String {
        let controlsRemoved = text.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : String($0) }.joined()
        let expression = try! NSRegularExpression(pattern: #"(?i)(password|token|secret|authorization)\s*[:=]\s*\S+|\b[A-Za-z0-9+/]{32,}={0,2}\b"#)
        let range = NSRange(controlsRemoved.startIndex..<controlsRemoved.endIndex, in: controlsRemoved)
        let redacted = expression.stringByReplacingMatches(in: controlsRemoved, range: range, withTemplate: "[REDACTED]")
        return String(redacted.prefix(240))
    }

    private static func verifyRuleBundle(bundleURL: URL?, signatureURL: URL?) -> Bool {
        guard let bundleURL, let signatureURL,
              let data = try? Data(contentsOf: bundleURL, options: .mappedIfSafe),
              let signatureText = try? String(contentsOf: signatureURL, encoding: .utf8),
              let signature = Data(base64Encoded: signatureText.trimmingCharacters(in: .whitespacesAndNewlines)),
              data.count <= 1024 * 1024, signature.count == 64,
              let publicData = Data(base64Encoded: "rFv2UFAuEcEudv/6ipTfE92gdqlk+Pik9hqzDbo6HXA=") else { return false }
        return (try? Curve25519.Signing.PublicKey(rawRepresentation: publicData).isValidSignature(signature, for: data)) ?? false
    }
}
