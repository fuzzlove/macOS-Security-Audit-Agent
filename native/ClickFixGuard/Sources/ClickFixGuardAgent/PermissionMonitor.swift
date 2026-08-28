import ApplicationServices
import CoreGraphics

struct PermissionState: Codable {
    let inputMonitoring: String
    let accessibility: String
    let clipboard: String
}

enum PermissionMonitor {
    static func current() -> PermissionState {
        PermissionState(inputMonitoring: CGPreflightListenEventAccess() ? "INPUT_MONITORING_GRANTED" : "INPUT_MONITORING_DENIED",
                        accessibility: AXIsProcessTrusted() ? "ACCESSIBILITY_GRANTED" : "ACCESSIBILITY_DENIED",
                        clipboard: "CLIPBOARD_ACCESS_UNKNOWN")
    }
    static func requestInputMonitoring() { _ = CGRequestListenEventAccess() }
    static func requestAccessibility() { _ = AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary) }
}
