import AppKit
import Foundation
import UserNotifications

final class NativeNotificationController: NSObject, UNUserNotificationCenterDelegate {
    private let center = UNUserNotificationCenter.current()
    override init() {
        super.init(); center.delegate = self
        let open = UNNotificationAction(identifier: "OPEN_INCIDENT", title: "Open Incident Details", options: .foreground)
        let acknowledge = UNNotificationAction(identifier: "ACKNOWLEDGE_INCIDENT", title: "Acknowledge Potential ClickFix Incident", options: .foreground)
        center.setNotificationCategories([UNNotificationCategory(identifier: "MSAA_CLICKFIX_CRITICAL", actions: [open, acknowledge], intentIdentifiers: [])])
    }
    func requestAuthorization(completion: @escaping (Bool) -> Void) {
        center.requestAuthorization(options: [.alert, .badge, .sound]) { granted, _ in completion(granted) }
    }
    func critical(incidentID: String, completion: @escaping (Bool) -> Void) {
        let content = UNMutableNotificationContent()
        content.title = "Potential ClickFix Command Detected"
        content.body = "Potential command or script content was detected on the clipboard when Command + Space was pressed. Do not paste or execute the clipboard. Open MSAA to review the incident."
        content.categoryIdentifier = "MSAA_CLICKFIX_CRITICAL"; content.threadIdentifier = incidentID
        content.userInfo = ["incident_id": incidentID]; content.badge = 1
        center.add(UNNotificationRequest(identifier: incidentID, content: content, trigger: nil)) { error in completion(error == nil) }
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) { completionHandler([.banner, .list, .badge]) }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        defer { completionHandler() }
        guard let incidentID = response.notification.request.content.userInfo["incident_id"] as? String else { return }
        let route = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MacAuditAgent/ClickFixGuard/pending-incident-route.json")
        let payload = try? JSONSerialization.data(withJSONObject: ["incident_id": incidentID, "source": "native_notification"], options: [.sortedKeys])
        if let payload { try? payload.write(to: route, options: [.atomic, .completeFileProtection]) }
        for identifier in ["com.fuzzlove.macos-security-audit-agent", "com.macos-security-audit-agent"] {
            if let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) {
                NSWorkspace.shared.openApplication(at: appURL, configuration: NSWorkspace.OpenConfiguration()); break
            }
        }
    }
}
