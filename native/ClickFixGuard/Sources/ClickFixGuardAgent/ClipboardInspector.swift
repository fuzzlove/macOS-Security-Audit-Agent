import AppKit
import Foundation

final class ClipboardInspector {
    static let maximumBytes = 64 * 1024

    func inspect() -> ClipboardSnapshot {
        autoreleasepool {
            let pasteboard = NSPasteboard.general
            let count = pasteboard.changeCount
            if let value = pasteboard.string(forType: .string) {
                let bytes = Data(value.utf8); let clipped = bytes.prefix(Self.maximumBytes)
                return ClipboardSnapshot(accessState: "CLIPBOARD_ACCESS_GRANTED", changeCount: count, contentType: NSPasteboard.PasteboardType.string.rawValue, bytes: Data(clipped), text: String(decoding: clipped, as: UTF8.self), truncated: bytes.count > Self.maximumBytes)
            }
            if let value = pasteboard.string(forType: .URL) {
                let bytes = Data(value.utf8); let clipped = bytes.prefix(Self.maximumBytes)
                return ClipboardSnapshot(accessState: "CLIPBOARD_ACCESS_GRANTED", changeCount: count, contentType: NSPasteboard.PasteboardType.URL.rawValue, bytes: Data(clipped), text: String(decoding: clipped, as: UTF8.self), truncated: bytes.count > Self.maximumBytes)
            }
            for type in [NSPasteboard.PasteboardType.rtf, .rtfd] {
                if let data = pasteboard.data(forType: type), data.count <= Self.maximumBytes,
                   let attributed = try? NSAttributedString(data: data, options: [:], documentAttributes: nil) {
                    let bytes = Data(attributed.string.utf8); let clipped = bytes.prefix(Self.maximumBytes)
                    return ClipboardSnapshot(accessState: "CLIPBOARD_ACCESS_GRANTED", changeCount: count, contentType: type.rawValue, bytes: Data(clipped), text: String(decoding: clipped, as: UTF8.self), truncated: bytes.count > Self.maximumBytes)
                }
            }
            let types = Set(pasteboard.types ?? [])
            let unsupported = !types.isEmpty
            return ClipboardSnapshot(accessState: "CLIPBOARD_ACCESS_GRANTED", changeCount: count, contentType: unsupported ? "UNSUPPORTED_BINARY" : "EMPTY", bytes: nil, text: nil, truncated: false)
        }
    }
}
