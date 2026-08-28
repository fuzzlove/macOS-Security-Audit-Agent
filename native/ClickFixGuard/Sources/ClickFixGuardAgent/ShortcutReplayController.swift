import CoreGraphics
import Foundation

final class ShortcutReplayController {
    let marker: Int64
    init() { marker = Int64.random(in: 1...Int64.max) }

    func replay(flags: CGEventFlags) -> Bool {
        guard let source = CGEventSource(stateID: .privateState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: 49, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: 49, keyDown: false) else { return false }
        down.flags = flags; up.flags = flags
        down.setIntegerValueField(.eventSourceUserData, value: marker)
        up.setIntegerValueField(.eventSourceUserData, value: marker)
        down.post(tap: .cgSessionEventTap); up.post(tap: .cgSessionEventTap)
        return true
    }
}
