import CoreGraphics
import Foundation
import os.lock
import ClickFixGuardShared

enum ShortcutMatcher {
    static func matches(keyCode: Int64, flags: CGEventFlags, sourceStateID: Int64, marker: Int64, replayMarker: Int64) -> Bool {
        keyCode == 49 && flags.contains(.maskCommand) && marker != replayMarker && sourceStateID == Int64(CGEventSourceStateID.hidSystemState.rawValue)
    }
}

final class BoundedShortcutQueue {
    private var lock = os_unfair_lock_s()
    private var records = Array<ShortcutRecord?>(repeating: nil, count: 256)
    private var readIndex = 0; private var writeIndex = 0; private(set) var drops: UInt64 = 0
    let available = DispatchSemaphore(value: 0)

    func enqueue(_ record: ShortcutRecord) {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        let next = (writeIndex + 1) % records.count
        guard next != readIndex else { drops += 1; return }
        records[writeIndex] = record; writeIndex = next; available.signal()
    }
    func dequeue() -> ShortcutRecord? {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        guard readIndex != writeIndex else { return nil }
        let record = records[readIndex]; records[readIndex] = nil; readIndex = (readIndex + 1) % records.count
        return record
    }
}

final class ClickFixEventTap {
    private let mode: GuardMode
    private let replayMarker: Int64
    private let queue: BoundedShortcutQueue
    private let health: (ClickFixErrorCode) -> Void
    private var tap: CFMachPort?
    private var attempts = 0

    init(mode: GuardMode, replayMarker: Int64, queue: BoundedShortcutQueue, health: @escaping (ClickFixErrorCode) -> Void) {
        self.mode = mode; self.replayMarker = replayMarker; self.queue = queue; self.health = health
    }
    func start() -> Bool {
        let mask = CGEventMask(1 << CGEventType.keyDown.rawValue)
        let options: CGEventTapOptions = mode == .observe ? .listenOnly : .defaultTap
        let refcon = Unmanaged.passUnretained(self).toOpaque()
        guard let created = CGEvent.tapCreate(tap: .cgSessionEventTap, place: .headInsertEventTap, options: options, eventsOfInterest: mask, callback: Self.callback, userInfo: refcon) else { return false }
        tap = created
        let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, created, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes); CGEvent.tapEnable(tap: created, enable: true)
        return true
    }
    private func handle(type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
            health(type == .tapDisabledByTimeout ? .eventTapTimeout : .eventTapDisabled)
            if attempts < 3, let tap { attempts += 1; CGEvent.tapEnable(tap: tap, enable: true) }
            return Unmanaged.passUnretained(event)
        }
        guard type == .keyDown else { return Unmanaged.passUnretained(event) }
        let marker = event.getIntegerValueField(.eventSourceUserData)
        let stateID = event.getIntegerValueField(.eventSourceStateID)
        guard ShortcutMatcher.matches(keyCode: event.getIntegerValueField(.keyboardEventKeycode), flags: event.flags, sourceStateID: stateID, marker: marker, replayMarker: replayMarker) else { return Unmanaged.passUnretained(event) }
        queue.enqueue(ShortcutRecord(timestampNS: DispatchTime.now().uptimeNanoseconds, keyCode: 49, flags: event.flags.rawValue, physical: true))
        return mode == .protect ? nil : Unmanaged.passUnretained(event)
    }
    private static let callback: CGEventTapCallBack = { _, type, event, refcon in
        guard let refcon else { return Unmanaged.passUnretained(event) }
        return Unmanaged<ClickFixEventTap>.fromOpaque(refcon).takeUnretainedValue().handle(type: type, event: event)
    }
}
