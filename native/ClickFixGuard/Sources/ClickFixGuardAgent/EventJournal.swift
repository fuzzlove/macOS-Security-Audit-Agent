import CryptoKit
import Foundation
import ClickFixGuardShared

private struct JournalRecord: Codable {
    let sequence: UInt64
    let recordType: String
    let recordID: String
    let occurredAt: Date
    let payload: Data
    let previousDigest: String
    let digest: String
}

final class EventJournal {
    private let queue = DispatchQueue(label: "com.msaa.clickfix.journal")
    private let url: URL
    private var sequence: UInt64 = 0
    private var head = String(repeating: "0", count: 64)

    init(url: URL) throws {
        self.url = url
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) }
        try recoverHead()
    }

    @discardableResult func append<T: Encodable>(type: String, id: String, occurredAt: Date, payload: T) throws -> String {
        try queue.sync {
            let payloadData = try Self.encoder.encode(payload)
            guard payloadData.count <= ClickFixProtocol.maximumEnvelopeBytes else { throw ClickFixErrorCode.evidencePersistenceFailed }
            let next = sequence + 1
            var material = Data(head.utf8); material.append(Data(type.utf8)); material.append(payloadData)
            let digest = SHA256.hash(data: material).map { String(format: "%02x", $0) }.joined()
            let record = JournalRecord(sequence: next, recordType: type, recordID: id, occurredAt: occurredAt, payload: payloadData, previousDigest: head, digest: digest)
            var line = try Self.encoder.encode(record); line.append(0x0a)
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd(); try handle.write(contentsOf: line); try handle.synchronize()
            sequence = next; head = digest
            return digest
        }
    }

    func records(after sequenceNumber: UInt64, limit: Int = 256) -> [Data] {
        queue.sync {
            guard let data = try? Data(contentsOf: url), data.count <= 32 * 1024 * 1024 else { return [] }
            return data.split(separator: 0x0a).compactMap { line -> (UInt64, Data)? in
                guard let record = try? Self.decoder.decode(JournalRecord.self, from: Data(line)), record.sequence > sequenceNumber else { return nil }
                return (record.sequence, Data(line))
            }.sorted { $0.0 < $1.0 }.prefix(max(1, min(limit, 256))).map(\.1)
        }
    }

    func verify() -> Bool {
        queue.sync { (try? Self.verifyFile(url)) != nil }
    }

    private func recoverHead() throws {
        let recovered = try Self.verifyFile(url); sequence = recovered.0; head = recovered.1
    }

    private static func verifyFile(_ url: URL) throws -> (UInt64, String) {
        let data = try Data(contentsOf: url); var expectedSequence: UInt64 = 0; var previous = String(repeating: "0", count: 64)
        for line in data.split(separator: 0x0a) {
            let record = try decoder.decode(JournalRecord.self, from: Data(line))
            guard record.sequence == expectedSequence + 1, record.previousDigest == previous else { throw ClickFixErrorCode.evidencePersistenceFailed }
            var material = Data(previous.utf8); material.append(Data(record.recordType.utf8)); material.append(record.payload)
            let digest = SHA256.hash(data: material).map { String(format: "%02x", $0) }.joined()
            guard digest == record.digest else { throw ClickFixErrorCode.evidencePersistenceFailed }
            expectedSequence = record.sequence; previous = digest
        }
        return (expectedSequence, previous)
    }

    private static let encoder: JSONEncoder = { let value = JSONEncoder(); value.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; value.dateEncodingStrategy = .iso8601; return value }()
    private static let decoder: JSONDecoder = { let value = JSONDecoder(); value.dateDecodingStrategy = .iso8601; return value }()
}

extension ClickFixErrorCode: Error {}
