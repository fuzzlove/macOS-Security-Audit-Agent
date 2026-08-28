import Foundation
import CryptoKit

public enum Canonical {
    public static let zeroDigest = String(repeating: "0", count: 64)
    public static func encoder() -> JSONEncoder {
        let e=JSONEncoder(); e.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]; e.dateEncodingStrategy = .custom { date, encoder in
            var c=encoder.singleValueContainer(); try c.encode(timestamp(date))
        }; return e
    }
    public static func timestamp(_ date: Date) -> String {
        let f=ISO8601DateFormatter(); f.formatOptions=[.withInternetDateTime,.withFractionalSeconds]; return f.string(from: Date(timeIntervalSince1970:(date.timeIntervalSince1970*1000).rounded(.down)/1000))
    }
    public static func data<T: Encodable>(_ value:T) throws -> Data { try encoder().encode(value) }
    public static func sha256(_ data:Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
    public static func recordDigest(_ record: EvidenceObservation) throws -> String { try sha256(data(record.withDigest(""))) }
}
public struct ChainVerification: Codable { public let valid:Bool; public let errors:[String]; public let expiredEvidence, simulatedEvidence:Int }
public enum EvidenceChain {
    public static func append(_ draft: EvidenceObservation, to records:[EvidenceObservation]) throws -> EvidenceObservation {
        let previous=records.last?.recordDigest ?? Canonical.zeroDigest
        guard draft.sequenceNumber == UInt64(records.count+1), draft.previousRecordDigest == previous else { throw AssuranceError.chainIntegrity }
        return draft.withDigest(try Canonical.recordDigest(draft))
    }
    public static func verify(_ records:[EvidenceObservation], now:Date=Date()) -> ChainVerification {
        var errors:[String]=[]; var previous=Canonical.zeroDigest; var seen=Set<UInt64>()
        for (index,r) in records.enumerated() {
            if !seen.insert(r.sequenceNumber).inserted { errors.append("duplicate sequence \(r.sequenceNumber)") }
            if r.sequenceNumber != UInt64(index+1) { errors.append("missing or reordered sequence at \(index+1)") }
            if r.previousRecordDigest != previous { errors.append("previous digest mismatch at \(r.sequenceNumber)") }
            if (try? Canonical.recordDigest(r)) != r.recordDigest { errors.append("record digest mismatch at \(r.sequenceNumber)") }
            previous=r.recordDigest
        }
        return .init(valid:errors.isEmpty,errors:errors,expiredEvidence:records.filter{$0.expiresAt <= now}.count,simulatedEvidence:records.filter{$0.simulationStatus != .production}.count)
    }
}
