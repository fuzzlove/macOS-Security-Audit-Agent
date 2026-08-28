import Foundation

public actor EvidenceStore {
    public static let schemaVersion=1; private let file:URL; private var records:[EvidenceObservation]
    public init(directory:URL) throws {
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]); file=directory.appendingPathComponent("evidence-v1.jsonl")
        if FileManager.default.fileExists(atPath:file.path) { records=try Self.decode(file) } else { records=[] }
        guard EvidenceChain.verify(records).valid else { throw AssuranceError.chainIntegrity }
    }
    public func all()->[EvidenceObservation]{records}
    public func append(_ draft:EvidenceObservation) throws -> EvidenceObservation {
        let record=try EvidenceChain.append(draft,to:records); let next=records+[record]
        let data=try next.map{try Canonical.data($0)+Data([0x0a])}.reduce(into:Data()){$0.append($1)}
        try data.write(to:file,options:[.atomic,.completeFileProtectionUnlessOpen]); records=next; return record
    }
    private static func decode(_ url:URL)throws->[EvidenceObservation] { let decoder=JSONDecoder(); decoder.dateDecodingStrategy = .custom{ d in let c=try d.singleValueContainer(); let s=try c.decode(String.self); guard let v=ISO8601DateFormatter.msaa.date(from:s) else{throw AssuranceError.malformedEvidence}; return v }; return try Data(contentsOf:url).split(separator:0x0a).map{try decoder.decode(EvidenceObservation.self,from:Data($0))} }
}
extension ISO8601DateFormatter { static let msaa:ISO8601DateFormatter = { let f=ISO8601DateFormatter();f.formatOptions=[.withInternetDateTime,.withFractionalSeconds];return f }() }
public enum SafePath { public static func normalizedExport(_ url:URL)->URL? { let u=url.standardizedFileURL; guard u.isFileURL,!u.path.contains("\0"),u.pathComponents.count>1 else{return nil}; return u } }
