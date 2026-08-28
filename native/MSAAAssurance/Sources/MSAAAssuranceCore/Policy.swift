import Foundation

public struct PolicyProfile: Codable, Sendable {
    public let schemaVersion, profileID, profileVersion: String; public let controls:[ControlDefinition]; public let signature:String?
}
public struct ImportedPolicy: Sendable { public let profile:PolicyProfile; public let verified:Bool; public let label:String }
public protocol PolicySignatureVerifier: Sendable { func verify(profileData:Data,signature:String) -> Bool }
public enum PolicyImporter {
    public static let maximumBytes=1_048_576
    public static func load(_ data:Data,developmentMode:Bool,verifier:PolicySignatureVerifier?=nil) throws -> ImportedPolicy {
        guard data.count<=maximumBytes else { throw AssuranceError.invalidPolicy("profile too large") }
        guard let object=try? JSONSerialization.jsonObject(with:data) as? [String:Any], Set(object.keys).isSubset(of:["schemaVersion","profileID","profileVersion","controls","signature"]) else { throw AssuranceError.invalidPolicy("unknown profile field") }
        let decoder=JSONDecoder(); decoder.dateDecodingStrategy = .custom{ d in let c=try d.singleValueContainer();let s=try c.decode(String.self);guard let date=ISO8601DateFormatter.msaa.date(from:s)else{throw AssuranceError.invalidPolicy("invalid timestamp")};return date }
        let p:PolicyProfile
        do { p=try decoder.decode(PolicyProfile.self,from:data) } catch { throw AssuranceError.invalidPolicy("strict decoding failed") }
        guard p.schemaVersion=="1.0" else { throw AssuranceError.invalidPolicy("unsupported schema") }
        guard Set(p.controls.map{$0.controlID}).count==p.controls.count else { throw AssuranceError.invalidPolicy("duplicate control identifier") }
        guard p.controls.allSatisfy({!$0.requiredDimensions.isEmpty && $0.evidenceFreshnessDuration>0 && $0.evidenceFreshnessDuration<=31_536_000 && !$0.requiredCollectorIDs.isEmpty}) else { throw AssuranceError.invalidPolicy("invalid control requirements") }
        let verified=p.signature.map{verifier?.verify(profileData:data,signature:$0) ?? false} ?? false
        guard verified || developmentMode else { throw AssuranceError.invalidPolicy("unsigned or invalid production profile") }
        return .init(profile:p,verified:verified,label:verified ? "verified":"UNVERIFIED DEVELOPMENT PROFILE")
    }
}
