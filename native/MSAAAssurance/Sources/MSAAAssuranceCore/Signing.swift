import Foundation
import CryptoKit

public struct SignatureMetadata: Codable, Sendable { public let signerType,algorithm,publicKey,signature:String; public let hardwareBacked:Bool }
public protocol EvidenceSigner: Sendable { var signerType:String {get}; var hardwareBacked:Bool {get}; func sign(_ data:Data) throws -> SignatureMetadata }
public struct InMemoryTestSigner: EvidenceSigner {
    private let key:Curve25519.Signing.PrivateKey; public let signerType="in-memory-test"; public let hardwareBacked=false
    public init(seed:Data=Data(repeating:7,count:32)) throws { key=try .init(rawRepresentation:seed) }
    public func sign(_ data:Data) throws -> SignatureMetadata { .init(signerType:signerType,algorithm:"Ed25519",publicKey:key.publicKey.rawRepresentation.base64EncodedString(),signature:try key.signature(for:data).base64EncodedString(),hardwareBacked:false) }
}
public enum SignatureVerifier { public static func verify(_ data:Data,metadata:SignatureMetadata)->Bool { guard metadata.algorithm=="Ed25519",let pub=Data(base64Encoded:metadata.publicKey),let sig=Data(base64Encoded:metadata.signature),let key=try? Curve25519.Signing.PublicKey(rawRepresentation:pub) else{return false}; return key.isValidSignature(sig,for:data) } }
