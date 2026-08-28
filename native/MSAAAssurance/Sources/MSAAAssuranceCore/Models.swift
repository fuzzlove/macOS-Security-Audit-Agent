import Foundation

public enum Dimension: String, Codable, CaseIterable, Sendable { case configuration, operation, observability, validation, recovery }
public enum DimensionState: String, Codable, Sendable { case unknown, pass, fail, degraded, stale, notApplicable }
public enum OverallState: String, Codable, Sendable { case pass, fail, degraded, stale, unknown, excepted, notApplicable }
public enum SimulationStatus: String, Codable, Sendable { case production, development, simulated }
public enum ReasonCode: String, Codable, Sendable {
    case requirementSatisfied, requirementNotSatisfied, collectorUnavailable, collectorHeartbeatExpired
    case evidenceExpired, evidenceMissing, parserFailure, commandTimeout, permissionDenied, unsupportedPlatform
    case validationPassed, validationFailed, validationNotExecuted, recoveryPassed, recoveryFailed
    case exceptionActive, exceptionExpired, evidenceIntegrityFailure, profileSignatureInvalid, simulatedEvidence
}
public enum CollectorState: String, Codable, Sendable { case healthy, degraded, unavailable, unauthorized, unsupported, stopped, unknown }

public struct SourceMapping: Codable, Hashable, Sendable {
    public let frameworkName, frameworkVersion, requirementID, mappingType, mappingNotes: String
    public init(frameworkName: String, frameworkVersion: String, requirementID: String, mappingType: String, mappingNotes: String) {
        self.frameworkName=frameworkName; self.frameworkVersion=frameworkVersion; self.requirementID=requirementID; self.mappingType=mappingType; self.mappingNotes=mappingNotes
    }
}
public struct ControlDefinition: Codable, Identifiable, Sendable {
    public var id: String { controlID }
    public let schemaVersion, controlID, title, description, controlVersion, profileID, profileVersion, severity: String
    public let requiredDimensions: [Dimension]; public let evidenceFreshnessDuration: TimeInterval
    public let requiredCollectorIDs, validationTestIDs, recoveryTestIDs: [String]
    public let sourceMappings: [SourceMapping]; public let expectedEvidenceTypes, applicablePlatformConditions: [String]
    public let remediationGuidance, privacyClassification: String; public let createdAt, updatedAt: Date
}
public struct EvidenceObservation: Codable, Identifiable, Sendable {
    public var id: String { evidenceID }
    public let schemaVersion, evidenceID: String; public let sequenceNumber: UInt64; public let controlID: String
    public let dimension: Dimension; public let evidenceType, sourceCollectorID, sourceCollectorVersion: String
    public let observedAt, recordedAt, expiresAt: Date; public let result: DimensionState; public let reasonCode: ReasonCode
    public let humanReadableSummary: String; public let normalizedMetadata: [String:String]
    public let rawEvidenceDigest, previousRecordDigest, recordDigest, policyVersion, applicationVersion, hostIdentifier: String
    public let simulationStatus: SimulationStatus; public let privacyClassification: String
    public init(schemaVersion: String="1.0", evidenceID: String, sequenceNumber: UInt64, controlID: String, dimension: Dimension, evidenceType: String, sourceCollectorID: String, sourceCollectorVersion: String, observedAt: Date, recordedAt: Date, expiresAt: Date, result: DimensionState, reasonCode: ReasonCode, humanReadableSummary: String, normalizedMetadata: [String:String]=[:], rawEvidenceDigest: String, previousRecordDigest: String, recordDigest: String="", policyVersion: String, applicationVersion: String, hostIdentifier: String, simulationStatus: SimulationStatus, privacyClassification: String) {
        self.schemaVersion=schemaVersion; self.evidenceID=evidenceID; self.sequenceNumber=sequenceNumber; self.controlID=controlID; self.dimension=dimension; self.evidenceType=evidenceType; self.sourceCollectorID=sourceCollectorID; self.sourceCollectorVersion=sourceCollectorVersion; self.observedAt=observedAt; self.recordedAt=recordedAt; self.expiresAt=expiresAt; self.result=result; self.reasonCode=reasonCode; self.humanReadableSummary=humanReadableSummary; self.normalizedMetadata=normalizedMetadata; self.rawEvidenceDigest=rawEvidenceDigest; self.previousRecordDigest=previousRecordDigest; self.recordDigest=recordDigest; self.policyVersion=policyVersion; self.applicationVersion=applicationVersion; self.hostIdentifier=hostIdentifier; self.simulationStatus=simulationStatus; self.privacyClassification=privacyClassification
    }
    public func withDigest(_ digest: String) -> Self { .init(schemaVersion:schemaVersion,evidenceID:evidenceID,sequenceNumber:sequenceNumber,controlID:controlID,dimension:dimension,evidenceType:evidenceType,sourceCollectorID:sourceCollectorID,sourceCollectorVersion:sourceCollectorVersion,observedAt:observedAt,recordedAt:recordedAt,expiresAt:expiresAt,result:result,reasonCode:reasonCode,humanReadableSummary:humanReadableSummary,normalizedMetadata:normalizedMetadata,rawEvidenceDigest:rawEvidenceDigest,previousRecordDigest:previousRecordDigest,recordDigest:digest,policyVersion:policyVersion,applicationVersion:applicationVersion,hostIdentifier:hostIdentifier,simulationStatus:simulationStatus,privacyClassification:privacyClassification) }
}
public struct CollectorHealth: Codable, Identifiable, Sendable {
    public var id: String { collectorID }; public let collectorID, version: String; public let capabilities: [String]
    public let lastStartedAt, lastSuccessfulObservationAt, lastHeartbeatAt: Date?; public let currentState: CollectorState
    public let errorReasonCode: ReasonCode?; public let droppedEventCount, sequenceGapCount: UInt64
    public let permissionState: String; public let simulationStatus: SimulationStatus
}
public struct ControlException: Codable, Identifiable, Sendable {
    public var id: String { exceptionID }; public let exceptionID, controlID, rationale, approvingAuthority: String
    public let createdAt, effectiveAt, expiresAt: Date; public let compensatingControlDescription, ticketReference, status: String; public let evidenceReferences: [String]
    public init(exceptionID:String,controlID:String,rationale:String,approvingAuthority:String,createdAt:Date,effectiveAt:Date,expiresAt:Date,compensatingControlDescription:String,ticketReference:String,status:String,evidenceReferences:[String]) throws {
        guard !rationale.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty, expiresAt > effectiveAt else { throw AssuranceError.invalidException }
        self.exceptionID=exceptionID; self.controlID=controlID; self.rationale=rationale; self.approvingAuthority=approvingAuthority; self.createdAt=createdAt; self.effectiveAt=effectiveAt; self.expiresAt=expiresAt; self.compensatingControlDescription=compensatingControlDescription; self.ticketReference=ticketReference; self.status=status; self.evidenceReferences=evidenceReferences
    }
}
public struct EvaluationResult: Codable, Sendable {
    public let controlID: String; public let overallState: OverallState; public let dimensionStates: [Dimension:DimensionState]
    public let reasonCodes, evidenceReferences, collectorDependencies: [String]; public let evidenceAge: TimeInterval?; public let nextExpiration: Date?
    public let exceptionStatus, policyVersion, evaluatorVersion: String
}
public enum AssuranceError: Error { case malformedEvidence, chainIntegrity, invalidException, invalidPolicy(String), commandFailed(ReasonCode), unsafePath }
