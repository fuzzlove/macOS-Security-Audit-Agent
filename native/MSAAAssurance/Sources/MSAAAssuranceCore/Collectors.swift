import Foundation

public struct CollectorOutput: Sendable { public let result:DimensionState; public let reason:ReasonCode; public let summary:String; public let metadata:[String:String] }
public protocol Collector: Sendable { var collectorID:String {get}; var version:String {get}; func collect() async -> (CollectorOutput,CollectorHealth) }
public protocol FixedCommandRunning: Sendable { func run(executable:URL,arguments:[String],timeout:TimeInterval,maximumOutputBytes:Int) async throws -> Data }
public struct ProcessRunner: FixedCommandRunning {
    public init() {}
    public func run(executable:URL,arguments:[String],timeout:TimeInterval,maximumOutputBytes:Int) async throws -> Data {
        guard executable.path.hasPrefix("/usr/") else { throw AssuranceError.commandFailed(.permissionDenied) }
        return try await withThrowingTaskGroup(of:Data.self) { group in
            group.addTask { let p=Process(); p.executableURL=executable; p.arguments=arguments; let pipe=Pipe(); p.standardOutput=pipe; p.standardError=Pipe(); try p.run(); p.waitUntilExit(); let d=pipe.fileHandleForReading.readDataToEndOfFile(); guard d.count<=maximumOutputBytes else { throw AssuranceError.commandFailed(.parserFailure) }; guard p.terminationStatus==0 else { throw AssuranceError.commandFailed(.requirementNotSatisfied) }; return d }
            group.addTask { try await Task.sleep(for:.seconds(timeout)); throw AssuranceError.commandFailed(.commandTimeout) }
            defer { group.cancelAll() }; return try await group.next()!
        }
    }
}
public struct FixedStatusCollector: Collector {
    public let collectorID,version:String; let executable:URL; let arguments:[String]; let parser:@Sendable(Data)->CollectorOutput; let runner:FixedCommandRunning
    public init(collectorID:String,version:String="1.0",executable:URL,arguments:[String],runner:FixedCommandRunning=ProcessRunner(),parser:@escaping @Sendable(Data)->CollectorOutput) { self.collectorID=collectorID;self.version=version;self.executable=executable;self.arguments=arguments;self.runner=runner;self.parser=parser }
    public func collect() async -> (CollectorOutput,CollectorHealth) {
        let now=Date()
        do { let data=try await runner.run(executable:executable,arguments:arguments,timeout:5,maximumOutputBytes:16_384); let out=parser(data); return (out,.init(collectorID:collectorID,version:version,capabilities:["read-only status"],lastStartedAt:now,lastSuccessfulObservationAt:now,lastHeartbeatAt:now,currentState:.healthy,errorReasonCode:nil,droppedEventCount:0,sequenceGapCount:0,permissionState:"notRequired",simulationStatus:.production)) }
        catch let AssuranceError.commandFailed(reason) { let state:CollectorState = reason == .permissionDenied ? .unauthorized:.degraded; return (.init(result:.degraded,reason:reason,summary:"Collector could not produce valid evidence.",metadata:[:]),.init(collectorID:collectorID,version:version,capabilities:["read-only status"],lastStartedAt:now,lastSuccessfulObservationAt:nil,lastHeartbeatAt:now,currentState:state,errorReasonCode:reason,droppedEventCount:0,sequenceGapCount:0,permissionState:state == .unauthorized ? "denied":"notRequired",simulationStatus:.production)) }
        catch { return (.init(result:.unknown,reason:.collectorUnavailable,summary:"Collector unavailable.",metadata:[:]),.init(collectorID:collectorID,version:version,capabilities:[],lastStartedAt:now,lastSuccessfulObservationAt:nil,lastHeartbeatAt:now,currentState:.unavailable,errorReasonCode:.collectorUnavailable,droppedEventCount:0,sequenceGapCount:0,permissionState:"unknown",simulationStatus:.production)) }
    }
    public static func redact(_ data:Data) -> String { String(decoding:data.prefix(512),as:UTF8.self).unicodeScalars.filter{CharacterSet.alphanumerics.union(.whitespaces).union(CharacterSet(charactersIn:"._-:")).contains($0)}.map(String.init).joined() }
}
public protocol EndpointSecurityCollecting: Collector { var productionEntitlementAvailable:Bool {get} }
public struct SyntheticEventCollector: EndpointSecurityCollecting {
    public let collectorID="msaa.synthetic.endpoint"; public let version="1.0"; public let productionEntitlementAvailable=false
    public init() {}
    public func collect() async -> (CollectorOutput,CollectorHealth) { let now=Date(); return (.init(result:.pass,reason:.simulatedEvidence,summary:"Benign synthetic liveness event observed.",metadata:["event":"synthetic-liveness"]),.init(collectorID:collectorID,version:version,capabilities:["synthetic liveness"],lastStartedAt:now,lastSuccessfulObservationAt:now,lastHeartbeatAt:now,currentState:.healthy,errorReasonCode:nil,droppedEventCount:0,sequenceGapCount:0,permissionState:"notApplicable",simulationStatus:.simulated)) }
}

public enum MacOSCollectors {
    public static func fileVault(runner:FixedCommandRunning=ProcessRunner())->FixedStatusCollector { .init(collectorID:"macos.filevault",executable:URL(fileURLWithPath:"/usr/bin/fdesetup"),arguments:["status"],runner:runner){data in let s=FixedStatusCollector.redact(data);let enabled=s.localizedCaseInsensitiveContains("FileVault is On");return .init(result:enabled ? .pass:.fail,reason:enabled ? .requirementSatisfied:.requirementNotSatisfied,summary:enabled ? "FileVault reports enabled.":"FileVault does not report enabled.",metadata:["enabled":String(enabled)]) } }
    public static func systemIntegrityProtection(runner:FixedCommandRunning=ProcessRunner())->FixedStatusCollector { .init(collectorID:"macos.sip",executable:URL(fileURLWithPath:"/usr/bin/csrutil"),arguments:["status"],runner:runner){data in let s=FixedStatusCollector.redact(data);let enabled=s.localizedCaseInsensitiveContains("enabled");return .init(result:enabled ? .pass:.fail,reason:enabled ? .requirementSatisfied:.requirementNotSatisfied,summary:enabled ? "System Integrity Protection reports enabled.":"System Integrity Protection does not report enabled.",metadata:["enabled":String(enabled)]) } }
    public static func gatekeeper(runner:FixedCommandRunning=ProcessRunner())->FixedStatusCollector { .init(collectorID:"macos.gatekeeper",executable:URL(fileURLWithPath:"/usr/sbin/spctl"),arguments:["--status"],runner:runner){data in let s=FixedStatusCollector.redact(data);let enabled=s.localizedCaseInsensitiveContains("assessments enabled");return .init(result:enabled ? .pass:.fail,reason:enabled ? .requirementSatisfied:.requirementNotSatisfied,summary:enabled ? "Gatekeeper assessments report enabled.":"Gatekeeper assessments do not report enabled.",metadata:["enabled":String(enabled)]) } }
}
