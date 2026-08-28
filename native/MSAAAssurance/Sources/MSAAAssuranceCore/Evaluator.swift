import Foundation

public enum Evaluator {
    public static let version="1.0"
    public static func evaluate(_ control:ControlDefinition,evidence:[EvidenceObservation],collectors:[CollectorHealth],exception:ControlException?=nil,now:Date=Date()) -> EvaluationResult {
        let relevant=evidence.filter{$0.controlID==control.controlID}; var states:[Dimension:DimensionState]=[:]; var reasons:[String]=[]
        let unhealthy=control.requiredCollectorIDs.compactMap { id in collectors.first{$0.collectorID==id} }.filter { h in h.currentState != .healthy || h.lastHeartbeatAt == nil || now.timeIntervalSince(h.lastHeartbeatAt!) > control.evidenceFreshnessDuration }
        for d in control.requiredDimensions {
            let candidates=relevant.filter{$0.dimension==d}.sorted{$0.observedAt>$1.observedAt}
            guard let latest=candidates.first else { states[d]=unhealthy.isEmpty ? .unknown:.degraded; reasons.append(ReasonCode.evidenceMissing.rawValue); continue }
            if latest.expiresAt <= now || now.timeIntervalSince(latest.observedAt)>control.evidenceFreshnessDuration { states[d] = .stale; reasons.append(ReasonCode.evidenceExpired.rawValue) }
            else if latest.simulationStatus != .production { states[d] = .degraded; reasons.append(ReasonCode.simulatedEvidence.rawValue) }
            else if !unhealthy.isEmpty { states[d] = .degraded; reasons.append(ReasonCode.collectorHeartbeatExpired.rawValue) }
            else { states[d] = latest.result; reasons.append(latest.reasonCode.rawValue) }
        }
        let values=Array(states.values); let activeException = exception.map{$0.effectiveAt<=now && $0.expiresAt>now && $0.status=="active"} ?? false
        let overall:OverallState = activeException ? .excepted : values.contains(.fail) ? .fail : values.contains(.stale) ? .stale : values.contains(.degraded) ? .degraded : values.contains(.unknown) ? .unknown : (!values.isEmpty && values.allSatisfy{$0 == .notApplicable}) ? .notApplicable : values.count==control.requiredDimensions.count && values.allSatisfy{$0 == .pass} ? .pass : .unknown
        return .init(controlID:control.controlID,overallState:overall,dimensionStates:states,reasonCodes:Array(Set(reasons)).sorted(),evidenceReferences:relevant.map{$0.evidenceID},collectorDependencies:control.requiredCollectorIDs,evidenceAge:relevant.map{now.timeIntervalSince($0.observedAt)}.min(),nextExpiration:relevant.map{$0.expiresAt}.min(),exceptionStatus:activeException ? "active":"none",policyVersion:control.profileVersion,evaluatorVersion:version)
    }
}
