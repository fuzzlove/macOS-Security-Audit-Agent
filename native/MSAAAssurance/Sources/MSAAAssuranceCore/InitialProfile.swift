import Foundation

public enum InitialProfile {
    public static func controls(now:Date=Date())->[ControlDefinition] {
        let specs:[(String,String,String,String)]=[
            ("MSAA-MAC-FV-1","FileVault status","macos.filevault","filevault-status"),
            ("MSAA-MAC-SIP-1","System Integrity Protection status","macos.sip","sip-status"),
            ("MSAA-MAC-GK-1","Gatekeeper assessment status","macos.gatekeeper","gatekeeper-status"),
            ("MSAA-LIVE-1","MSAA collector liveness","msaa.liveness","collector-heartbeat"),
            ("MSAA-CHAIN-1","MSAA evidence-chain integrity","msaa.chain","chain-verification"),
            ("MSAA-RECOVERY-1","MSAA test-fixture recovery","msaa.recovery","fixture-recovery")]
        return specs.map { id,title,collector,evidence in .init(schemaVersion:"1.0",controlID:id,title:title,description:"Assures \(title.lowercased()) using fresh local evidence.",controlVersion:"1.0",profileID:"msaa-development",profileVersion:"1.0",severity:"high",requiredDimensions:Dimension.allCases,evidenceFreshnessDuration:3600,requiredCollectorIDs:[collector],validationTestIDs:["synthetic-liveness"],recoveryTestIDs:id.hasSuffix("RECOVERY-1") ? ["fixture-recovery"]:[],sourceMappings:[],expectedEvidenceTypes:[evidence],applicablePlatformConditions:["macOS >= 14"],remediationGuidance:"Review the typed failure and restore the required collector or control.",privacyClassification:"system-metadata",createdAt:now,updatedAt:now) }
    }
}
