import Foundation
import MSAAAssuranceCore

@main enum VerifyCommand {
    static func main() {
        let args=CommandLine.arguments.dropFirst();let json=args.contains("--json")
        guard let path=args.first(where:{$0 != "--json"}) else{FileHandle.standardError.write(Data("usage: msaa-verify <bundle> [--json]\n".utf8));exit(2)}
        do { let r=try EvidenceBundle.verify(URL(fileURLWithPath:path));if json,let encoded=try? Canonical.encoder().encode(r),let text=String(data:encoded,encoding:.utf8) { print(text) } else { print("VALID: evidence chain and signed manifest verified; expired=\(r.expiredEvidence), simulated=\(r.simulatedEvidence)") };exit(0) } catch { if json { print("{\"valid\":false,\"error\":\"integrity verification failed\"}") } else { FileHandle.standardError.write(Data("INVALID: integrity verification failed\n".utf8)) };exit(1) }
    }
}
