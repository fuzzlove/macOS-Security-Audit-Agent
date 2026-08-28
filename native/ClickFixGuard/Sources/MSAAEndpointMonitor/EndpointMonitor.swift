#if canImport(EndpointSecurity)
import EndpointSecurity
import Foundation

public struct ClickFixExecObservation: Sendable {
    public let parentProcess: String
    public let executable: String
    public let observedAtNanoseconds: UInt64

    public init(parentProcess: String, executable: String, observedAtNanoseconds: UInt64) {
        self.parentProcess = parentProcess
        self.executable = executable
        self.observedAtNanoseconds = observedAtNanoseconds
    }
}

public protocol MSAAEndpointMonitoring: Sendable {
    var initialized: Bool { get }
    func start(_ handler: @escaping @Sendable (ClickFixExecObservation) -> Void) throws
    func stop()
}

/// Compile-gated interface only. It is not operational unless an entitled,
/// signed client initializes successfully in the deployed application.
public enum EndpointMonitorAvailability {
    public static let requiresEntitlement = true
    public static let operationalByDefault = false
}
#else
public enum EndpointMonitorAvailability {
    public static let requiresEntitlement = true
    public static let operationalByDefault = false
}
#endif
