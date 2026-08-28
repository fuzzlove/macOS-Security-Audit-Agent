#if canImport(EndpointSecurity)
import EndpointSecurity

public struct ClickFixExecObservation: Sendable {
    public let parentProcess: String
    public let executable: String
    public let observedAtNanoseconds: UInt64
}

public protocol MSAAEndpointMonitoring: Sendable {
    var initialized: Bool { get }
    func start(_ handler: @escaping @Sendable (ClickFixExecObservation) -> Void) throws
    func stop()
}

/// Compile-gated adapter boundary only. A deployment must supply an entitled,
/// appropriately signed implementation and prove successful ES initialization.
public enum EndpointMonitorAvailability {
    public static let requiresEntitlement = true
}
#endif
