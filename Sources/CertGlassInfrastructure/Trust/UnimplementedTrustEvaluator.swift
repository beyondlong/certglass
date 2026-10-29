import CertGlassCore

public struct UnimplementedTrustEvaluator: TrustEvaluating {
    public init() {}

    public func evaluate(_ request: TrustRequest) async throws -> ChainReport {
        // HANDOFF C: configure and confirm offline policies before any Security evaluation.
        throw CertGlassError.notImplemented(feature: "macOS 离线信任评估")
    }
}
