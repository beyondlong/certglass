import CertGlassCore
import Foundation

public struct UnimplementedCertificateParser: CertificateParsing {
    public init() {}

    public func parse(der: Data) async throws -> CertificateRecord {
        // HANDOFF B: typed X.509 parsing plus a structural fallback for unsupported algorithms.
        throw CertGlassError.notImplemented(feature: "X.509 证书解析")
    }
}
