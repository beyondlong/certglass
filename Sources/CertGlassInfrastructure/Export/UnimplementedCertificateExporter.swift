import CertGlassCore
import Foundation

public struct UnimplementedCertificateExporter: CertificateExporting {
    public init() {}

    public func encode(_ certificate: CertificateRecord, as format: CertificateExportFormat) async throws -> Data {
        // HANDOFF D: DER must be byte-identical; PEM wraps the same original DER.
        throw CertGlassError.notImplemented(feature: "证书导出编码")
    }
}
