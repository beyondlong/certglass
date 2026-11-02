import CertGlassCore
import Foundation

public struct StandardCertificateExporter: CertificateExporting {
    public init() {}

    public func encode(_ certificate: CertificateRecord, as format: CertificateExportFormat) async throws -> Data {
        switch format {
        case .der: return certificate.der
        case .pem: return Self.pem(certificate.der)
        }
    }

    /// PEM wraps the exact original DER; bytes round-trip byte-identically.
    static func pem(_ der: Data) -> Data {
        let base64 = der.base64EncodedString()
        let lines = stride(from: 0, to: base64.count, by: 64).map { start -> String in
            let end = min(start + 64, base64.count)
            let startIdx = base64.index(base64.startIndex, offsetBy: start)
            let endIdx = base64.index(base64.startIndex, offsetBy: end)
            return String(base64[startIdx..<endIdx])
        }
        return Data((
            "-----BEGIN CERTIFICATE-----\n" + lines.joined(separator: "\n") + "\n-----END CERTIFICATE-----\n"
        ).utf8)
    }
}
