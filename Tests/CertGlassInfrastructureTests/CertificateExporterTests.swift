import CertGlassCore
import CertGlassInfrastructure
import Foundation
import Testing

struct CertificateExporterTests {
    private let der = Data((0..<255).map { UInt8($0) })

    @Test func derExportReturnsOriginalBytesUnmodified() async throws {
        let record = CertificateRecord(der: der)
        let exporter = StandardCertificateExporter()
        let output = try await exporter.encode(record, as: .der)
        #expect(output == der)
    }

    @Test func pemExportReopensToIdenticalDER() async throws {
        let record = CertificateRecord(der: der)
        let exporter = StandardCertificateExporter()
        let pem = try await exporter.encode(record, as: .pem)

        let text = String(decoding: pem, as: UTF8.self)
        #expect(text.hasPrefix("-----BEGIN CERTIFICATE-----\n"))
        #expect(text.hasSuffix("\n-----END CERTIFICATE-----\n"))
        #expect(!text.contains("\r"))

        // The base64 body must decode back to the exact original DER.
        let body = text
            .dropFirst("-----BEGIN CERTIFICATE-----\n".count)
            .dropLast("\n-----END CERTIFICATE-----\n".count)
        let base64 = String(body).replacingOccurrences(of: "\n", with: "")
        #expect(Data(base64Encoded: base64) == der)
    }

    @Test func pemLongDERWrapsAt64Columns() async throws {
        var longDER = Data([0x30, 0x82, 0x01, 0x00])
        longDER.append(Data(repeating: 0xAB, count: 256))
        let pem = try await StandardCertificateExporter()
            .encode(CertificateRecord(der: longDER), as: .pem)
        let lines = String(decoding: pem, as: UTF8.self).split(separator: "\n")
        let bodyLines = lines.dropFirst().dropLast()
        #expect(bodyLines.allSatisfy { $0.count <= 64 })
        #expect(Data(base64Encoded: bodyLines.joined()) == longDER)
    }
}
