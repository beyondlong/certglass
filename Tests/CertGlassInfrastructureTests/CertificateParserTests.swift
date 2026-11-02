import CertGlassCore
import CertGlassInfrastructure
import CryptoKit
import Foundation
import Testing

struct CertificateParserTests {
    private let parser = StandardCertificateParser()

    @Test func rsaLeafParsesCompletelyWithIdentity() async throws {
        let der = try fixture("leaf.cer")
        let record = try await parser.parse(der: der)
        #expect(record.der == der)
        #expect(record.id.sha256 == CertificateID(der: der).sha256)
        #expect(record.parseStatus == .complete)
        #expect(record.subject?.displayValue.contains("CertGlass Test Leaf") == true)
        #expect(record.issuer?.displayValue.contains("CertGlass Test Root") == true)
        #expect(record.publicKeyAlgorithm?.oid == "1.2.840.113549.1.1.1")
        #expect(record.signatureAlgorithm?.oid == "1.2.840.113549.1.1.11")
        #expect(record.publicKeyBytes?.count == 270)
        #expect(record.notValidBefore != nil)
        #expect(record.notValidAfter != nil)
        // notValidAfter is about 3650 days after notValidBefore.
        let span = try #require(record.notValidAfter?.timeIntervalSince(record.notValidBefore ?? Date()))
        #expect(abs(span - 3650 * 86_400) < 86_400)
    }

    @Test func caCertificateIsRecognized() async throws {
        let record = try await parser.parse(der: try fixture("ca.cer"))
        #expect(record.caStatus == .certificateAuthority)
        #expect(record.subject?.displayValue == record.issuer?.displayValue)
    }

    @Test func validityFieldsUseReadableUTCDateTime() async throws {
        let record = try await parser.parse(der: try fixture("cg-sm2.cer"))
        let before = try #require(record.fields.first { $0.id == "notValidBefore" })
        let after = try #require(record.fields.first { $0.id == "notValidAfter" })
        #expect(before.displayValue == CertificateDateFormatting.string(from: try #require(record.notValidBefore)))
        #expect(after.displayValue == CertificateDateFormatting.string(from: try #require(record.notValidAfter)))
        #expect(before.displayValue.range(of: #"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"#, options: .regularExpression) != nil)
        #expect(after.displayValue.range(of: #"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"#, options: .regularExpression) != nil)
        #expect(!before.displayValue.contains("T"))
        #expect(!after.displayValue.hasSuffix("Z"))
    }

    @Test func leafCertificateIsRecognizedAsEndEntity() async throws {
        let record = try await parser.parse(der: try fixture("leaf.cer"))
        #expect(record.caStatus == .endEntity)
        #expect(record.subject?.displayValue != record.issuer?.displayValue)
    }

    @Test func standardExtensionsAreExposedWithRawValues() async throws {
        let record = try await parser.parse(der: try fixture("leaf.cer"))
        let oids = record.extensions.map(\.oid)
        #expect(oids.contains("2.5.29.19"))
        #expect(oids.contains("2.5.29.15"))
        #expect(oids.contains("2.5.29.37"))
        #expect(oids.contains("2.5.29.17"))
        let basicConstraints = try #require(record.extensions.first { $0.oid == "2.5.29.19" })
        #expect(basicConstraints.rawValue.isEmpty == false)
        let fields = record.fields.filter { $0.oid != nil }
        #expect(fields.count >= record.extensions.count)
    }

    @Test func serialNumberMatchesDERIntegerContent() async throws {
        let der = try fixture("leaf.cer")
        let record = try await parser.parse(der: der)
        let serial = try #require(record.serialNumber)
        #expect(serial.isEmpty == false)
        // DER INTEGER content: leading byte of a positive serial is < 0x80.
        #expect(serial.first ?? 0 < 0x80)
    }

    @Test func ed25519ParsesCompletely() async throws {
        let record = try await parser.parse(der: try fixture("cg-ed.cer"))
        #expect(record.parseStatus == .complete)
        #expect(record.publicKeyAlgorithm?.oid == "1.3.101.112")
    }

    @Test func rsaPSSSignatureAlgorithmIsPreserved() async throws {
        let record = try await parser.parse(der: try fixture("cg-pss.cer"))
        // RSA-PSS: both SPKI and signature algorithm carry the PSS OID with parameters.
        #expect(record.signatureAlgorithm?.oid == "1.2.840.113549.1.1.10")
        #expect(record.publicKeyAlgorithm?.oid == "1.2.840.113549.1.1.10")
        #expect(record.publicKeyAlgorithm?.parametersDER != nil)
        // Actual support is recorded either way; the record must not claim failure.
        #expect(record.parseStatus == .complete || record.parseStatus == .partial)
    }

    @Test func postQuantumSignatureOIDsUseCanonicalDisplayNames() async throws {
        let algorithms: [(oid: String, displayName: String)] = [
            ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
            ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
            ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
            ("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"),
            ("2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f"),
            ("2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s"),
            ("2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f"),
            ("2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s"),
            ("2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f"),
            ("2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s"),
            ("2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f"),
            ("2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s"),
            ("2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f"),
            ("2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s"),
            ("2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"),
            ("1.3.9999.3.11", "Falcon-512"),
            ("1.3.9999.3.14", "Falcon-1024")
        ]

        for algorithm in algorithms {
            let der = Self.syntheticCertificate(publicKeyAlgorithmOID: Self.oidContent(algorithm.oid))
            let record = try await parser.parse(der: der)
            let publicKeyField = try #require(record.fields.first { $0.id == "publicKeyAlgorithm" })
            #expect(publicKeyField.oid == algorithm.oid)
            #expect(publicKeyField.displayValue == algorithm.displayName)
            // Post-quantum keys show raw byte length; the synthetic SPKI key is 2 bytes.
            let publicKeyDescription = try #require(record.fields.first { $0.id == "publicKey" })
            #expect(publicKeyDescription.displayValue == "\(algorithm.displayName) (2 字节)")
        }
    }

    @Test func headerlessMLDSA44PKCS7FixtureDisplaysAlgorithmNames() async throws {
        let input = try DocumentInput(data: fixture("HardSecondMLDSA44.p7b"))
        let container = try await StandardContainerDecoder().decode(input)
        #expect(container.format == .base64PKCS7)
        #expect(container.certificatesDER.count == 2)

        let record = try await parser.parse(der: try #require(container.certificatesDER.first))
        #expect(record.signatureAlgorithm?.oid == "2.16.840.1.101.3.4.3.17")
        #expect(record.publicKeyAlgorithm?.oid == "2.16.840.1.101.3.4.3.17")
        #expect(record.fields.first { $0.id == "signatureAlgorithm" }?.displayValue == "ML-DSA-44")
        #expect(record.fields.first { $0.id == "publicKeyAlgorithm" }?.displayValue == "ML-DSA-44")
            #expect(record.fields.first { $0.id == "publicKey" }?.displayValue == "ML-DSA-44 (1312 字节)")
    }

    @Test func sm2DegradesToPartialWithoutLosingFields() async throws {
        let der = try fixture("cg-sm2.cer")
        let record = try await parser.parse(der: der)
        #expect(record.parseStatus == .partial)
        #expect(record.publicKeyAlgorithm?.oid == "1.2.840.10045.2.1")
        #expect(record.publicKeyAlgorithm?.parametersDER != nil)
        #expect(record.signatureAlgorithm?.oid == "1.2.156.10197.1.501")
        #expect(record.subject?.displayValue.contains("SM2") == true)
        #expect(record.notValidAfter != nil)
        #expect(record.extensions.isEmpty == false)
        #expect(record.id.sha256 == CertificateID(der: der).sha256)
        #expect(record.diagnostics.contains { $0.code == .partialParse })
    }

    @Test func unknownAlgorithmYieldsPartialWithRawPreservation() async throws {
        // Synthetic certificate with an unassigned public key algorithm OID (1.2.163).
        let der = Self.syntheticCertificate(publicKeyAlgorithmOID: [0x2A, 0x81, 0x23])
        let record = try await parser.parse(der: der)
        #expect(record.parseStatus == .partial)
        #expect(record.publicKeyAlgorithm?.oid == "1.2.163")
        #expect(record.subject?.displayValue.contains("CN=unknown") == true)
        #expect(record.notValidBefore != nil)
        #expect(record.id.sha256 == CertificateID(der: der).sha256)
    }

    @Test func publicKeyFieldShowsAlgorithmAndBits() async throws {
        let rsa = try await parser.parse(der: try fixture("leaf.cer"))
        let rsaField = try #require(rsa.fields.first { $0.id == "publicKey" })
        #expect(rsaField.displayValue == "RSA (2048 Bits)")
        #expect(rsaField.rawValue?.count == 270)

        let ed = try await parser.parse(der: try fixture("cg-ed.cer"))
        let edField = try #require(ed.fields.first { $0.id == "publicKey" })
        #expect(edField.displayValue == "Ed25519 (256 Bits)")
    }

    @Test func unknownExtensionFieldShowsOIDNameAndHexValue() async throws {
        // Windows-style listing: the dotted OID is the field name, the value is
        // the raw extension bytes in hex.
        let der = Self.syntheticCertificate(
            publicKeyAlgorithmOID: [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
            extensionOID: [0x2A, 0x81, 0x23],
            extensionValue: Data("100080".utf8))
        let record = try await parser.parse(der: der)
        let field = try #require(record.fields.first { $0.id.hasPrefix("extension.1.2.163") })
        #expect(field.chineseName == "1.2.163")
        #expect(field.displayValue == "31 30 30 30 38 30")
        #expect(field.rawValue == Data("100080".utf8))
    }

    @Test func corruptDERIsRejected() async throws {
        let der = try fixture("leaf.cer")
        await #expect(throws: CertGlassError.malformedDER) {
            try await parser.parse(der: der.prefix(der.count - 10))
        }
    }

    @Test func randomBytesAreRejected() async throws {
        await #expect(throws: (any Error).self) {
            try await parser.parse(der: Data((0..<64).map { UInt8($0 &* 7 % 251) }))
        }
    }

    private func fixture(_ name: String) throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent(name)
        return try Data(contentsOf: url)
    }

    private static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var result = Data([tag])
        if content.count < 0x80 {
            result.append(UInt8(content.count))
        } else if content.count <= 0xFF {
            result += [0x81, UInt8(content.count)]
        } else {
            result += [0x82, UInt8(content.count >> 8), UInt8(content.count & 0xFF)]
        }
        result += content
        return result
    }

    private static func syntheticCertificate(
        publicKeyAlgorithmOID: [UInt8], extensionOID: [UInt8]? = nil, extensionValue: Data? = nil
    ) -> Data {
        func oidDER(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }
        func integer(_ value: UInt8) -> Data { tlv(0x02, Data([value])) }
        let name = tlv(0x30, tlv(0x31, tlv(0x30, oidDER([0x55, 0x04, 0x03]) + tlv(0x0C, Data("unknown".utf8)))))
        let utcTime = tlv(0x17, Data("260101000000Z".utf8))
        let validity = tlv(0x30, utcTime + utcTime)
        let algorithm = tlv(0x30, oidDER(publicKeyAlgorithmOID))
        let spki = tlv(0x30, algorithm + tlv(0x03, Data([0x00, 0x01, 0x02])))
        var tbsContent = tlv(0xA0, integer(2)) + integer(1)
            + tlv(0x30, oidDER([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x11]))
            + name + validity + name + spki
        if let extensionOID, let extensionValue {
            let extensionEntry = tlv(0x30, oidDER(extensionOID) + tlv(0x04, extensionValue))
            tbsContent += tlv(0xA3, tlv(0x30, extensionEntry))
        }
        let tbs = tlv(0x30, tbsContent)
        let signatureAlgorithm = tlv(0x30, oidDER([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]))
        let signature = tlv(0x03, Data([0x00, 0xAA, 0xBB]))
        return tlv(0x30, tbs + signatureAlgorithm + signature)
    }

    private static func oidContent(_ dottedOID: String) -> [UInt8] {
        let components = dottedOID.split(separator: ".").compactMap { Int($0) }
        precondition(components.count >= 2)
        var content = [UInt8(components[0] * 40 + components[1])]
        for component in components.dropFirst(2) {
            var value = component
            var encoded = [UInt8(value & 0x7F)]
            value >>= 7
            while value > 0 {
                encoded.append(UInt8(value & 0x7F) | 0x80)
                value >>= 7
            }
            content.append(contentsOf: encoded.reversed())
        }
        return content
    }
}
