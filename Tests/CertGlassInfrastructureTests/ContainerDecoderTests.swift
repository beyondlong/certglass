import CertGlassCore
import CertGlassInfrastructure
import Foundation
import Testing

struct ContainerDecoderTests {
    private let decoder = StandardContainerDecoder()

    @Test func derSingleCertificateDecodesExactBytes() async throws {
        let der = try fixture("leaf.cer")
        let container = try await decoder.decode(try DocumentInput(data: der))
        #expect(container.format == .der)
        #expect(container.certificatesDER == [der])
    }

    @Test func pemSingleCertificateDecodesToOriginalDER() async throws {
        let der = try fixture("leaf.cer")
        let input = try DocumentInput(data: pemData([("CERTIFICATE", der)], lineEnding: "\n"))
        let container = try await decoder.decode(input)
        #expect(container.format == .pem)
        #expect(container.certificatesDER == [der])
    }

    @Test func pemWithCRLFLineEndingsDecodes() async throws {
        let der = try fixture("leaf.cer")
        let input = try DocumentInput(data: pemData([("CERTIFICATE", der)], lineEnding: "\r\n"))
        let container = try await decoder.decode(input)
        #expect(container.certificatesDER == [der])
    }

    @Test func multiBlockPEMPreservesEncounterOrder() async throws {
        let leaf = try fixture("leaf.cer")
        let ca = try fixture("ca.cer")
        let input = try DocumentInput(data: pemData(
            [("CERTIFICATE", leaf), ("CERTIFICATE", ca)], lineEnding: "\n"
        ))
        let container = try await decoder.decode(input)
        #expect(container.certificatesDER == [leaf, ca])
    }

    @Test func pemTextOutsideBlocksIsIgnored() async throws {
        let der = try fixture("leaf.cer")
        let wrapped = "Subject: something\r\n\r\n" + pemText([("CERTIFICATE", der)], lineEnding: "\n") + "\ntrailing note\n"
        let container = try await decoder.decode(try DocumentInput(data: Data(wrapped.utf8)))
        #expect(container.certificatesDER == [der])
    }

    @Test func pkcs7DERContainerExtractsAllCertificates() async throws {
        let leaf = try fixture("leaf.cer")
        let ca = try fixture("ca.cer")
        let container = try await decoder.decode(try DocumentInput(data: try fixture("chain.p7b")))
        #expect(container.format == .pkcs7DER)
        #expect(container.certificatesDER.count == 2)
        #expect(Set(container.certificatesDER) == [leaf, ca])
    }

    @Test func pkcs7PEMContainerExtractsAllCertificates() async throws {
        let leaf = try fixture("leaf.cer")
        let ca = try fixture("ca.cer")
        let container = try await decoder.decode(try DocumentInput(data: try fixture("chain.p7b.pem")))
        #expect(container.format == .pkcs7PEM)
        #expect(container.certificatesDER.count == 2)
        #expect(Set(container.certificatesDER) == [leaf, ca])
    }

    @Test func privateKeyPEMBlockIsExplicitlyRejected() async throws {
        let input = try DocumentInput(data: Data(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".utf8
        ))
        await #expect(throws: CertGlassError.privateKeyPEM(label: "PRIVATE KEY")) {
            try await decoder.decode(input)
        }
    }

    @Test func rsaPrivateKeyPEMBlockIsExplicitlyRejected() async throws {
        let input = try DocumentInput(data: Data(
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n".utf8
        ))
        await #expect(throws: CertGlassError.privateKeyPEM(label: "RSA PRIVATE KEY")) {
            try await decoder.decode(input)
        }
    }

    @Test func invalidPEMBase64IsRejected() async throws {
        let input = try DocumentInput(data: Data(
            "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n".utf8
        ))
        await #expect(throws: CertGlassError.malformedPEMBase64) {
            try await decoder.decode(input)
        }
    }

    @Test func truncatedPEMBlockIsRejected() async throws {
        let input = try DocumentInput(data: Data(
            "-----BEGIN CERTIFICATE-----\nAAAA\n".utf8
        ))
        await #expect(throws: CertGlassError.truncatedPEM) {
            try await decoder.decode(input)
        }
    }

    @Test func truncatedDERIsRejectedAsMalformed() async throws {
        let der = try fixture("leaf.cer")
        let input = try DocumentInput(data: der.prefix(der.count - 8))
        await #expect(throws: CertGlassError.malformedDER) {
            try await decoder.decode(input)
        }
    }

    @Test func emptyDERSequenceIsRejectedAsMalformed() async throws {
        let input = try DocumentInput(data: Data([0x30, 0x00]))
        await #expect(throws: CertGlassError.malformedDER) {
            try await decoder.decode(input)
        }
    }

    @Test func nonASN1ContentIsRejectedAsUnsupported() async throws {
        let input = try DocumentInput(data: Data("hello world".utf8))
        await #expect(throws: CertGlassError.unsupportedFile) {
            try await decoder.decode(input)
        }
    }

    @Test func derSequenceWithoutCertificateStructureIsRejected() async throws {
        let input = try DocumentInput(data: Data([0x30, 0x03, 0x02, 0x01, 0x00]))
        await #expect(throws: CertGlassError.malformedDER) {
            try await decoder.decode(input)
        }
    }

    @Test func structurallyValidSyntheticCertificateDecodes() async throws {
        // Structural fixture only; deep X.509 validation belongs to the parser.
        let input = try DocumentInput(data: Self.minimalCertDER(0x42))
        let container = try await decoder.decode(input)
        #expect(container.format == .der)
        #expect(container.certificatesDER == [Self.minimalCertDER(0x42)])
    }

    @Test func headerlessBase64CertificateDecodesToOriginalDER() async throws {
        let der = try fixture("leaf.cer")
        let input = try DocumentInput(data: Data(der.base64EncodedString().utf8))
        let container = try await decoder.decode(input)
        #expect(container.format == .base64DER)
        #expect(container.certificatesDER == [der])
    }

    @Test func headerlessBase64ToleratesWhitespaceAndMissingPadding() async throws {
        let der = try fixture("leaf.cer")
        var base64 = der.base64EncodedString()
        base64.removeLast(1) // one '=' dropped
        let wrapped = "\r\n" + base64 + "\n"
        let container = try await decoder.decode(try DocumentInput(data: Data(wrapped.utf8)))
        #expect(container.format == .base64DER)
        #expect(container.certificatesDER == [der])
    }

    @Test func headerlessBase64PKCS7ExtractsAllCertificates() async throws {
        let leaf = try fixture("leaf.cer")
        let ca = try fixture("ca.cer")
        let p7 = try fixture("chain.p7b")
        let input = try DocumentInput(data: Data(p7.base64EncodedString().utf8))
        let container = try await decoder.decode(input)
        #expect(container.format == .base64PKCS7)
        #expect(Set(container.certificatesDER) == [leaf, ca])
    }

    @Test func nonBase64CharacterTextIsRejectedAsUnsupported() async throws {
        let input = try DocumentInput(data: Data("!!!! not base64 !!!".utf8))
        await #expect(throws: CertGlassError.unsupportedFile) {
            try await decoder.decode(input)
        }
    }

    private func fixture(_ name: String) throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent(name)
        return try Data(contentsOf: url)
    }

    private func pemText(_ blocks: [(label: String, der: Data)], lineEnding: String) -> String {
        blocks.map { block in
            let base64 = block.der.base64EncodedString()
            let lines = stride(from: 0, to: base64.count, by: 64).map { start -> String in
                let end = min(start + 64, base64.count)
                let startIdx = base64.index(base64.startIndex, offsetBy: start)
                let endIdx = base64.index(base64.startIndex, offsetBy: end)
                return String(base64[startIdx..<endIdx])
            }
            return "-----BEGIN \(block.label)-----\(lineEnding)"
                + lines.joined(separator: lineEnding) + lineEnding
                + "-----END \(block.label)-----"
        }.joined(separator: lineEnding)
    }

    private func pemData(_ blocks: [(label: String, der: Data)], lineEnding: String) -> Data {
        Data(pemText(blocks, lineEnding: lineEnding).utf8)
    }

    private static func minimalCertDER(_ payload: UInt8) -> Data {
        func tlv(_ tag: UInt8, _ content: Data) -> Data {
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
        let tbs = tlv(0x30, tlv(0x30, tlv(0x02, Data([payload]))))
        let algorithm = tlv(0x30, tlv(0x02, Data([payload])))
        let signature = tlv(0x03, Data([0x00, payload]))
        return tlv(0x30, tbs + algorithm + signature)
    }
}
