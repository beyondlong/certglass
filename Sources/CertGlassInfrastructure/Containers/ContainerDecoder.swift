import CertGlassCore
import Foundation
import Security

/// Decodes DER single certificates, PEM blocks and certificate-only PKCS#7
/// messages. Signature containers are only mined for certificates; no signature
/// verification and no keychain access.
public struct StandardContainerDecoder: ContainerDecoding {
    public init() {}

    public func decode(_ input: DocumentInput) async throws -> DecodedContainer {
        let bytes = [UInt8](input.data)
        if input.data.range(of: Data("-----BEGIN".utf8)) != nil {
            return try decodePEM(text: String(decoding: bytes, as: UTF8.self))
        }
        if let decoded = base64TextContent(bytes) {
            let container = try decodeDER([UInt8](decoded))
            let format: ContainerFormat = container.format == .pkcs7DER ? .base64PKCS7 : .base64DER
            return DecodedContainer(format: format, certificatesDER: container.certificatesDER)
        }
        return try decodeDER(bytes)
    }
}

/// Recognizes header-less Base64 certificate text: whitespace-tolerant ASCII
/// whose entire content decodes as Base64. Returns nil when the input is not
/// Base64 text, so DER detection stays content-based.
private func base64TextContent(_ bytes: [UInt8]) -> Data? {
    guard let text = String(bytes: bytes, encoding: .utf8) else { return nil }
    let compact = text.filter { !$0.isWhitespace }
    guard !compact.isEmpty, compact.allSatisfy(\.isBase64Character) else { return nil }
    var padded = compact
    if padded.count % 4 != 0 { padded.append(String(repeating: "=", count: 4 - padded.count % 4)) }
    guard let decoded = Data(base64Encoded: padded) else { return nil }
    return decoded
}

private extension Character {
    var isBase64Character: Bool {
        isLetter && isASCII || isNumber && isASCII || self == "+" || self == "/" || self == "="
    }
}

private struct TLV {
    let tag: UInt8
    let contentRange: Range<Int>
    let endIndex: Int
}

private func readTLV(_ bytes: [UInt8], at index: Int) -> TLV? {
    guard index + 2 <= bytes.count else { return nil }
    let tag = bytes[index]
    let first = bytes[index + 1]
    var length: Int
    var contentStart: Int
    if first < 0x80 {
        length = Int(first)
        contentStart = index + 2
    } else {
        let byteCount = Int(first & 0x7F)
        guard byteCount > 0, byteCount <= 4, index + 2 + byteCount <= bytes.count else { return nil }
        length = 0
        for offset in 0..<byteCount { length = length << 8 | Int(bytes[index + 2 + offset]) }
        contentStart = index + 2 + byteCount
    }
    let end = contentStart + length
    guard end <= bytes.count else { return nil }
    return TLV(tag: tag, contentRange: contentStart..<end, endIndex: end)
}

/// Structural check only: outer SEQUENCE whose first element is a SEQUENCE
/// (tbsCertificate). Deep validation belongs to the certificate parser.
private func looksLikeCertificate(_ bytes: [UInt8]) -> Bool {
    guard let outer = readTLV(bytes, at: 0), outer.tag == 0x30 else { return false }
    guard let inner = readTLV(bytes, at: outer.contentRange.lowerBound), inner.tag == 0x30 else { return false }
    return true
}

private let pkcs7SignedDataOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]

private func decodeDER(_ bytes: [UInt8]) throws -> DecodedContainer {
    guard !bytes.isEmpty, bytes[0] == 0x30 else {
        throw CertGlassError.unsupportedFile
    }
    guard let outer = readTLV(bytes, at: 0) else {
        throw CertGlassError.malformedDER
    }
    let firstInner = readTLV(bytes, at: outer.contentRange.lowerBound)
    if let firstInner, firstInner.tag == 0x06,
       Array(bytes[firstInner.contentRange]) == pkcs7SignedDataOID {
        let der = Data(bytes.prefix(outer.endIndex))
        let certificates = try decodePKCS7(der)
        return DecodedContainer(format: .pkcs7DER, certificatesDER: certificates)
    }
    guard looksLikeCertificate(bytes) else {
        // A SEQUENCE header that cannot be walked as a certificate is a truncation or corruption.
        throw CertGlassError.malformedDER
    }
    return DecodedContainer(format: .der, certificatesDER: [Data(bytes.prefix(outer.endIndex))])
}

private struct PEMBlock {
    let label: String
    let body: Data
}

private func parsePEMBlocks(_ text: String) throws -> [PEMBlock] {
    // CR-LF is a single grapheme cluster, so split on newline characters rather
    // than the "\n" character.
    let lines = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
        .map { $0.trimmingCharacters(in: .whitespaces) }
    var blocks: [PEMBlock] = []
    var index = 0
    while index < lines.count {
        guard let begin = beginLabel(lines[index]) else {
            index += 1
            continue
        }
        var bodyLines: [String] = []
        var endIndex: Int? = nil
        var cursor = index + 1
        while cursor < lines.count {
            if let end = endLabel(lines[cursor]), end == begin {
                endIndex = cursor
                break
            }
            guard beginLabel(lines[cursor]) == nil else { break }
            bodyLines.append(lines[cursor])
            cursor += 1
        }
        guard let endIndex else { throw CertGlassError.truncatedPEM }
        let base64 = bodyLines.joined().filter { !$0.isWhitespace }
        guard let body = Data(base64Encoded: base64), !base64.isEmpty else {
            throw CertGlassError.malformedPEMBase64
        }
        blocks.append(PEMBlock(label: begin, body: body))
        index = endIndex + 1
    }
    if blocks.isEmpty { throw CertGlassError.truncatedPEM }
    return blocks
}

private func beginLabel(_ line: String) -> String? {
    guard line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") else { return nil }
    let label = line.dropFirst("-----BEGIN ".count).dropLast(5)
    return label.isEmpty ? nil : String(label)
}

private func endLabel(_ line: String) -> String? {
    guard line.hasPrefix("-----END "), line.hasSuffix("-----") else { return nil }
    let label = line.dropFirst("-----END ".count).dropLast(5)
    return label.isEmpty ? nil : String(label)
}

private func decodePEM(text: String) throws -> DecodedContainer {
    let blocks = try parsePEMBlocks(text)
    var certificates: [Data] = []
    var decodedPKCS7 = false
    for block in blocks {
        if block.label.hasSuffix("PRIVATE KEY") || block.label.contains("PRIVATE KEY") {
            throw CertGlassError.privateKeyPEM(label: block.label)
        }
        switch block.label {
        case "CERTIFICATE", "X509 CERTIFICATE":
            let bytes = [UInt8](block.body)
            guard looksLikeCertificate(bytes) else { throw CertGlassError.malformedDER }
            certificates.append(block.body)
        case "PKCS7", "CMS":
            certificates.append(contentsOf: try decodePKCS7(block.body))
            decodedPKCS7 = true
        default:
            // Unrecognized blocks (for example PUBLIC KEY) carry no certificates.
            continue
        }
    }
    guard !certificates.isEmpty else { throw CertGlassError.unsupportedFile }
    return DecodedContainer(
        format: decodedPKCS7 ? .pkcs7PEM : .pem,
        certificatesDER: certificates
    )
}

private func decodePKCS7(_ der: Data) throws -> [Data] {
    var decoder: CMSDecoder?
    guard CMSDecoderCreate(&decoder) == errSecSuccess, let decoder else {
        throw CertGlassError.unsupportedContainer
    }
    let updateStatus = der.withUnsafeBytes { raw -> OSStatus in
        guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return errSecParam
        }
        return CMSDecoderUpdateMessage(decoder, base, raw.count)
    }
    guard updateStatus == errSecSuccess, CMSDecoderFinalizeMessage(decoder) == errSecSuccess else {
        throw CertGlassError.unsupportedContainer
    }
    var certsCF: CFArray?
    guard CMSDecoderCopyAllCerts(decoder, &certsCF) == errSecSuccess, let certsCF else {
        throw CertGlassError.noCertificates
    }
    // CMSDecoderCopyAllCerts yields SecCertificate refs; SecCertificateCopyData
    // returns the DER bytes originally supplied to the message.
    let certificateRefs = (certsCF as NSArray).map { $0 as! SecCertificate }
    let certificates = certificateRefs.compactMap { SecCertificateCopyData($0) as Data? }
    guard !certificates.isEmpty else { throw CertGlassError.noCertificates }
    return certificates
}
