import CertGlassCore
import Foundation
import SwiftASN1
import X509

/// Parses X.509 certificates while preserving the original DER and all raw
/// values. A structural SwiftASN1 walk always produces the displayed values;
/// a typed ``X509.Certificate`` parse is attempted only to decide whether the
/// record is complete or partial. Typed-parse failure degrades to partial;
/// structural failure throws.
public struct StandardCertificateParser: CertificateParsing {
    public init() {}

    public func parse(der: Data) async throws -> CertificateRecord {
        let bytes = [UInt8](der)
        let outer: [ASN1Node]
        do {
            let root = try DER.parse(bytes)
            guard root.identifier.tagClass == .universal, root.identifier.tagNumber == 0x10,
                  let nodes = root.childNodes, nodes.count == 3 else {
                throw CertGlassError.malformedDER
            }
            outer = nodes
        } catch let error as CertGlassError {
            throw error
        } catch {
            // Structural failures from SwiftASN1 all mean "not a decodable certificate".
            throw CertGlassError.malformedDER
        }
        let walked: StructuralWalk
        do {
            walked = try StructuralWalk(outer)
        } catch let error as CertGlassError {
            throw error
        } catch {
            throw CertGlassError.malformedDER
        }
        let typed = try? X509.Certificate(derEncoded: bytes)

        var diagnostics: [Diagnostic] = []
        if typed == nil {
            let keyOID = walked.publicKeyAlgorithm?.oid ?? "未知"
            let signatureOID = walked.signatureAlgorithm?.oid ?? "未知"
            diagnostics.append(Diagnostic(
                code: .partialParse, source: .parser, severity: .warning,
                message: "强类型解析不支持此证书，字段按原始值展示（公钥算法 \(keyOID)，签名算法 \(signatureOID)）。"
            ))
            diagnostics.append(Diagnostic(
                code: .unsupportedAlgorithm, source: .parser, severity: .warning,
                message: "算法不支持强类型解析；这不代表系统无法评估或证书已损坏。"
            ))
        }
        for unknownCritical in walked.extensions where unknownCritical.critical && !isInterpreted(unknownCritical.oid) {
            diagnostics.append(Diagnostic(
                code: .unhandledCriticalExtension, source: .parser, severity: .warning,
                message: "应用未实现该扩展的语义解释（OID \(unknownCritical.oid)）；这不等同于系统已拒绝该证书。原始值已保留。",
                fieldOID: unknownCritical.oid
            ))
        }

        let caStatus = walked.caStatus
        let extensionDetails = walked.extensions.enumerated().map {
            ExtensionDecoder.detail(for: $1, occurrence: $0)
        }
        let fields = StructuralWalk.fields(for: walked, extensionSummaries: extensionDetails.map(\.summary))
        return CertificateRecord(
            der: der,
            subject: walked.subject,
            issuer: walked.issuer,
            serialNumber: walked.serialNumber,
            notValidBefore: walked.notValidBefore,
            notValidAfter: walked.notValidAfter,
            publicKeyAlgorithm: walked.publicKeyAlgorithm,
            signatureAlgorithm: walked.signatureAlgorithm,
            publicKeyBytes: walked.publicKeyBytes,
            signatureBytes: walked.signatureBytes,
            extensions: walked.extensions,
            extensionDetails: extensionDetails,
            fields: fields,
            parseStatus: typed == nil ? .partial : .complete,
            caStatus: caStatus,
            diagnostics: diagnostics
        )
    }

    private func isInterpreted(_ oid: String) -> Bool {
        OIDNames.extensions[oid] != nil
    }
}

private struct StructuralWalk {
    var version: Int?
    var serialNumber: Data?
    var signatureAlgorithm: AlgorithmIdentifier?
    var publicKeyAlgorithm: AlgorithmIdentifier?
    var publicKeyBytes: Data?
    var signatureBytes: Data?
    var issuer: CertGlassCore.DistinguishedName?
    var subject: CertGlassCore.DistinguishedName?
    var notValidBefore: Date?
    var notValidAfter: Date?
    var extensions: [CertificateExtension]
    var caStatus: CAStatus

    init(_ outer: [ASN1Node]) throws {
        extensions = []
        caStatus = .unknown
        guard let tbs = outer[0].childNodes, tbs.count >= 7, outer[0].isConstructed else {
            throw CertGlassError.malformedDER
        }
        let signatureBitString = try ASN1BitString(derEncoded: outer[2])
        signatureBytes = Data(signatureBitString.bytes)
        signatureAlgorithm = try Self.algorithmIdentifier(outer[1])

        var cursor = tbs.makeIterator()
        var first = cursor.next()
        if let versionNode = first,
           versionNode.identifier.tagClass == .contextSpecific, versionNode.identifier.tagNumber == 0 {
            version = versionNode.childNodes?.first?.primitiveBytes?.first.map(Int.init)
            first = cursor.next()
        } else {
            version = 0
        }
        guard let serialNode = first, let serialBytes = serialNode.primitiveBytes else {
            throw CertGlassError.malformedDER
        }
        serialNumber = Data(serialBytes)
        // TBS signature field mirrors the outer signature algorithm; keep the outer value.
        guard cursor.next() != nil else { throw CertGlassError.malformedDER }

        issuer = try DistinguishedNameDecoder.decode(cursor.next())
        let validity = try Self.validity(cursor.next())
        notValidBefore = validity.notBefore
        notValidAfter = validity.notAfter
        subject = try DistinguishedNameDecoder.decode(cursor.next())
        guard let spki = cursor.next(), let spkiChildren = spki.childNodes, spkiChildren.count >= 2 else {
            throw CertGlassError.malformedDER
        }
        publicKeyAlgorithm = try Self.algorithmIdentifier(spkiChildren[0])
        let keyBitString = try ASN1BitString(derEncoded: spkiChildren[1])
        publicKeyBytes = Data(keyBitString.bytes)

        while let remaining = cursor.next() {
            guard remaining.identifier.tagClass == .contextSpecific,
                  remaining.identifier.tagNumber == 3 else { continue }
            extensions = try Self.extensions(remaining)
        }
        caStatus = Self.caStatus(from: extensions)
    }

    private static func algorithmIdentifier(_ node: ASN1Node) throws -> AlgorithmIdentifier {
        guard node.isConstructed, let children = node.childNodes, let oidNode = children.first,
              node.identifier.tagClass == .universal, node.identifier.tagNumber == 0x10 else {
            throw CertGlassError.malformedDER
        }
        let oid = try ASN1ObjectIdentifier(derEncoded: oidNode)
        let parameters = children.count > 1 ? Data(children[1].encodedBytes) : nil
        return AlgorithmIdentifier(oid: oid.description, parametersDER: parameters)
    }

    private static func validity(_ node: ASN1Node?) throws -> (notBefore: Date, notAfter: Date) {
        guard let node, node.isConstructed, let children = node.childNodes, children.count == 2 else {
            throw CertGlassError.malformedDER
        }
        return (try date(children[0]), try date(children[1]))
    }

    private static func date(_ node: ASN1Node) throws -> Date {
        var components = DateComponents()
        components.timeZone = TimeZone(identifier: "UTC")
        switch node.identifier {
        case .utcTime:
            let time = try UTCTime(derEncoded: node)
            components.year = time.year
            components.month = time.month
            components.day = time.day
            components.hour = time.hours
            components.minute = time.minutes
            components.second = time.seconds
        case .generalizedTime:
            let time = try GeneralizedTime(derEncoded: node)
            components.year = time.year
            components.month = time.month
            components.day = time.day
            components.hour = time.hours
            components.minute = time.minutes
            components.second = time.seconds
        default:
            throw CertGlassError.malformedDER
        }
        guard let date = Calendar(identifier: .gregorian).date(from: components) else {
            throw CertGlassError.malformedDER
        }
        return date
    }

    private static func extensions(_ contextNode: ASN1Node) throws -> [CertificateExtension] {
        guard let sequence = contextNode.childNodes?.first, let items = sequence.childNodes else {
            throw CertGlassError.malformedDER
        }
        var result: [CertificateExtension] = []
        for item in items {
            guard item.isConstructed, let parts = item.childNodes, let oidNode = parts.first else {
                throw CertGlassError.malformedDER
            }
            let oid = try ASN1ObjectIdentifier(derEncoded: oidNode)
            var index = 1
            var critical = false
            if index < parts.count, parts[index].identifier == .boolean,
               let booleanBytes = parts[index].primitiveBytes, booleanBytes.first != 0 {
                critical = true
                index += 1
            }
            guard index < parts.count, let contents = parts[index].primitiveBytes else {
                throw CertGlassError.malformedDER
            }
            result.append(CertificateExtension(oid: oid.description, critical: critical, rawValue: Data(contents)))
        }
        return result
    }

    private static func caStatus(from extensions: [CertificateExtension]) -> CAStatus {
        guard let basicConstraints = extensions.first(where: { $0.oid == "2.5.29.19" }) else {
            return .unknown
        }
        guard let node = try? DER.parse([UInt8](basicConstraints.rawValue)),
              node.isConstructed, let children = node.childNodes else {
            return .unknown
        }
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
        guard let first = children.first else { return .endEntity }
        if first.identifier == .boolean, let bytes = first.primitiveBytes {
            // DER BOOLEAN TRUE is encoded as 0xFF; any nonzero value means true.
            return bytes.first != 0 ? .certificateAuthority : .endEntity
        }
        return .endEntity
    }

    static func fields(for walked: StructuralWalk, extensionSummaries: [String]) -> [CertificateField] {
        var fields: [CertificateField] = []
        let formatter = ISO8601DateFormatter()
        if let version = walked.version {
            fields.append(CertificateField(
                id: "version", chineseName: "版本", englishName: "Version",
                displayValue: "v\(version + 1)"
            ))
        }
        if let serial = walked.serialNumber {
            fields.append(CertificateField(
                id: "serialNumber", chineseName: "序列号", englishName: "Serial Number",
                displayValue: Self.hex(serial), rawValue: serial
            ))
        }
        if let issuer = walked.issuer {
            fields.append(CertificateField(
                id: "issuer", chineseName: "颁发者", englishName: "Issuer",
                displayValue: issuer.displayValue
            ))
        }
        if let subject = walked.subject {
            fields.append(CertificateField(
                id: "subject", chineseName: "主体", englishName: "Subject",
                displayValue: subject.displayValue
            ))
        }
        if let notBefore = walked.notValidBefore {
            fields.append(CertificateField(
                id: "notValidBefore", chineseName: "生效时间", englishName: "Not Valid Before",
                displayValue: formatter.string(from: notBefore)
            ))
        }
        if let notAfter = walked.notValidAfter {
            fields.append(CertificateField(
                id: "notValidAfter", chineseName: "失效时间", englishName: "Not Valid After",
                displayValue: formatter.string(from: notAfter)
            ))
        }
        if let signatureAlgorithm = walked.signatureAlgorithm {
            fields.append(CertificateField(
                id: "signatureAlgorithm", chineseName: "签名算法", englishName: "Signature Algorithm",
                oid: signatureAlgorithm.oid,
                displayValue: OIDNames.algorithmName(oid: signatureAlgorithm.oid, parametersDER: signatureAlgorithm.parametersDER)
            ))
        }
        if let publicKeyAlgorithm = walked.publicKeyAlgorithm {
            fields.append(CertificateField(
                id: "publicKeyAlgorithm", chineseName: "公钥算法", englishName: "Public Key Algorithm",
                oid: publicKeyAlgorithm.oid,
                displayValue: OIDNames.algorithmName(oid: publicKeyAlgorithm.oid, parametersDER: publicKeyAlgorithm.parametersDER)
            ))
        }
        if let publicKeyBytes = walked.publicKeyBytes {
            let description = walked.publicKeyAlgorithm.map {
                Self.publicKeyDescription(algorithm: $0, keyBytes: publicKeyBytes)
            } ?? Self.hex(publicKeyBytes)
            fields.append(CertificateField(
                id: "publicKey", chineseName: "公钥", englishName: "Public Key",
                displayValue: description, rawValue: publicKeyBytes
            ))
        }
        if let signatureBytes = walked.signatureBytes {
            fields.append(CertificateField(
                id: "signature", chineseName: "签名值", englishName: "Signature",
                displayValue: Self.hex(signatureBytes), rawValue: signatureBytes
            ))
        }
        for (index, extensionValue) in walked.extensions.enumerated() {
            let names = OIDNames.extensions[extensionValue.oid]
            fields.append(CertificateField(
                id: "extension.\(extensionValue.oid)#\(index)",
                // Windows-style listing: unknown extensions show the dotted OID
                // as the field name and the raw value bytes as the value.
                chineseName: names?.chinese ?? extensionValue.oid,
                englishName: names?.english ?? "Unknown Extension",
                oid: extensionValue.oid,
                critical: extensionValue.critical,
                displayValue: names != nil
                    ? (extensionSummaries.indices.contains(index) ? extensionSummaries[index] : "")
                    : Self.hex(extensionValue.rawValue),
                rawValue: extensionValue.rawValue
            ))
        }
        return fields
    }

    /// Windows-style key description: algorithm family plus key size, for
    /// example "RSA (2048 Bits)". The raw key bytes stay available separately.
    static func publicKeyDescription(algorithm: AlgorithmIdentifier, keyBytes: Data) -> String {
        let bytes = [UInt8](keyBytes)
        switch algorithm.oid {
        case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
            // rsaEncryption / RSA-PSS: the SPKI BIT STRING carries RSAPublicKey DER.
            guard let bits = wrappedSequenceIntegerBits(bytes) else { return "RSA" }
            return "RSA (\(bits) Bits)"
        case "1.2.840.10040.4.1":
            // DSA: the BIT STRING carries SEQUENCE { y INTEGER }.
            guard let bits = wrappedSequenceIntegerBits(bytes) else { return "DSA" }
            return "DSA (\(bits) Bits)"
        case "1.2.840.10045.2.1":
            guard let bits = ecPointBits(bytes) else { return "ECDSA" }
            return "ECDSA (\(bits) Bits)"
        case "1.2.156.10197.1.301":
            guard let bits = ecPointBits(bytes) else { return "SM2" }
            return "SM2 (\(bits) Bits)"
        case "1.3.101.112": return "Ed25519 (256 Bits)"
        case "1.3.101.110": return "X25519 (256 Bits)"
        case "1.3.101.113": return "Ed448 (456 Bits)"
        case "1.3.101.111": return "X448 (448 Bits)"
        default:
            return OIDNames.algorithmName(oid: algorithm.oid, parametersDER: algorithm.parametersDER)
        }
    }

    private static func wrappedSequenceIntegerBits(_ bytes: [UInt8]) -> Int? {
        guard let root = try? DER.parse(bytes), let children = root.childNodes,
              let integer = children.first, let content = integer.primitiveBytes else { return nil }
        return integerBitLength(Array(content))
    }

    private static func ecPointBits(_ bytes: [UInt8]) -> Int? {
        switch bytes.first {
        case 0x04 where bytes.count > 1 && (bytes.count - 1) % 2 == 0:
            return (bytes.count - 1) / 2 * 8
        case 0x02, 0x03:
            return (bytes.count - 1) * 8
        default: return nil
        }
    }

    private static func integerBitLength(_ content: [UInt8]) -> Int {
        var significant = content
        while significant.first == 0 { significant.removeFirst() }
        guard let first = significant.first else { return 0 }
        var bits = (significant.count - 1) * 8
        var byte = first
        while byte != 0 { bits += 1; byte >>= 1 }
        return bits
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}
