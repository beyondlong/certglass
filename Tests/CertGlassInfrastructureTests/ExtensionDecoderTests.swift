import CertGlassCore
import CertGlassInfrastructure
import Foundation
import Testing

/// Minimal DER builders for extension values; these exercise the extension
/// decoders directly, independent of any full certificate.
struct ExtensionDecoderTests {
    private func tlv(_ tag: UInt8, _ content: Data) -> Data {
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

    private func ext(_ oid: String, critical: Bool = false, _ value: Data) -> CertificateExtension {
        CertificateExtension(oid: oid, critical: critical, rawValue: value)
    }

    private func detail(_ ext: CertificateExtension) -> CertificateExtensionDetail {
        ExtensionDecoder.detail(for: ext, occurrence: 0)
    }

    private func bitString(_ bytes: Data, unusedBits: UInt8) -> Data {
        tlv(0x03, Data([unusedBits]) + bytes)
    }

    // MARK: Key Usage

    @Test func keyUsageDecodesEachSetBitInChinese() {
        // bits 0 and 2: digitalSignature + keyEncipherment
        let value = bitString(Data([0b1010_0000]), unusedBits: 1)
        let result = detail(ext("2.5.29.15", value))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.summary == "数字签名、密钥加密")
        let setBits = result.items.filter { $0.displayValue.hasPrefix("已设置") }
        #expect(setBits.map(\.id) == ["2.5.29.15#0.bit0", "2.5.29.15#0.bit2"])
    }

    @Test func keyUsageAllNineBitsAndEncodingInfo() {
        let value = bitString(Data([0xFF, 0x80]), unusedBits: 7)
        let result = detail(ext("2.5.29.15", value))
        #expect(result.summary == "数字签名、内容承诺（不可否认）、密钥加密、数据加密、密钥协商、证书签名、CRL 签名、仅加密、仅解密")
        #expect(result.items.contains { $0.id.hasSuffix(".encoding") && $0.displayValue.contains("末尾未使用 7 位") })
    }

    @Test func keyUsageEmptyBitStringIsInterpretedButDeclaresNothing() {
        let value = bitString(Data([0x00]), unusedBits: 7)
        let result = detail(ext("2.5.29.15", value))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.summary == "未声明任何密钥用途。")
    }

    @Test func keyUsageNonZeroUnusedBitsAreMalformedAndRawPreserved() {
        let raw = bitString(Data([0b1010_0010]), unusedBits: 3)
        let result = detail(ext("2.5.29.15", raw))
        #expect(result.interpretationStatus == .malformed)
        #expect(result.items.isEmpty)
        #expect(result.rawValue == raw)
    }

    @Test func keyUsageNonBitStringIsMalformed() {
        let result = detail(ext("2.5.29.15", tlv(0x02, Data([1]))))
        #expect(result.interpretationStatus == .malformed)
    }

    // MARK: Extended Key Usage

    @Test func ekuKnownOIDsDecodeWithChineseNames() {
        func oid(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }
        let value = tlv(0x30, oid([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
            + oid([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]))
        let result = detail(ext("2.5.29.37", value))
        #expect(result.summary.contains("serverAuth"))
        #expect(result.summary.contains("clientAuth"))
        #expect(result.items.count == 2)
        #expect(result.items[0].oid == "1.3.6.1.5.5.7.3.1")
    }

    @Test func ekuAnyAndUnknownOIDsArePreserved() {
        func oid(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }
        let value = tlv(0x30, oid([0x55, 0x1D, 0x25, 0x00]) + oid([0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x19]))
        let result = detail(ext("2.5.29.37", value))
        #expect(result.summary.contains("anyExtendedKeyUsage"))
        #expect(result.summary.contains("1.3.6.1.4.1.153"))
        #expect(result.summary.contains("未注册"))
        #expect(result.items.last?.chineseName == "未注册用途")
    }

    // MARK: SAN / GeneralName

    private func generalNames(_ entries: Data...) -> Data {
        tlv(0x30, entries.reduce(Data(), +))
    }

    @Test func sanCoversDNSIPv4IPv6EmailURIAndRawIPPreservation() {
        let dns = tlv(0x82, Data("a.example.com".utf8))
        let ipv4 = tlv(0x87, Data([10, 0, 0, 1]))
        let ipv6 = tlv(0x87, Data([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]))
        let email = tlv(0x81, Data("a@b.cn".utf8))
        let uri = tlv(0x86, Data("https://example.cn/crl".utf8))
        let result = detail(ext("2.5.29.17", generalNames(dns, ipv4, ipv6, email, uri)))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.summary.contains("DNS 名称 ×1"))
        #expect(result.summary.contains("IP 地址 ×2"))
        let ipItems = result.items.filter { $0.englishName == "iPAddress" }
        #expect(ipItems[0].displayValue.contains("10.0.0.1"))
        #expect(ipItems[1].displayValue.contains("2001:db8::1"))
        #expect(ipItems[0].rawValue == Data([10, 0, 0, 1]))
        #expect(result.items.first?.displayValue == "a.example.com")
    }

    @Test func sanDirectoryAndRegisteredIDAndOtherNameDoNotGuessSemantics() {
        // directoryName: CN=测试 in an explicit Name
        let cnValue = tlv(0x0C, Data("测试".utf8))
        let cn = tlv(0x30, tlv(0x06, Data([0x55, 0x04, 0x03])) + cnValue)
        let rdn = tlv(0x31, cn)
        let directory = tlv(0xA4, tlv(0x30, rdn))
        // registeredID 1.2.3
        let registered = tlv(0x88, Data([0x2A, 0x03]))
        // otherName with type-id 1.2.3.4 and inner primitive
        let other = tlv(0xA0, tlv(0x06, Data([0x2A, 0x03, 0x04])) + tlv(0xA0, tlv(0x04, Data([0xAA]))))
        let result = detail(ext("2.5.29.17", generalNames(directory, registered, other)))
        #expect(result.items[0].englishName == "directoryName")
        #expect(result.items[0].displayValue.contains("CN=测试"))
        #expect(result.items[1].displayValue == "1.2.3")
        #expect(result.items[2].chineseName == "其他名称")
        #expect(result.items[2].oid == "1.2.3.4")
        #expect(result.items[2].rawValue != nil)
    }

    @Test func issuerAlternativeNameReusesGeneralNamesDecoding() {
        let dns = tlv(0x82, Data("ian.example.com".utf8))
        let result = detail(ext("2.5.29.18", generalNames(dns)))
        #expect(result.chineseName == "颁发者备用名称")
        #expect(result.summary.contains("ian.example.com"))
    }

    // MARK: SKI / AKI

    @Test func skiShowsIdentifierAndByteCount() {
        let keyID = Data(repeating: 0xAB, count: 20)
        let result = detail(ext("2.5.29.14", tlv(0x04, keyID)))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.summary.contains("20 字节"))
        #expect(result.items.first?.rawValue == keyID)
    }

    @Test func akiDecodesKeyIDIssuerAndSerial() {
        let keyID = tlv(0x80, Data([0x11, 0x22]))
        let serial = tlv(0x82, Data([0x7F])) // INTEGER 127
        let value = tlv(0x30, keyID + serial)
        let result = detail(ext("2.5.29.35", value))
        #expect(result.summary.contains("11 22"))
        #expect(result.summary.contains("颁发者序列号 127"))
        #expect(result.items.count == 2)
    }

    @Test func akiUnknownTagIsMalformed() {
        let value = tlv(0x30, tlv(0x83, Data([1])))
        let result = detail(ext("2.5.29.35", value))
        #expect(result.interpretationStatus == .malformed)
    }

    // MARK: CRL Distribution Points

    @Test func crlDPShowsURIsAndOfflineNotice() {
        let uri = tlv(0x86, Data("http://crl.example.cn/root.crl".utf8))
        // RFC 5280 implicit tagging: [0] distributionPoint -> [0] fullName
        // (the tag replaces the GeneralNames SEQUENCE tag) -> URI directly.
        let dp = tlv(0x30, tlv(0xA0, tlv(0xA0, uri)))
        let result = detail(ext("2.5.29.31", tlv(0x30, dp)))
        #expect(result.summary.contains("1 个 URI"))
        #expect(result.summary.contains("不会访问"))
        #expect(result.items.first?.children.first?.displayValue == "http://crl.example.cn/root.crl")
    }

    @Test func crlDPDecodesDirectoryAddressLikeRealBJCACertificate() {
        // Replicates a real BJCA certificate: one DP whose fullName is a
        // directoryName GeneralName, plus one URI-only DP.
        func rdn(_ oid: [UInt8], _ stringTag: UInt8, _ value: String) -> Data {
            tlv(0x31, tlv(0x30, tlv(0x06, Data(oid)) + tlv(stringTag, Data(value.utf8))))
        }
        let name = tlv(0x30,
            rdn([0x55, 0x04, 0x06], 0x13, "CN")
            + rdn([0x55, 0x04, 0x0A], 0x0C, "BJCA")
            + rdn([0x55, 0x04, 0x03], 0x0C, "ca3crl58"))
        let directoryDP = tlv(0x30, tlv(0xA0, tlv(0xA0, tlv(0xA4, name))))
        let uri = tlv(0x86, Data("http://ldap.example.cn/crl/ca3crl58.crl".utf8))
        let uriDP = tlv(0x30, tlv(0xA0, tlv(0xA0, uri)))
        let result = detail(ext("2.5.29.31", tlv(0x30, directoryDP + uriDP)))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.summary.contains("2 个分发点"))
        #expect(result.summary.contains("1 个 URI"))
        #expect(result.items[0].children.first?.chineseName == "目录名称")
        #expect(result.items[0].children.first?.displayValue.contains("ca3crl58") == true)
        #expect(result.items[1].children.first?.displayValue == "http://ldap.example.cn/crl/ca3crl58.crl")
    }

    @Test func crlDPToleratesRedundantGeneralNamesSequenceWrapper() {
        // Some encoders wrap the entries in an extra GeneralNames SEQUENCE.
        let uri = tlv(0x86, Data("http://crl.example.cn/root.crl".utf8))
        let dp = tlv(0x30, tlv(0xA0, tlv(0xA0, tlv(0x30, uri))))
        let result = detail(ext("2.5.29.31", tlv(0x30, dp)))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.items.first?.children.first?.displayValue == "http://crl.example.cn/root.crl")
    }

    @Test func crlDPDecodesRealBJCACertificateExtnValueBytes() {
        // extnValue captured verbatim from a real public BJCA end-entity
        // certificate (no private key material): one DP whose fullName is a
        // directoryName, plus one URI-only DP.
        func der(_ hex: String) -> Data {
            var data = Data()
            var index = hex.startIndex
            while index < hex.endIndex {
                let next = hex.index(index, offsetBy: 2)
                data.append(UInt8(hex[index..<next], radix: 16)!)
                index = next
            }
            return data
        }
        let result = detail(ext("2.5.29.31", der(
            "3081A4306DA06BA069A4673065310B300906035504061302434E310D300B060355040A0C04424A434131183016"
            + "060355040B0C0F5075626C6963205472757374204341311A301806035504030C115075626C69632054727573"
            + "742043412D313111300F0603550403130863613363726C35383033A031A02F862D687474703A2F2F6C646170"
            + "2E626A63612E6F72672E636E2F63726C2F707463612F63613363726C35382E63726C"
        )))
        #expect(result.interpretationStatus == .interpreted)
        #expect(result.summary.contains("2 个分发点"))
        #expect(result.summary.contains("1 个 URI"))
        #expect(result.items[0].children.first?.chineseName == "目录名称")
        #expect(result.items[0].children.first?.displayValue.contains("ca3crl58") == true)
        #expect(result.items[1].children.first?.displayValue
            == "http://ldap.bjca.org.cn/crl/ptca/ca3crl58.crl")
    }

    // MARK: AIA

    @Test func aiaShowsOCSPAndCAIssuersWithOfflineNotice() {
        func method(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }
        let ocsp = tlv(0x30, method([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01])
            + tlv(0x86, Data("http://ocsp.example.cn".utf8)))
        let caIssuers = tlv(0x30, method([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02])
            + tlv(0x86, Data("http://ca.example.cn/root.crt".utf8)))
        let result = detail(ext("1.3.6.1.5.5.7.1.1", tlv(0x30, ocsp + caIssuers)))
        #expect(result.summary.contains("OCSP"))
        #expect(result.summary.contains("CA Issuers"))
        #expect(result.summary.contains("不会访问"))
        #expect(result.items.count == 2)
        #expect(result.items[0].children.first?.displayValue == "http://ocsp.example.cn")
    }

    // MARK: Certificate Policies

    @Test func policiesDecodeOIDAndCPSQualifier() {
        func oid(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }
        let cpsQualifier = tlv(0x30, oid([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01])
            + tlv(0x86, Data("https://policy.example.cn/cps".utf8)))
        let policy = tlv(0x30, oid([0x2A, 0x81, 0x1C, 0xD0, 0x01]) + tlv(0xA0, cpsQualifier))
        let result = detail(ext("2.5.29.32", tlv(0x30, policy)))
        #expect(result.summary.contains("1 个策略"))
        let policyItem = result.items[0]
        #expect(policyItem.oid == "1.2.156.10241")
        #expect(policyItem.children.first?.displayValue == "https://policy.example.cn/cps")
        #expect(policyItem.children.first?.chineseName == "CPS 指针")
    }

    @Test func policiesOIDUsesDottedFormForArbitraryArcs() {
        // 2A 81 1C D0 01 decodes to 1.2.156.10272.1 only when arcs align; assert purely dotted output.
        func oid(_ bytes: [UInt8]) -> Data { tlv(0x06, Data(bytes)) }
        let policy = tlv(0x30, oid([0x2A, 0x81, 0x23]) + tlv(0xA0, Data()))
        let result = detail(ext("2.5.29.32", tlv(0x30, policy)))
        #expect(result.items[0].oid == "1.2.163")
    }

    // MARK: Name Constraints

    @Test func nameConstraintsDecodeRFC5280ImplicitSubtrees() {
        let permittedDNS = tlv(0x82, Data(".example.cn".utf8))
        let excludedEmail = tlv(0x81, Data("internal.example.cn".utf8))
        // Real shape: [0]/[1] IMPLICIT GeneralSubtrees -> GeneralSubtree entries.
        let value = tlv(0x30,
            tlv(0xA0, tlv(0x30, permittedDNS))
            + tlv(0xA1, tlv(0x30, excludedEmail)))
        let result = detail(ext("2.5.29.30", value))
        #expect(result.summary == "允许 1 项、排除 1 项。")
        #expect(result.items[0].chineseName == "允许的名称子树")
        #expect(result.items[1].chineseName == "排除的名称子树")
    }

    @Test func nameConstraintsTolerateRedundantSubtreesSequenceWrapper() {
        let permittedDNS = tlv(0x82, Data(".example.cn".utf8))
        let excludedEmail = tlv(0x81, Data("internal.example.cn".utf8))
        // Extra GeneralSubtrees SEQUENCE wrapper variant.
        let value = tlv(0x30,
            tlv(0xA0, tlv(0x30, tlv(0x30, permittedDNS)))
            + tlv(0xA1, tlv(0x30, tlv(0x30, excludedEmail))))
        let result = detail(ext("2.5.29.30", value))
        #expect(result.summary == "允许 1 项、排除 1 项。")
    }

    // MARK: Subject Directory Attributes

    @Test func subjectDirectoryAttributesDecodeOIDAndValues() {
        let attribute = tlv(0x30, tlv(0x06, Data([0x55, 0x04, 0x0B]))
            + tlv(0x31, tlv(0x0C, Data("工程部".utf8))))
        let result = detail(ext("2.5.29.9", tlv(0x30, attribute)))
        #expect(result.summary.contains("1 个目录属性"))
        #expect(result.items[0].oid == "2.5.4.11")
        #expect(result.items[0].children.first?.displayValue == "工程部")
    }

    // MARK: Unknown extensions

    @Test func standardClassificationFollowsOIDArcNotInterpretation() {
        // 标准扩展 = OID 属于公开标准弧（X.509 / PKIX），与应用是否实现解释无关。
        #expect(detail(ext("2.5.29.99", tlv(0x30, Data()))).isPublicStandard == true)
        #expect(detail(ext("1.3.6.1.5.5.7.1.2", tlv(0x30, Data()))).isPublicStandard == true)
        #expect(detail(ext("2.5.29.19", tlv(0x30, Data()))).isPublicStandard == true)
        // 私有/厂商弧一律算未知扩展。
        #expect(detail(ext("1.2.163.5", tlv(0x30, Data()))).isPublicStandard == false)
        #expect(detail(ext("2.16.840.1.113730.1.1", tlv(0x30, Data()))).isPublicStandard == false)
        #expect(detail(ext("1.3.6.1.4.1.311.10.3.1", tlv(0x30, Data()))).isPublicStandard == false)
    }

    @Test func unknownOIDIsRawOnlyWithDigestAndBytes() {
        let raw = tlv(0x30, tlv(0x02, Data([9])))
        let result = detail(ext("1.2.163.1", critical: true, raw))
        #expect(result.interpretationStatus == .rawOnly)
        #expect(result.chineseName == "未知扩展")
        #expect(result.summary.contains("1.2.163.1") || result.summary.contains("原始值"))
        #expect(result.rawValue == raw)
        #expect(result.rawDERTree?.tagNumber == 16)
        #expect(result.rawDERTree?.children.first?.tagNumber == 2)
    }

    @Test func garbageRawValueKeepsBytesWithoutDigest() {
        let raw = Data([0x00, 0x01, 0x02])
        let result = detail(ext("1.2.163.2", raw))
        #expect(result.interpretationStatus == .rawOnly)
        #expect(result.rawValue == raw)
        #expect(result.rawDERTree == nil)
    }

    // MARK: Occurrence identity

    @Test func repeatedOIDOccurrenceProducesDistinctStableIDs() {
        let raw = tlv(0x30, tlv(0x02, Data([9])))
        let first = ExtensionDecoder.detail(for: ext("1.2.163.1", raw), occurrence: 0)
        let second = ExtensionDecoder.detail(for: ext("1.2.163.1", raw), occurrence: 1)
        #expect(first.id == "1.2.163.1#0")
        #expect(second.id == "1.2.163.1#1")
        #expect(first != second)
    }
}
