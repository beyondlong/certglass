import CertGlassCore
import Foundation
import SwiftASN1

/// Decodes known RFC 5280 extensions into structured Chinese-language detail
/// trees. All decoders take only the extnValue content bytes; unknown OIDs,
/// undecodable values and unexpected structures degrade to `rawOnly` /
/// `malformed` while preserving the original bytes. No network, keychain or
/// trust conclusions are involved.
public enum ExtensionDecoder {
    public static func detail(for extensionValue: CertificateExtension, occurrence: Int) -> CertificateExtensionDetail {
        let names = OIDNames.extensions[extensionValue.oid]
        let id = "\(extensionValue.oid)#\(occurrence)"
        let isPublicStandard = OIDNames.isPublicStandardExtension(extensionValue.oid)
        let context = ExtensionContext(
            oid: extensionValue.oid, id: id,
            chinese: names?.chinese ?? "未知扩展", english: names?.english ?? "Unknown Extension",
            critical: extensionValue.critical, rawValue: extensionValue.rawValue,
            isPublicStandard: isPublicStandard
        )
        switch extensionValue.oid {
        case "2.5.29.19": return basicConstraints(context)
        case "2.5.29.15": return keyUsage(context)
        case "2.5.29.37": return extendedKeyUsage(context)
        case "2.5.29.17", "2.5.29.18": return generalNames(context, isIssuer: extensionValue.oid == "2.5.29.18")
        case "2.5.29.14": return subjectKeyIdentifier(context)
        case "2.5.29.35": return authorityKeyIdentifier(context)
        case "2.5.29.31": return crlDistributionPoints(context)
        case "1.3.6.1.5.5.7.1.1": return authorityInformationAccess(context)
        case "2.5.29.32": return certificatePolicies(context)
        case "2.5.29.30": return nameConstraints(context)
        case "2.5.29.9": return subjectDirectoryAttributes(context)
        default:
            return CertificateExtensionDetail(
                id: context.id, oid: context.oid, chineseName: context.chinese, englishName: context.english,
                critical: context.critical,
                summary: "原始值（\(context.rawValue.count) 字节），应用未实现语义解释。",
                interpretationStatus: .rawOnly, isPublicStandard: context.isPublicStandard,
                items: [], rawValue: context.rawValue,
                rawDERTree: ASN1SummaryBuilder.digest(context.rawValue)
            )
        }
    }

    private struct ExtensionContext {
        let oid: String
        let id: String
        let chinese: String
        let english: String
        let critical: Bool
        let rawValue: Data
        let isPublicStandard: Bool
    }

    private static func rawNode(_ value: Data) -> ASN1Node? {
        try? DER.parse([UInt8](value))
    }

    /// Lenient signed big-endian INTEGER decode for display; no minimal-encoding
    /// enforcement (an over-encoded integer still shows its value).
    private static func integerValue(of node: ASN1Node) -> Int? {
        DERInteger.value(of: node)
    }

    private static func malformed(_ context: ExtensionContext, reason: String) -> CertificateExtensionDetail {
        CertificateExtensionDetail(
            id: context.id, oid: context.oid, chineseName: context.chinese, englishName: context.english,
            critical: context.critical, summary: "扩展编码异常：\(reason)。",
            interpretationStatus: .malformed, isPublicStandard: context.isPublicStandard,
            items: [], rawValue: context.rawValue,
            rawDERTree: ASN1SummaryBuilder.digest(context.rawValue)
        )
    }

    private static func detail(
        _ context: ExtensionContext, summary: String, items: [CertificateExtensionItem]
    ) -> CertificateExtensionDetail {
        CertificateExtensionDetail(
            id: context.id, oid: context.oid, chineseName: context.chinese, englishName: context.english,
            critical: context.critical, summary: summary,
            interpretationStatus: .interpreted, isPublicStandard: context.isPublicStandard,
            items: items, rawValue: context.rawValue,
            rawDERTree: ASN1SummaryBuilder.digest(context.rawValue)
        )
    }

    // MARK: - 2.5.29.19 Basic Constraints

    private static func basicConstraints(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let children = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE 结构")
        }
        var index = 0
        var isCA = false
        var pathLength: Int?
        if let first = children.first, first.identifier == .boolean, let bytes = first.primitiveBytes {
            isCA = bytes.first != 0
            index = 1
        }
        if children.count > index, children[index].identifier == .integer {
            pathLength = integerValue(of: children[index])
        }
        var items = [CertificateExtensionItem(
            id: "\(context.id).ca", chineseName: "是否证书颁发机构（cA）", englishName: "cA",
            displayValue: isCA ? "是（CA 证书）" : "否（终端实体证书）"
        )]
        if let pathLength {
            items.append(CertificateExtensionItem(
                id: "\(context.id).pathLen", chineseName: "路径长度限制（pathLenConstraint）",
                englishName: "pathLenConstraint", displayValue: "\(pathLength)"
            ))
        }
        let summary: String
        switch (isCA, pathLength) {
        case (true, let len?):
            if len == 0 {
                summary = "CA 证书，只能签发终端实体证书。"
            } else {
                summary = "CA 证书，路径长度限制 \(len)。"
            }
        case (true, nil): summary = "CA 证书，未声明路径长度限制。"
        case (false, _): summary = "非 CA 证书（终端实体）。"
        }
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 2.5.29.15 Key Usage

    private static let keyUsageBits: [(bit: Int, chinese: String, english: String, explanation: String)] = [
        (0, "数字签名", "digitalSignature", "用于验证签名或生成数字签名"),
        (1, "内容承诺（不可否认）", "nonRepudiation", "用于内容承诺场景；仅按证书声明展示，不推导法律结论"),
        (2, "密钥加密", "keyEncipherment", "用公钥加密或封装密钥"),
        (3, "数据加密", "dataEncipherment", "直接使用公钥加密数据"),
        (4, "密钥协商", "keyAgreement", "用于建立或协商共享密钥"),
        (5, "证书签名", "keyCertSign", "用于签发或签署下级证书"),
        (6, "CRL 签名", "cRLSign", "用于签署证书吊销列表"),
        (7, "仅加密", "encipherOnly", "仅在密钥协商语境下表示加密方向"),
        (8, "仅解密", "decipherOnly", "仅在密钥协商语境下表示解密方向")
    ]

    private static func keyUsage(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.identifier == .bitString, let bytes = node.primitiveBytes,
              !bytes.isEmpty else {
            return malformed(context, reason: "不是 BIT STRING 结构")
        }
        let unusedBits = Int(bytes.first!)
        guard unusedBits <= 7 else {
            return malformed(context, reason: "BIT STRING 未使用位数非法（\(unusedBits)）")
        }
        let data = Data(bytes.dropFirst())
        let totalBits = data.count * 8 - unusedBits
        if let lastByte = data.last, unusedBits > 0, lastByte & ((1 << unusedBits) - 1) != 0 {
            return malformed(context, reason: "BIT STRING 末尾未使用位被置位")
        }
        func bit(_ index: Int) -> Bool {
            let byteIndex = index / 8
            guard byteIndex < data.count else { return false }
            return data[data.startIndex + byteIndex] & (1 << (7 - index % 8)) != 0
        }
        var setNames: [String] = []
        var items: [CertificateExtensionItem] = []
        for entry in keyUsageBits {
            let set = bit(entry.bit)
            if set { setNames.append(entry.chinese) }
            items.append(CertificateExtensionItem(
                id: "\(context.id).bit\(entry.bit)",
                chineseName: entry.chinese,
                englishName: "\(entry.english)（bit \(entry.bit)）",
                displayValue: set ? "已设置：\(entry.explanation)" : "未设置"
            ))
        }
        items.append(CertificateExtensionItem(
            id: "\(context.id).encoding", chineseName: "原始编码", englishName: "BIT STRING",
            displayValue: "共 \(totalBits) 个有效位，末尾未使用 \(unusedBits) 位；原始值 \(data.count) 字节。"
        ))
        let summary = setNames.isEmpty ? "未声明任何密钥用途。" : setNames.joined(separator: "、")
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 2.5.29.37 Extended Key Usage

    private static func extendedKeyUsage(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let oids = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE OF OBJECT IDENTIFIER 结构")
        }
        var summaryParts: [String] = []
        var unknownCount = 0
        var items: [CertificateExtensionItem] = []
        for (index, child) in oids.enumerated() {
            guard let oid = try? ASN1ObjectIdentifier(derEncoded: child) else {
                return malformed(context, reason: "第 \(index + 1) 项不是 OBJECT IDENTIFIER")
            }
            let dotted = oid.description
            if let names = OIDNames.extendedKeyUsages[dotted] {
                summaryParts.append("\(names.english)（\(names.chinese)）")
                items.append(CertificateExtensionItem(
                    id: "\(context.id).eku\(index)", chineseName: names.chinese, englishName: names.english,
                    oid: dotted, displayValue: dotted
                ))
            } else {
                unknownCount += 1
                summaryParts.append(dotted)
                items.append(CertificateExtensionItem(
                    id: "\(context.id).eku\(index)", chineseName: "未注册用途", englishName: "Unknown Purpose",
                    oid: dotted, displayValue: "应用未注册该用途 OID，保留点分标识：\(dotted)"
                ))
            }
        }
        var summary = summaryParts.isEmpty ? "未声明任何扩展用途。" : summaryParts.joined(separator: "、")
        if unknownCount > 0 { summary += "（其中 \(unknownCount) 个未注册 OID 保留原始标识）" }
        return detail(context, summary: summary, items: items)
    }

    // MARK: - GeneralName helpers (SAN / IAN / CRL DP / AIA / NC)

    private enum GeneralNameTag: Int {
        case otherName = 0, rfc822 = 1, dns = 2, directory = 4, uri = 6, ip = 7, registeredID = 8

        var label: (chinese: String, english: String) {
            switch self {
            case .otherName: ("其他名称", "otherName")
            case .rfc822: ("电子邮件", "rfc822Name")
            case .dns: ("DNS 名称", "dNSName")
            case .directory: ("目录名称", "directoryName")
            case .uri: ("URI", "uniformResourceIdentifier")
            case .ip: ("IP 地址", "iPAddress")
            case .registeredID: ("注册 ID", "registeredID")
            }
        }
    }

    private static func generalNameItem(_ node: ASN1Node, id: String) -> CertificateExtensionItem? {
        guard node.identifier.tagClass == .contextSpecific,
              let tag = GeneralNameTag(rawValue: Int(node.identifier.tagNumber)) else { return nil }
        let label = tag.label
        switch tag {
        case .dns, .rfc822, .uri:
            guard let bytes = node.primitiveBytes else { return nil }
            let value = String(decoding: Data(bytes), as: UTF8.self)
            return CertificateExtensionItem(
                id: id, chineseName: label.chinese, englishName: label.english,
                displayValue: value, rawValue: Data(bytes)
            )
        case .ip:
            guard let bytes = node.primitiveBytes else { return nil }
            let data = Data(bytes)
            let value = data.count == 4 ? dottedIP(data)
                : data.count == 16 ? ipv6String(data) : data.map { String(format: "%02x", $0) }.joined()
            return CertificateExtensionItem(
                id: id, chineseName: label.chinese, englishName: label.english,
                displayValue: "\(value)（原始 \(data.map { String(format: "%02x", $0) }.joined())）",
                rawValue: data
            )
        case .registeredID:
            guard let bytes = node.primitiveBytes, let dotted = dottedOID(bytes) else { return nil }
            return CertificateExtensionItem(
                id: id, chineseName: label.chinese, englishName: label.english,
                oid: dotted, displayValue: dotted
            )
        case .directory:
            // [4] EXPLICIT Name: the actual Name SEQUENCE is one level down.
            guard let nameNode = node.childNodes?.first,
                  let name = try? DistinguishedNameDecoder.decode(nameNode) else { return nil }
            return CertificateExtensionItem(
                id: id, chineseName: label.chinese, englishName: label.english,
                displayValue: name.displayValue
            )
        case .otherName:
            // Do not guess the inner type; show the type-id OID and raw bytes only.
            let children = node.childNodes ?? []
            let typeOID = children.first.flatMap { try? ASN1ObjectIdentifier(derEncoded: $0).description }
            let raw = Data(node.encodedBytes)
            return CertificateExtensionItem(
                id: id, chineseName: label.chinese, englishName: label.english,
                oid: typeOID, displayValue: "type-id：\(typeOID ?? "未知")；原始值 \(raw.count) 字节", rawValue: raw
            )
        }
    }

    private static func dottedIP(_ data: Data) -> String {
        data.map { String($0) }.joined(separator: ".")
    }

    /// Dotted-decimal OID from raw content octets, used where the encoded node
    /// carries a context-specific tag (for example registeredID [8]).
    private static func dottedOID(_ content: ArraySlice<UInt8>) -> String? {
        guard let first = content.first, first & 0x80 == 0 else { return nil }
        var arcs: [UInt] = first >= 80 ? [2, UInt(first) - 80] : [UInt(first) / 40, UInt(first) % 40]
        var value: UInt = 0
        var inProgress = false
        for byte in content.dropFirst() {
            value = value << 7 | UInt(byte & 0x7F)
            inProgress = byte & 0x80 != 0
            if !inProgress { arcs.append(value); value = 0 }
        }
        guard !inProgress else { return nil }
        return arcs.map(String.init).joined(separator: ".")
    }

    private static func ipv6String(_ data: Data) -> String {
        var groups: [String] = []
        var iterator = data.makeIterator()
        while let high = iterator.next(), let low = iterator.next() {
            groups.append(String(format: "%x", UInt16(high) << 8 | UInt16(low)))
        }
        // Compress the longest zero run into "::".
        var bestStart = -1, bestLength = 0, currentStart = -1, currentLength = 0
        for (index, group) in groups.enumerated() {
            if group == "0" {
                if currentStart < 0 { currentStart = index }
                currentLength += 1
                if currentLength > bestLength { bestStart = currentStart; bestLength = currentLength }
            } else {
                currentStart = -1; currentLength = 0
            }
        }
        guard bestLength > 1 else { return groups.joined(separator: ":") }
        return (groups[..<bestStart] + [""] + groups[(bestStart + bestLength)...]).joined(separator: ":")
    }

    private static func generalNames(_ context: ExtensionContext, isIssuer: Bool) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let entries = node.childNodes else {
            return malformed(context, reason: "不是 GeneralNames SEQUENCE 结构")
        }
        var items: [CertificateExtensionItem] = []
        var counts: [String: Int] = [:]
        for (index, entry) in entries.enumerated() {
            guard let item = generalNameItem(entry, id: "\(context.id).gn\(index)") else {
                items.append(CertificateExtensionItem(
                    id: "\(context.id).gn\(index)", chineseName: "无法识别的 GeneralName", englishName: "Unknown GeneralName",
                    displayValue: "未识别的标签 [\(entry.identifier.tagNumber)]，原始值 \(entry.encodedBytes.count) 字节",
                    rawValue: Data(entry.encodedBytes)
                ))
                continue
            }
            counts[item.chineseName, default: 0] += 1
            items.append(item)
        }
        let typePrefix = isIssuer ? "颁发者备用名称：" : ""
        let summary: String
        if counts.isEmpty {
            summary = "\(typePrefix)未包含可识别的名称项。"
        } else {
            let breakdown = counts.map { "\($0.key) ×\($0.value)" }.sorted().joined(separator: "、")
            let preview = items.prefix(2).map(\.displayValue).joined(separator: "、")
            summary = "\(typePrefix)\(breakdown)：\(preview)\(items.count > 2 ? " 等" : "")"
        }
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 2.5.29.14 Subject Key Identifier

    private static func subjectKeyIdentifier(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.identifier == .octetString, let bytes = node.primitiveBytes else {
            return malformed(context, reason: "不是 OCTET STRING 结构")
        }
        let keyID = Data(bytes)
        return detail(context, summary: "\(keyID.count) 字节标识符：\(hex(keyID))", items: [
            CertificateExtensionItem(
                id: "\(context.id).keyID", chineseName: "密钥标识符", englishName: "keyIdentifier",
                displayValue: hex(keyID), rawValue: keyID
            )
        ])
    }

    // MARK: - 2.5.29.35 Authority Key Identifier

    private static func authorityKeyIdentifier(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let children = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE 结构")
        }
        var items: [CertificateExtensionItem] = []
        var summaryParts: [String] = []
        for child in children {
            guard child.identifier.tagClass == .contextSpecific else {
                return malformed(context, reason: "出现非上下文标签的字段")
            }
            switch child.identifier.tagNumber {
            case 0:
                guard let bytes = child.primitiveBytes else {
                    return malformed(context, reason: "keyIdentifier 编码异常")
                }
                let keyID = Data(bytes)
                items.append(CertificateExtensionItem(
                    id: "\(context.id).keyID", chineseName: "密钥标识符", englishName: "keyIdentifier",
                    displayValue: hex(keyID), rawValue: keyID
                ))
                summaryParts.append("keyIdentifier \(hex(keyID))")
            case 1:
                guard let issuer = try? DistinguishedNameDecoder.decode(child) else {
                    return malformed(context, reason: "authorityCertIssuer 编码异常")
                }
                items.append(CertificateExtensionItem(
                    id: "\(context.id).issuer", chineseName: "颁发者名称", englishName: "authorityCertIssuer",
                    displayValue: issuer.displayValue
                ))
                summaryParts.append("颁发者 \(issuer.displayValue)")
            case 2:
                guard let serial = integerValue(of: child) else {
                    return malformed(context, reason: "authorityCertSerialNumber 编码异常")
                }
                let serialText = String(serial)
                items.append(CertificateExtensionItem(
                    id: "\(context.id).serial", chineseName: "颁发者证书序列号", englishName: "authorityCertSerialNumber",
                    displayValue: serialText, rawValue: Data(child.primitiveBytes ?? [])
                ))
                summaryParts.append("颁发者序列号 \(serialText)")
            default:
                return malformed(context, reason: "出现未知标签 [\(child.identifier.tagNumber)]")
            }
        }
        let summary = summaryParts.isEmpty ? "未包含任何字段。" : summaryParts.joined(separator: "；")
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 2.5.29.31 CRL Distribution Points

    private static let crlReasons: [(bit: Int, chinese: String, english: String)] = [
        (0, "密钥泄露", "keyCompromise"), (1, "CA 泄露", "caCompromise"),
        (2, "隶属关系变更", "affiliationChanged"), (3, "已被替代", "superseded"),
        (4, "停止运营", "cessationOfOperation"), (6, "证书冻结", "certificateHold")
    ]

    private static func crlDistributionPoints(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let points = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE OF DistributionPoint 结构")
        }
        var items: [CertificateExtensionItem] = []
        var uriCount = 0
        for (pointIndex, point) in points.enumerated() {
            guard point.isConstructed, let fields = point.childNodes else {
                return malformed(context, reason: "第 \(pointIndex + 1) 个分发点不是 SEQUENCE 结构")
            }
            var pointItems: [CertificateExtensionItem] = []
            for field in fields {
                guard field.identifier.tagClass == .contextSpecific else {
                    return malformed(context, reason: "分发点出现非上下文标签")
                }
                switch field.identifier.tagNumber {
                case 0, 2: // distributionPoint / cRLIssuer: [x] EXPLICIT DistributionPointName
                    // [x] -> CHOICE alternative [0] fullName or [1] nameRelativeToCRLIssuer ->
                    // GeneralNames SEQUENCE (or RDN). Only fullName URIs count for the summary.
                    guard let choice = field.childNodes?.first else {
                        return malformed(context, reason: "分发点 [\(field.identifier.tagNumber)] 缺少名称")
                    }
                    switch choice.identifier.tagNumber {
                    case 0: // fullName [0] GeneralNames (also reached for cRLIssuer [2])
                        // RFC 5280 defines these extensions in the implicit-tagging
                        // module: the context tag REPLACES the GeneralNames SEQUENCE
                        // tag, so this node's children are GeneralName entries
                        // directly. Tolerate a redundant SEQUENCE wrapper that some
                        // encoders still emit; raw bytes stay authoritative either way.
                        var entries = choice.childNodes ?? []
                        if entries.count == 1, entries[0].identifier.tagClass == .universal,
                           let inner = entries[0].childNodes,
                           inner.first?.identifier.tagClass == .contextSpecific {
                            entries = inner
                        }
                        guard !entries.isEmpty else {
                            return malformed(context, reason: "分发点名称不是 GeneralNames 结构")
                        }
                        for (nameIndex, entry) in entries.enumerated() {
                            let suffix = field.identifier.tagNumber == 0 ? "" : ".issuer"
                            if let item = generalNameItem(entry, id: "\(context.id).dp\(pointIndex)\(suffix).\(nameIndex)") {
                                if item.englishName == "uniformResourceIdentifier" && field.identifier.tagNumber == 0 {
                                    uriCount += 1
                                }
                                pointItems.append(item)
                            }
                        }
                    case 1: // nameRelativeToCRLIssuer [1] RelativeDistinguishedName (SET OF AttributeTypeAndValue)
                        let parts = (choice.childNodes ?? []).compactMap { attribute -> String? in
                            guard attribute.isConstructed, let pair = attribute.childNodes,
                                  let oidNode = pair.first, let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode) else {
                                return nil
                            }
                            let value = pair.count > 1 ? DistinguishedNameDecoder.attributeValue(of: pair[1]) : nil
                            let shortName = OIDNames.attributeShortNames[oid.description] ?? oid.description
                            return "\(shortName)=\(value ?? "<原始值>")"
                        }
                        pointItems.append(CertificateExtensionItem(
                            id: "\(context.id).dp\(pointIndex).relative",
                            chineseName: "相对 CRL 颁发者的名称", englishName: "nameRelativeToCRLIssuer",
                            displayValue: parts.isEmpty ? "<原始值>" : parts.joined(separator: "+")
                        ))
                    default:
                        return malformed(context, reason: "分发点名称出现未知标签 [\(choice.identifier.tagNumber)]")
                    }
                case 1: // reasons
                    if let bytes = field.primitiveBytes, !bytes.isEmpty {
                        let unusedBits = Int(bytes.first!)
                        let data = Data(bytes.dropFirst())
                        let reasonNames = crlReasons.filter { reason in
                            let byteIndex = reason.bit / 8
                            guard byteIndex < data.count else { return false }
                            return data[data.startIndex + byteIndex] & (1 << (7 - reason.bit % 8)) != 0
                        }.map { "\($0.chinese)（\($0.english)）" }
                        _ = unusedBits
                        pointItems.append(CertificateExtensionItem(
                            id: "\(context.id).dp\(pointIndex).reasons",
                            chineseName: "吊销理由范围", englishName: "reasons",
                            displayValue: reasonNames.isEmpty ? "未声明具体理由" : reasonNames.joined(separator: "、")
                        ))
                    }
                default:
                    return malformed(context, reason: "分发点出现未知标签 [\(field.identifier.tagNumber)]")
                }
            }
            items.append(CertificateExtensionItem(
                id: "\(context.id).dp\(pointIndex)", chineseName: "分发点 \(pointIndex + 1)", englishName: "DistributionPoint",
                displayValue: pointItems.isEmpty ? "（无内容）" : pointItems.map(\.displayValue).joined(separator: "；"),
                children: pointItems
            ))
        }
        let summary = uriCount > 0 ? "共 \(points.count) 个分发点、\(uriCount) 个 URI（本应用不会访问这些地址）。"
            : "共 \(points.count) 个分发点。"
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 1.3.6.1.5.5.7.1.1 Authority Information Access

    private static func authorityInformationAccess(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let accesses = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE OF AccessDescription 结构")
        }
        var items: [CertificateExtensionItem] = []
        var methodCounts: [String] = []
        for (index, access) in accesses.enumerated() {
            guard access.isConstructed, let parts = access.childNodes, parts.count >= 2,
                  let method = try? ASN1ObjectIdentifier(derEncoded: parts[0]) else {
                return malformed(context, reason: "第 \(index + 1) 项不是 AccessDescription 结构")
            }
            let methodNames = OIDNames.accessMethods[method.description] ??
                (chinese: "未注册访问方法", english: "Unknown Access Method")
            guard let location = generalNameItem(parts[1], id: "\(context.id).aia\(index).location") else {
                return malformed(context, reason: "第 \(index + 1) 项访问位置编码异常")
            }
            methodCounts.append(methodNames.english)
            items.append(CertificateExtensionItem(
                id: "\(context.id).aia\(index)", chineseName: methodNames.chinese, englishName: methodNames.english,
                oid: method.description, displayValue: location.displayValue,
                rawValue: location.rawValue,
                children: [location]
            ))
        }
        let counted = Dictionary(grouping: methodCounts, by: { $0 }).map { "\($0.key) ×\($0.value.count)" }.sorted()
        let summary = counted.isEmpty ? "未包含访问描述。"
            : "访问方法：\(counted.joined(separator: "、"))（本应用不会访问这些地址）。"
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 2.5.29.32 Certificate Policies

    private static func certificatePolicies(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let policies = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE OF PolicyInformation 结构")
        }
        var items: [CertificateExtensionItem] = []
        for (index, policy) in policies.enumerated() {
            guard policy.isConstructed, let parts = policy.childNodes, let policyOIDNode = parts.first,
                  let policyOID = try? ASN1ObjectIdentifier(derEncoded: policyOIDNode) else {
                return malformed(context, reason: "第 \(index + 1) 个策略缺少 OBJECT IDENTIFIER")
            }
            var qualifiers: [CertificateExtensionItem] = []
            if parts.count > 1, let qualifierSequence = parts[1].childNodes {
                for (qualifierIndex, qualifier) in qualifierSequence.enumerated() {
                    guard qualifier.isConstructed, let qualifierParts = qualifier.childNodes,
                          qualifierParts.count >= 2,
                          let qualifierOID = try? ASN1ObjectIdentifier(derEncoded: qualifierParts[0]) else {
                        return malformed(context, reason: "第 \(index + 1) 个策略的限定词编码异常")
                    }
                    let names = OIDNames.policyQualifiers[qualifierOID.description] ??
                        (chinese: "未注册限定词", english: "Unknown Qualifier")
                    let valueNode = qualifierParts[1]
                    var valueText = hex(Data(valueNode.encodedBytes))
                    if qualifierOID.description == "1.3.6.1.5.5.7.2.1", let bytes = valueNode.primitiveBytes {
                        valueText = String(decoding: Data(bytes), as: UTF8.self)
                    } else if qualifierOID.description == "1.3.6.1.5.5.7.2.2",
                              let notice = try? noticeText(valueNode) {
                        valueText = notice
                    }
                    qualifiers.append(CertificateExtensionItem(
                        id: "\(context.id).pol\(index).q\(qualifierIndex)",
                        chineseName: names.chinese, englishName: names.english,
                        oid: qualifierOID.description, displayValue: valueText,
                        rawValue: Data(valueNode.encodedBytes)
                    ))
                }
            }
            items.append(CertificateExtensionItem(
                id: "\(context.id).pol\(index)", chineseName: "策略", englishName: "PolicyInformation",
                oid: policyOID.description, displayValue: policyOID.description,
                children: qualifiers
            ))
        }
        return detail(context, summary: "共 \(policies.count) 个策略（OID 见各项）。", items: items)
    }

    private static func noticeText(_ node: ASN1Node) throws -> String? {
        // UserNotice ::= SEQUENCE { noticeRef [0] OPTIONAL, explicitText [1] EXPLICIT OPTIONAL }
        guard let children = node.childNodes else { return nil }
        for child in children where child.identifier.tagNumber == 1 && child.identifier.tagClass == .contextSpecific {
            if let inner = child.childNodes?.first, let text = DistinguishedNameDecoder.attributeValue(of: inner) {
                return text
            }
        }
        return nil
    }

    // MARK: - 2.5.29.30 Name Constraints

    private static func nameConstraints(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed else {
            return malformed(context, reason: "不是 SEQUENCE 结构")
        }
        func subtreeItems(_ node: ASN1Node, idPrefix: String) -> [CertificateExtensionItem] {
            // permitted/excluded are [x] IMPLICIT GeneralSubtrees: the context tag
            // replaces the SEQUENCE tag, so children are GeneralSubtree entries
            // (SEQUENCE { base GeneralName, ... }). Tolerate a redundant SEQUENCE
            // wrapper; GeneralSubtree bases are always context-tagged GeneralNames.
            var entries = node.childNodes ?? []
            while entries.count == 1, entries[0].identifier.tagClass == .universal,
                  entries[0].childNodes?.first?.identifier.tagClass == .universal {
                entries = entries[0].childNodes ?? []
            }
            return entries.enumerated().compactMap { index, subtree in
                guard let base = subtree.childNodes?.first else { return nil }
                return generalNameItem(base, id: "\(idPrefix).\(index)")
            }
        }
        var permitted: [CertificateExtensionItem] = []
        var excluded: [CertificateExtensionItem] = []
        for child in node.childNodes ?? [] {
            guard child.identifier.tagClass == .contextSpecific else {
                return malformed(context, reason: "出现非上下文标签的字段")
            }
            switch child.identifier.tagNumber {
            case 0: permitted = subtreeItems(child, idPrefix: "\(context.id).permitted")
            case 1: excluded = subtreeItems(child, idPrefix: "\(context.id).excluded")
            default: return malformed(context, reason: "出现未知标签 [\(child.identifier.tagNumber)]")
            }
        }
        var items: [CertificateExtensionItem] = []
        if !permitted.isEmpty {
            items.append(CertificateExtensionItem(
                id: "\(context.id).permitted", chineseName: "允许的名称子树", englishName: "permittedSubtrees",
                displayValue: permitted.map(\.displayValue).joined(separator: "；"), children: permitted
            ))
        }
        if !excluded.isEmpty {
            items.append(CertificateExtensionItem(
                id: "\(context.id).excluded", chineseName: "排除的名称子树", englishName: "excludedSubtrees",
                displayValue: excluded.map(\.displayValue).joined(separator: "；"), children: excluded
            ))
        }
        let summary: String
        if permitted.isEmpty && excluded.isEmpty {
            summary = "未包含任何名称约束。"
        } else {
            summary = "允许 \(permitted.count) 项、排除 \(excluded.count) 项。"
        }
        return detail(context, summary: summary, items: items)
    }

    // MARK: - 2.5.29.9 Subject Directory Attributes

    private static func subjectDirectoryAttributes(_ context: ExtensionContext) -> CertificateExtensionDetail {
        guard let node = rawNode(context.rawValue), node.isConstructed, let attributes = node.childNodes else {
            return malformed(context, reason: "不是 SEQUENCE OF Attribute 结构")
        }
        var items: [CertificateExtensionItem] = []
        for (index, attribute) in attributes.enumerated() {
            guard attribute.isConstructed, let parts = attribute.childNodes, parts.count >= 2,
                  let attributeOID = try? ASN1ObjectIdentifier(derEncoded: parts[0]) else {
                return malformed(context, reason: "第 \(index + 1) 个属性缺少 OBJECT IDENTIFIER")
            }
            let values = (parts[1].childNodes ?? []).map { child -> CertificateExtensionItem in
                let text = DistinguishedNameDecoder.attributeValue(of: child) ?? hex(Data(child.encodedBytes))
                return CertificateExtensionItem(
                    id: "\(context.id).attr\(index).\(child.encodedBytes.startIndex)",
                    chineseName: "属性值", englishName: "AttributeValue", displayValue: text,
                    rawValue: Data(child.encodedBytes)
                )
            }
            items.append(CertificateExtensionItem(
                id: "\(context.id).attr\(index)", chineseName: "目录属性", englishName: "Attribute",
                oid: attributeOID.description, displayValue: values.map(\.displayValue).joined(separator: "；"),
                children: values
            ))
        }
        return detail(context, summary: "共 \(attributes.count) 个目录属性。", items: items)
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}
