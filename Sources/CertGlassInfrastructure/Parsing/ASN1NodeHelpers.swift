import CertGlassCore
import Foundation
import SwiftASN1

/// Lenient signed big-endian INTEGER decode for display; no minimal-encoding
/// enforcement (an over-encoded integer still shows its value).
enum DERInteger {
    static func value(of node: ASN1Node) -> Int? {
        guard let bytes = node.primitiveBytes, !bytes.isEmpty, bytes.count <= 7 else { return nil }
        var value = 0
        for byte in bytes { value = value << 8 | Int(byte) }
        if bytes.first! & 0x80 != 0 { value -= 1 << (bytes.count * 8) }
        return value
    }
}

extension ASN1Node {
    var isConstructed: Bool {
        if case .constructed = content { return true }
        return false
    }

    var primitiveBytes: ArraySlice<UInt8>? {
        if case .primitive(let bytes) = content { return bytes }
        return nil
    }

    var childNodes: [ASN1Node]? {
        if case .constructed(let collection) = content { return Array(collection) }
        return nil
    }
}

/// Shared X.509 Name (RDN sequence) decoding used by TBS fields and
/// directoryName GeneralNames.
enum DistinguishedNameDecoder {
    static func decode(_ node: ASN1Node?) throws -> CertGlassCore.DistinguishedName {
        guard let node, node.isConstructed, let rdns = node.childNodes else {
            throw CertGlassError.malformedDER
        }
        var parsed: [[NameAttribute]] = []
        var displayParts: [String] = []
        for rdn in rdns {
            guard rdn.isConstructed, let attributes = rdn.childNodes else {
                throw CertGlassError.malformedDER
            }
            var rdnAttributes: [NameAttribute] = []
            var rdnDisplayParts: [String] = []
            for attribute in attributes {
                guard attribute.isConstructed, let parts = attribute.childNodes, let oidNode = parts.first else {
                    throw CertGlassError.malformedDER
                }
                let oid = try ASN1ObjectIdentifier(derEncoded: oidNode)
                let valueNode = parts.count > 1 ? parts[1] : nil
                let value = valueNode.flatMap(attributeValue(of:))
                rdnAttributes.append(NameAttribute(
                    oid: oid.description, value: value,
                    rawDER: Data(valueNode?.encodedBytes ?? [])
                ))
                let shortName = OIDNames.attributeShortNames[oid.description] ?? oid.description
                rdnDisplayParts.append("\(shortName)=\(value ?? "<原始值>")")
            }
            parsed.append(rdnAttributes)
            displayParts.append(rdnDisplayParts.joined(separator: "+"))
        }
        return DistinguishedName(relativeDistinguishedNames: parsed, displayValue: displayParts.joined(separator: ", "))
    }

    static func attributeValue(of node: ASN1Node) -> String? {
        guard node.identifier.tagClass == .universal, let bytes = node.primitiveBytes else { return nil }
        let data = Data(bytes)
        switch node.identifier.tagNumber {
        case 12, 19, 22, 26, 18: // UTF8, Printable, IA5, Visible, Numeric
            return String(decoding: data, as: UTF8.self)
        case 20: // TeletextString uses Latin-1 in practice
            return String(String.UnicodeScalarView(data.map { UnicodeScalar($0) }))
        case 30: // BMPString: UTF-16 big endian
            var units: [UInt16] = []
            var iterator = bytes.makeIterator()
            while let high = iterator.next(), let low = iterator.next() {
                units.append(UInt16(high) << 8 | UInt16(low))
            }
            return String(decoding: units, as: UTF16.self)
        case 28: // UniversalString: UTF-32 big endian
            var units: [UInt32] = []
            var iterator = bytes.makeIterator()
            while let a = iterator.next(), let b = iterator.next(), let c = iterator.next(), let d = iterator.next() {
                units.append(UInt32(a) << 24 | UInt32(b) << 16 | UInt32(c) << 8 | UInt32(d))
            }
            return String(decoding: units, as: UTF32.self)
        default:
            return nil
        }
    }
}

/// Builds a bounded read-only ASN.1 summary tree for display. It never
/// interprets semantics and caps node count and depth so pathological
/// encodings cannot blow up the UI.
enum ASN1SummaryBuilder {
    static let maxNodes = 256
    static let maxDepth = 12

    static func digest(_ data: Data) -> ASN1SummaryNode? {
        guard let bytes = [UInt8](data).first, bytes != 0x00, bytes != 0xFF,
              let root = try? DER.parse([UInt8](data)) else { return nil }
        var budget = maxNodes
        return node(root, depth: 0, budget: &budget)
    }

    private static func node(_ asn1: ASN1Node, depth: Int, budget: inout Int) -> ASN1SummaryNode? {
        guard depth <= maxDepth, budget > 0 else { return nil }
        budget -= 1
        let children: [ASN1SummaryNode]
        if let asn1Children = asn1.childNodes, depth < maxDepth {
            var childBudget = budget
            children = asn1Children.prefix(childBudget).compactMap { child in
                node(child, depth: depth + 1, budget: &childBudget)
            }
            budget = childBudget
        } else {
            children = []
        }
        return ASN1SummaryNode(
            tagClass: tagClass(asn1.identifier.tagClass),
            tagNumber: Int(asn1.identifier.tagNumber),
            constructed: asn1.isConstructed,
            totalLength: asn1.encodedBytes.count,
            displayValue: displayValue(of: asn1),
            children: children
        )
    }

    private static func tagClass(_ raw: ASN1Identifier.TagClass) -> ASN1SummaryTagClass {
        switch raw {
        case .universal: .universal
        case .application: .application
        case .contextSpecific: .contextSpecific
        case .private: .privateClass
        }
    }

    private static func displayValue(of node: ASN1Node) -> String? {
        guard let bytes = node.primitiveBytes else { return nil }
        let data = Data(bytes)
        switch node.identifier.tagNumber {
        case 6:
            return (try? ASN1ObjectIdentifier(derEncoded: node))?.description
        case 2:
            return DERInteger.value(of: node).map(String.init)
        case 12, 19, 22, 26, 18, 20, 30, 28:
            return DistinguishedNameDecoder.attributeValue(of: node)
        default:
            guard !data.isEmpty, data.count <= 24 else { return nil }
            return data.map { String(format: "%02x", $0) }.joined(separator: " ")
        }
    }
}
