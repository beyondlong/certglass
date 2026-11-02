import Foundation

/// Interpretation outcome for one certificate extension. The raw extnValue
/// bytes stay authoritative regardless of the status.
public enum ExtensionInterpretationStatus: String, Sendable, Equatable {
    /// The application decoded the extension and offers structured items.
    case interpreted
    /// Unknown or unsupported OID: only raw bytes and a generic DER digest.
    case rawOnly
    /// The extension is known but its encoding could not be decoded; raw bytes preserved.
    case malformed
}

/// Tag class and structure of one ASN.1 node, for read-only DER summaries.
public enum ASN1SummaryTagClass: String, Sendable, Equatable {
    case universal, application, contextSpecific, privateClass
}

/// A display-oriented ASN.1 node summary. Deliberately free of SwiftASN1,
/// Security or SwiftUI types so it can cross module and concurrency boundaries.
public struct ASN1SummaryNode: Sendable, Equatable {
    public let tagClass: ASN1SummaryTagClass
    public let tagNumber: Int
    public let constructed: Bool
    /// Encoded length in bytes: content plus header, as encountered.
    public let totalLength: Int
    /// Optional human-readable primitive value (hex for opaque bytes).
    public let displayValue: String?
    public let children: [ASN1SummaryNode]

    public init(
        tagClass: ASN1SummaryTagClass, tagNumber: Int, constructed: Bool, totalLength: Int,
        displayValue: String? = nil, children: [ASN1SummaryNode] = []
    ) {
        self.tagClass = tagClass
        self.tagNumber = tagNumber
        self.constructed = constructed
        self.totalLength = totalLength
        self.displayValue = displayValue
        self.children = children
    }
}

/// One structured line inside a decoded extension; items nest to form a tree.
public struct CertificateExtensionItem: Identifiable, Sendable, Equatable {
    public let id: String
    public let chineseName: String
    public let englishName: String
    public let oid: String?
    public let displayValue: String
    public let rawValue: Data?
    public let children: [CertificateExtensionItem]

    public init(
        id: String, chineseName: String, englishName: String, oid: String? = nil,
        displayValue: String, rawValue: Data? = nil, children: [CertificateExtensionItem] = []
    ) {
        self.id = id
        self.chineseName = chineseName
        self.englishName = englishName
        self.oid = oid
        self.displayValue = displayValue
        self.rawValue = rawValue
        self.children = children
    }
}

/// Structured Chinese-language interpretation of one extension occurrence.
/// Display data only; it never changes trust conclusions.
public struct CertificateExtensionDetail: Identifiable, Sendable, Equatable {
    /// Stable path: OID plus occurrence index when an OID appears more than once.
    public let id: String
    public let oid: String
    public let chineseName: String
    public let englishName: String
    public let critical: Bool
    /// Short one-line summary, also used as the extension field display value.
    public let summary: String
    public let interpretationStatus: ExtensionInterpretationStatus
    /// Whether the OID belongs to a publicly standardized extension arc
    /// (X.509 `2.5.29.*` or PKIX `1.3.6.1.5.5.7.1.*`), regardless of whether
    /// this application implements an interpretation for it.
    public let isPublicStandard: Bool
    public let items: [CertificateExtensionItem]
    /// Original extnValue content bytes; never re-encoded or truncated.
    public let rawValue: Data
    /// Generic DER digest of the raw value, or nil when it is not decodable DER.
    public let rawDERTree: ASN1SummaryNode?

    public init(
        id: String, oid: String, chineseName: String, englishName: String, critical: Bool,
        summary: String, interpretationStatus: ExtensionInterpretationStatus,
        isPublicStandard: Bool = false,
        items: [CertificateExtensionItem], rawValue: Data, rawDERTree: ASN1SummaryNode? = nil
    ) {
        self.id = id
        self.oid = oid
        self.chineseName = chineseName
        self.englishName = englishName
        self.critical = critical
        self.summary = summary
        self.interpretationStatus = interpretationStatus
        self.isPublicStandard = isPublicStandard
        self.items = items
        self.rawValue = rawValue
        self.rawDERTree = rawDERTree
    }
}
