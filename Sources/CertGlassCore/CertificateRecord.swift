import CryptoKit
import Foundation

public struct CertificateID: Hashable, Sendable {
    public let sha256: String

    public init(der: Data) {
        self.sha256 = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }
}

public enum ParseStatus: String, Sendable { case complete, partial }
public enum CAStatus: String, Sendable { case certificateAuthority, endEntity, unknown }

public struct NameAttribute: Sendable, Equatable {
    public let oid: String
    public let value: String?
    public let rawDER: Data

    public init(oid: String, value: String?, rawDER: Data) {
        self.oid = oid
        self.value = value
        self.rawDER = rawDER
    }
}

public struct DistinguishedName: Sendable, Equatable {
    /// Preserve RDN order, duplicate attributes and multi-valued RDNs.
    public let relativeDistinguishedNames: [[NameAttribute]]
    public let displayValue: String

    public init(relativeDistinguishedNames: [[NameAttribute]], displayValue: String) {
        self.relativeDistinguishedNames = relativeDistinguishedNames
        self.displayValue = displayValue
    }
}

public struct AlgorithmIdentifier: Sendable, Equatable {
    public let oid: String
    public let parametersDER: Data?

    public init(oid: String, parametersDER: Data? = nil) {
        self.oid = oid
        self.parametersDER = parametersDER
    }
}

public struct CertificateExtension: Sendable, Equatable {
    public let oid: String
    public let critical: Bool
    /// Original extnValue contents; do not re-encode for export or fingerprints.
    public let rawValue: Data

    public init(oid: String, critical: Bool, rawValue: Data) {
        self.oid = oid
        self.critical = critical
        self.rawValue = rawValue
    }
}

public struct CertificateField: Identifiable, Sendable, Equatable {
    /// A stable field path, including an index when an OID occurs more than once.
    public let id: String
    public let chineseName: String
    public let englishName: String
    public let oid: String?
    public let critical: Bool?
    public let displayValue: String
    public let rawValue: Data?

    public init(
        id: String, chineseName: String, englishName: String, oid: String? = nil,
        critical: Bool? = nil, displayValue: String, rawValue: Data? = nil
    ) {
        self.id = id
        self.chineseName = chineseName
        self.englishName = englishName
        self.oid = oid
        self.critical = critical
        self.displayValue = displayValue
        self.rawValue = rawValue
    }
}

public struct CertificateRecord: Identifiable, Sendable, Equatable {
    public let id: CertificateID
    public let der: Data
    public let subject: DistinguishedName?
    public let issuer: DistinguishedName?
    public let serialNumber: Data?
    public let notValidBefore: Date?
    public let notValidAfter: Date?
    public let publicKeyAlgorithm: AlgorithmIdentifier?
    public let signatureAlgorithm: AlgorithmIdentifier?
    public let publicKeyBytes: Data?
    public let signatureBytes: Data?
    public let extensions: [CertificateExtension]
    /// Structured interpretation, one entry per extension in encounter order.
    public let extensionDetails: [CertificateExtensionDetail]
    public let fields: [CertificateField]
    public let parseStatus: ParseStatus
    public let caStatus: CAStatus
    public let diagnostics: [Diagnostic]

    public init(
        der: Data, subject: DistinguishedName? = nil, issuer: DistinguishedName? = nil,
        serialNumber: Data? = nil, notValidBefore: Date? = nil, notValidAfter: Date? = nil,
        publicKeyAlgorithm: AlgorithmIdentifier? = nil, signatureAlgorithm: AlgorithmIdentifier? = nil,
        publicKeyBytes: Data? = nil, signatureBytes: Data? = nil,
        extensions: [CertificateExtension] = [], extensionDetails: [CertificateExtensionDetail] = [],
        fields: [CertificateField] = [],
        parseStatus: ParseStatus = .partial, caStatus: CAStatus = .unknown,
        diagnostics: [Diagnostic] = []
    ) {
        self.id = CertificateID(der: der)
        self.der = der
        self.subject = subject
        self.issuer = issuer
        self.serialNumber = serialNumber
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
        self.publicKeyAlgorithm = publicKeyAlgorithm
        self.signatureAlgorithm = signatureAlgorithm
        self.publicKeyBytes = publicKeyBytes
        self.signatureBytes = signatureBytes
        self.extensions = extensions
        self.extensionDetails = extensionDetails
        self.fields = fields
        self.parseStatus = parseStatus
        self.caStatus = caStatus
        self.diagnostics = diagnostics
    }
}
