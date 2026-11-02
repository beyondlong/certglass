import Foundation

public enum DiagnosticSource: String, Sendable { case parser, systemTrust, application }
public enum DiagnosticSeverity: String, Sendable { case information, warning, error }
public enum DiagnosticCode: String, Sendable {
    case notImplemented, partialParse, expired, notYetValid, unknownRoot, incompleteChain
    case untrustedSelfSigned, invalidSignature, unsupportedAlgorithm, unhandledCriticalExtension
    case revoked, systemError, evaluationFailed, invalidInput
    case privateKey, malformedBase64, truncatedPEM, malformedDER, unsupportedContainer
    case exportFailed
}

public struct SystemErrorDetail: Sendable, Equatable {
    public let domain: String
    public let code: Int
    public let description: String
    public let underlyingErrors: [SystemErrorDetail]

    public init(domain: String, code: Int, description: String, underlyingErrors: [SystemErrorDetail] = []) {
        self.domain = domain
        self.code = code
        self.description = description
        self.underlyingErrors = underlyingErrors
    }
}

public struct Diagnostic: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let code: DiagnosticCode
    public let source: DiagnosticSource
    public let severity: DiagnosticSeverity
    public let message: String
    public let certificateID: CertificateID?
    public let fieldOID: String?
    public let systemError: SystemErrorDetail?

    public init(
        id: UUID = UUID(), code: DiagnosticCode, source: DiagnosticSource,
        severity: DiagnosticSeverity, message: String, certificateID: CertificateID? = nil,
        fieldOID: String? = nil, systemError: SystemErrorDetail? = nil
    ) {
        self.id = id
        self.code = code
        self.source = source
        self.severity = severity
        self.message = message
        self.certificateID = certificateID
        self.fieldOID = fieldOID
        self.systemError = systemError
    }
}
