import Foundation

public enum ContainerFormat: String, Sendable {
    case der, pem, pkcs7DER, pkcs7PEM
    /// Header-less Base64 text (common for Windows exports and some CA portals).
    case base64DER, base64PKCS7
}

public struct DecodedContainer: Sendable, Equatable {
    public let format: ContainerFormat
    /// Unmodified certificate DER, with original encounter order preserved.
    public let certificatesDER: [Data]

    public init(format: ContainerFormat, certificatesDER: [Data]) {
        self.format = format
        self.certificatesDER = certificatesDER
    }
}

public protocol ContainerDecoding: Sendable {
    func decode(_ input: DocumentInput) async throws -> DecodedContainer
}

public protocol CertificateParsing: Sendable {
    /// Unsupported algorithms should yield partial records when structure is valid.
    func parse(der: Data) async throws -> CertificateRecord
}

public protocol TrustEvaluating: Sendable {
    /// Return completed/untrusted for policy rejection; throw for execution failures.
    func evaluate(_ request: TrustRequest) async throws -> ChainReport
}

public enum CertificateExportFormat: String, Sendable { case der, pem }

public protocol CertificateExporting: Sendable {
    /// Encode public certificate bytes only. Choosing/writing a destination belongs to the app.
    func encode(_ certificate: CertificateRecord, as format: CertificateExportFormat) async throws -> Data
}

/// Shows the standard system certificate viewer (the panel used by Keychain
/// Access) for raw DER. Display only; never installs or modifies keychain items.
public protocol CertificateViewing: Sendable {
    @MainActor func showCertificate(der: Data)
}

public struct InspectorServices: Sendable {
    public let containerDecoder: any ContainerDecoding
    public let certificateParser: any CertificateParsing
    public let trustEvaluator: any TrustEvaluating
    public let certificateExporter: any CertificateExporting
    public let certificateViewer: any CertificateViewing

    public init(
        containerDecoder: any ContainerDecoding, certificateParser: any CertificateParsing,
        trustEvaluator: any TrustEvaluating, certificateExporter: any CertificateExporting,
        certificateViewer: any CertificateViewing
    ) {
        self.containerDecoder = containerDecoder
        self.certificateParser = certificateParser
        self.trustEvaluator = trustEvaluator
        self.certificateExporter = certificateExporter
        self.certificateViewer = certificateViewer
    }
}
