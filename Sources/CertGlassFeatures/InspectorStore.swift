import CertGlassCore
import Combine
import Foundation

/// One certificate file loaded into the window's collection.
public struct LoadedFileInfo: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let displayName: String?
    public let byteCount: Int

    public init(id: UUID, displayName: String?, byteCount: Int) {
        self.id = id
        self.displayName = displayName
        self.byteCount = byteCount
    }
}

@MainActor
public final class InspectorStore: ObservableObject {
    @Published public private(set) var certificates: [CertificateRecord] = []
    @Published public private(set) var loadedFiles: [LoadedFileInfo] = []
    @Published public private(set) var selectedCertificateID: CertificateID?
    @Published public private(set) var chainReport: ChainReport?
    @Published public private(set) var assessment = TrustAssessment()
    @Published public private(set) var documentError: Diagnostic?
    @Published public private(set) var exportError: Diagnostic?
    @Published public private(set) var isLoadingDocument = false

    public var selectedCertificate: CertificateRecord? {
        certificates.first { $0.id == selectedCertificateID }
    }

    /// Source file of the selected certificate, for the window header.
    public var selectedFileInfo: LoadedFileInfo? {
        guard let id = selectedCertificateID.flatMap({ fileIDByCertificateID[$0] }) else { return nil }
        return loadedFiles.first { $0.id == id }
    }

    private let services: InspectorServices
    private let limits: InputLimits
    private let now: @Sendable () -> Date
    private var operationID = UUID()
    private var fileIDByCertificateID: [CertificateID: UUID] = [:]

    public init(
        services: InspectorServices, limits: InputLimits = .default,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.services = services
        self.limits = limits
        self.now = now
    }

    /// Adds one file's certificates to the window collection. Certificates are
    /// deduplicated across all loaded files by DER SHA-256 identity; an opened
    /// file whose certificates all already exist does not disturb the current
    /// selection. A failed open keeps the existing collection and reports a
    /// document error.
    public func open(_ input: DocumentInput) async {
        let operation = UUID()
        operationID = operation
        documentError = nil
        exportError = nil
        isLoadingDocument = true
        defer {
            if operationID == operation { isLoadingDocument = false }
        }

        do {
            let checkedInput = try DocumentInput(data: input.data, displayName: input.displayName, limits: limits)
            let container = try await services.containerDecoder.decode(checkedInput)
            try Task.checkCancellation()
            guard operationID == operation else { return }
            guard !container.certificatesDER.isEmpty else { throw CertGlassError.noCertificates }
            guard container.certificatesDER.count <= limits.maximumCertificates else {
                throw CertGlassError.tooManyCertificates(maximumCount: limits.maximumCertificates)
            }

            var parsed: [CertificateRecord] = []
            var seenInFile: Set<CertificateID> = []
            for der in container.certificatesDER {
                let record = try await services.certificateParser.parse(der: der)
                try Task.checkCancellation()
                guard operationID == operation else { return }
                if seenInFile.insert(record.id).inserted { parsed.append(record) }
            }

            let file = LoadedFileInfo(
                id: UUID(), displayName: checkedInput.displayName, byteCount: checkedInput.data.count
            )
            var knownIDs = Set(certificates.map(\.id))
            var added: [CertificateRecord] = []
            for record in parsed where knownIDs.insert(record.id).inserted {
                added.append(record)
            }
            certificates += added
            loadedFiles.append(file)
            for record in added { fileIDByCertificateID[record.id] = file.id }
            isLoadingDocument = false

            // Some CA-issued SM2 certificates used as the inspected leaf also
            // declare CA=true, so CA status alone cannot identify the leaf.
            // Prefer a non-self-issued certificate before falling back to the
            // first decoded item; this keeps a root-first PKCS#7 in the right
            // inspection context without changing the supplied certificate set.
            let selected = added.first(where: { $0.caStatus == .endEntity })
                ?? added.first(where: { record in
                    guard let subject = record.subject, let issuer = record.issuer else { return false }
                    return subject.displayValue != issuer.displayValue
                })
                ?? added.first
            guard let selected else { return }
            selectedCertificateID = selected.id
            await evaluate(selected, operation: operation)
        } catch is CancellationError {
            // A cancelled or superseded open must not publish an error.
        } catch {
            guard operationID == operation else { return }
            documentError = diagnostic(for: error, fallbackCode: .invalidInput)
        }
    }

    /// Reads a file URL (open panel, Finder open-with or drag & drop) and adds
    /// it to the collection.
    public func openFile(at url: URL) async {
        do {
            let data = try await Task.detached(priority: .userInitiated) { try Data(contentsOf: url) }.value
            await open(try DocumentInput(data: data, displayName: url.lastPathComponent, limits: limits))
        } catch {
            documentError = diagnostic(for: error, fallbackCode: .invalidInput)
        }
    }

    public func selectCertificate(_ id: CertificateID) async {
        guard let certificate = certificates.first(where: { $0.id == id }) else { return }
        let operation = UUID()
        operationID = operation
        selectedCertificateID = id
        await evaluate(certificate, operation: operation)
    }

    /// Opens the standard system certificate viewer for the record (read-only).
    public func showCertificateViewer(for id: CertificateID) {
        guard let certificate = certificates.first(where: { $0.id == id }) else { return }
        services.certificateViewer.showCertificate(der: certificate.der)
    }

    /// Encodes the currently selected certificate; writing the file belongs to the caller.
    public func exportSelectedCertificate(as format: CertificateExportFormat) async -> Data? {
        exportError = nil
        guard let certificate = selectedCertificate else { return nil }
        do {
            return try await services.certificateExporter.encode(certificate, as: format)
        } catch {
            let nsError = error as NSError
            exportError = Diagnostic(
                code: .exportFailed, source: .application, severity: .error,
                message: error.localizedDescription,
                systemError: SystemErrorDetail(
                    domain: nsError.domain, code: nsError.code, description: nsError.localizedDescription
                )
            )
            return nil
        }
    }

    private func evaluate(_ certificate: CertificateRecord, operation: UUID) async {
        let time = now()
        let context = TrustContext(verificationTime: time)
        let request = TrustRequest(
            selectedCertificateDER: certificate.der,
            additionalCertificatesDER: certificates.filter { $0.id != certificate.id }.map(\.der),
            verificationTime: time
        )
        chainReport = nil
        assessment = TrustAssessment(executionState: .running, context: context)
        do {
            let result = try await services.trustEvaluator.evaluate(request)
            try Task.checkCancellation()
            guard operationID == operation else { return }
            chainReport = result
            assessment = result.assessment
        } catch is CancellationError {
            guard operationID == operation else { return }
            assessment = TrustAssessment(context: context)
        } catch {
            guard operationID == operation else { return }
            assessment = TrustAssessment(
                executionState: .failed,
                diagnostics: [diagnostic(for: error, fallbackCode: .evaluationFailed)], context: context
            )
        }
    }

    public func clearExportError() { exportError = nil }

    public func reportExportFailure(_ diagnostic: Diagnostic) { exportError = diagnostic }

    private func diagnostic(for error: any Error, fallbackCode: DiagnosticCode) -> Diagnostic {
        let nsError = error as NSError
        let code: DiagnosticCode
        switch error as? CertGlassError {
        case .notImplemented: code = .notImplemented
        case .privateKeyPEM: code = .privateKey
        case .malformedPEMBase64: code = .malformedBase64
        case .truncatedPEM: code = .truncatedPEM
        case .malformedDER: code = .malformedDER
        case .unsupportedContainer: code = .unsupportedContainer
        case .some, .none: code = fallbackCode
        }
        return Diagnostic(
            code: code, source: .application, severity: .error,
            message: error.localizedDescription,
            systemError: SystemErrorDetail(domain: nsError.domain, code: nsError.code, description: nsError.localizedDescription)
        )
    }
}
