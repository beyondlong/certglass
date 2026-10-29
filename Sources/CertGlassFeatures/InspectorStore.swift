import CertGlassCore
import Combine
import Foundation

@MainActor
public final class InspectorStore: ObservableObject {
    @Published public private(set) var certificates: [CertificateRecord] = []
    @Published public private(set) var selectedCertificateID: CertificateID?
    @Published public private(set) var chainReport: ChainReport?
    @Published public private(set) var assessment = TrustAssessment()
    @Published public private(set) var documentError: Diagnostic?
    @Published public private(set) var isLoadingDocument = false

    public var selectedCertificate: CertificateRecord? {
        certificates.first { $0.id == selectedCertificateID }
    }

    private let services: InspectorServices
    private let limits: InputLimits
    private let now: @Sendable () -> Date
    private var operationID = UUID()

    public init(
        services: InspectorServices, limits: InputLimits = .default,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.services = services
        self.limits = limits
        self.now = now
    }

    public func open(_ input: DocumentInput) async {
        let operation = UUID()
        operationID = operation
        certificates = []
        selectedCertificateID = nil
        chainReport = nil
        assessment = TrustAssessment()
        documentError = nil
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

            var records: [CertificateRecord] = []
            var seen: Set<CertificateID> = []
            for der in container.certificatesDER {
                let record = try await services.certificateParser.parse(der: der)
                try Task.checkCancellation()
                guard operationID == operation else { return }
                if seen.insert(record.id).inserted { records.append(record) }
            }
            certificates = records
            isLoadingDocument = false
            if let selected = records.first(where: { $0.caStatus == .endEntity }) ?? records.first {
                selectedCertificateID = selected.id
                await evaluate(selected, operation: operation)
            }
        } catch is CancellationError {
            // A cancelled or superseded view must not publish an error for a new document.
        } catch {
            guard operationID == operation else { return }
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

    private func diagnostic(for error: any Error, fallbackCode: DiagnosticCode) -> Diagnostic {
        let nsError = error as NSError
        let code: DiagnosticCode
        if case .notImplemented = error as? CertGlassError {
            code = .notImplemented
        } else if error is CertGlassError {
            code = .invalidInput
        } else {
            code = fallbackCode
        }
        return Diagnostic(
            code: code, source: .application, severity: .error,
            message: error.localizedDescription,
            systemError: SystemErrorDetail(domain: nsError.domain, code: nsError.code, description: nsError.localizedDescription)
        )
    }
}
