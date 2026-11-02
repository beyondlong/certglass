import CertGlassCore
import CertGlassFeatures
import CertGlassInfrastructure
import Foundation
import Testing

@MainActor
struct InspectorStoreTests {
    @Test func opensParsedCertificatesAndUsesOfflineRequest() async throws {
        let firstDER = Data([1]), leafDER = Data([2])
        let evaluator = RecordingEvaluator(result: .success(ChainReport(
            assessment: TrustAssessment(executionState: .completed, systemConclusion: .untrusted)
        )))
        let fixedTime = Date(timeIntervalSince1970: 1_700_000_000)
        let store = makeStore(blocks: [firstDER, leafDER, leafDER], evaluator: evaluator, now: { fixedTime })
        await store.open(try DocumentInput(data: Data([9])))

        #expect(store.certificates.map(\.der) == [firstDER, leafDER])
        #expect(store.selectedCertificate?.der == leafDER)
        #expect(store.assessment.systemConclusion == .untrusted)
        let requests = await evaluator.requests
        #expect(requests.count == 1)
        #expect(requests.first?.selectedCertificateDER == leafDER)
        #expect(requests.first?.additionalCertificatesDER == [firstDER])
        #expect(requests.first?.verificationTime == fixedTime)
        #expect(requests.first?.policy == .basicX509)
    }

    @Test func trustExecutionFailurePreservesParsedCertificates() async throws {
        let store = makeStore(blocks: [Data([2])], evaluator: RecordingEvaluator(
            result: .failure(.notImplemented(feature: "测试信任实现"))
        ))
        await store.open(try DocumentInput(data: Data([9])))
        #expect(store.certificates.count == 1)
        #expect(store.selectedCertificate != nil)
        #expect(store.assessment.executionState == .failed)
        #expect(store.assessment.systemConclusion == .undetermined)
        #expect(store.assessment.context?.networkFetchDisabled == nil)
        #expect(store.assessment.diagnostics.first?.code == .notImplemented)
        #expect(store.assessment.diagnostics.first?.source == .application)
        #expect(store.documentError == nil)
    }

    @Test func invalidDERReportsDocumentErrorWithoutFakeCertificates() async throws {
        let store = InspectorStore(services: ScaffoldServices.make())
        await store.open(try DocumentInput(data: Data([0x30, 0])))
        #expect(store.certificates.isEmpty)
        #expect(store.chainReport == nil)
        #expect(store.assessment.systemConclusion == .undetermined)
        #expect(store.documentError?.code == .malformedDER)
        #expect(!store.isLoadingDocument)
    }

    @Test func collectionLimitIsCheckedBeforeParsing() async throws {
        let store = makeStore(
            blocks: [Data([1]), Data([2])],
            evaluator: RecordingEvaluator(result: .success(ChainReport())),
            limits: InputLimits(maximumFileBytes: 10, maximumCertificates: 1)
        )
        await store.open(try DocumentInput(data: Data([9])))
        #expect(store.certificates.isEmpty)
        #expect(store.documentError?.code == .invalidInput)
    }

    @Test func unknownCAStatusIsNotPreferredAsEndEntity() async throws {
        let store = makeStore(
            blocks: [Data([1]), Data([3])],
            evaluator: RecordingEvaluator(result: .success(ChainReport()))
        )
        await store.open(try DocumentInput(data: Data([9])))
        #expect(store.selectedCertificate?.der == Data([1]))
    }

    @Test func emptyDecodedCollectionIsAnInputError() async throws {
        let store = makeStore(blocks: [], evaluator: RecordingEvaluator(result: .success(ChainReport())))
        await store.open(try DocumentInput(data: Data([9])))
        #expect(store.documentError?.code == .invalidInput)
        #expect(store.certificates.isEmpty)
    }

    @Test func parserFailureIsDocumentErrorNotTrustFailure() async throws {
        let store = InspectorStore(services: InspectorServices(
            containerDecoder: FixedDecoder(blocks: [Data([1])]),
            certificateParser: FailingParser(),
            trustEvaluator: RecordingEvaluator(result: .success(ChainReport())),
            certificateExporter: StandardCertificateExporter(), certificateViewer: StandardCertificateViewer()
        ))
        await store.open(try DocumentInput(data: Data([9])))
        #expect(store.documentError?.code == .invalidInput)
        #expect(store.documentError?.systemError?.domain == "CertGlass.ParserFixture")
        #expect(store.assessment.executionState == .notStarted)
        #expect(store.certificates.isEmpty)
    }

    @Test func olderTrustResultCannotReplaceNewSelection() async throws {
        let evaluator = GatedEvaluator()
        let store = makeStore(blocks: [Data([1]), Data([2])], evaluator: evaluator)
        let input = try DocumentInput(data: Data([9]))
        let opening = Task { await store.open(input) }
        await evaluator.waitForRequest(Data([2]))
        let otherID = try #require(store.certificates.first?.id)
        let selecting = Task { await store.selectCertificate(otherID) }
        await evaluator.waitForRequest(Data([1]))

        await evaluator.finish(Data([1]), conclusion: .untrusted)
        await selecting.value
        await evaluator.finish(Data([2]), conclusion: .trusted)
        await opening.value

        #expect(store.selectedCertificate?.der == Data([1]))
        #expect(store.assessment.systemConclusion == .untrusted)
    }

    @Test func openingMoreFilesAccumulatesIntoOneCollection() async throws {
        let store = InspectorStore(services: InspectorServices(
            containerDecoder: MultiFileDecoder(files: [
                Data([9]): [Data([1]), Data([2])],
                Data([8]): [Data([2]), Data([3])]
            ]),
            certificateParser: FixtureParser(),
            trustEvaluator: RecordingEvaluator(result: .success(ChainReport())),
            certificateExporter: StandardCertificateExporter(), certificateViewer: StandardCertificateViewer()
        ))
        await store.open(try DocumentInput(data: Data([9])))
        await store.open(try DocumentInput(data: Data([8])))

        #expect(store.certificates.map(\.der) == [Data([1]), Data([2]), Data([3])])
        #expect(store.loadedFiles.count == 2)
        #expect(store.selectedCertificate?.der == Data([3]))
        #expect(store.selectedFileInfo?.byteCount == 1)
        #expect(store.documentError == nil)
    }

    @Test func failedOpenKeepsExistingCollection() async throws {
        let store = InspectorStore(services: InspectorServices(
            containerDecoder: MultiFileDecoder(files: [
                Data([9]): [Data([1])],
                Data([8]): []
            ]),
            certificateParser: FixtureParser(),
            trustEvaluator: RecordingEvaluator(result: .success(ChainReport())),
            certificateExporter: StandardCertificateExporter(), certificateViewer: StandardCertificateViewer()
        ))
        await store.open(try DocumentInput(data: Data([9])))
        await store.open(try DocumentInput(data: Data([8])))

        #expect(store.documentError?.code == .invalidInput)
        #expect(store.certificates.map(\.der) == [Data([1])])
        #expect(store.loadedFiles.count == 1)
        #expect(store.selectedCertificate?.der == Data([1]))
    }

    private func makeStore(
        blocks: [Data], evaluator: any TrustEvaluating,
        limits: InputLimits = .default, now: @escaping @Sendable () -> Date = { Date() }
    ) -> InspectorStore {
        InspectorStore(services: InspectorServices(
            containerDecoder: FixedDecoder(blocks: blocks), certificateParser: FixtureParser(),
            trustEvaluator: evaluator, certificateExporter: StandardCertificateExporter(), certificateViewer: StandardCertificateViewer()
        ), limits: limits, now: now)
    }
}

private struct FixedDecoder: ContainerDecoding {
    let blocks: [Data]
    func decode(_ input: DocumentInput) async throws -> DecodedContainer {
        DecodedContainer(format: .pem, certificatesDER: blocks)
    }
}

private struct MultiFileDecoder: ContainerDecoding {
    let files: [Data: [Data]]
    func decode(_ input: DocumentInput) async throws -> DecodedContainer {
        DecodedContainer(format: .pem, certificatesDER: files[input.data] ?? [])
    }
}

private struct FixtureParser: CertificateParsing {
    func parse(der: Data) async throws -> CertificateRecord {
        // Synthetic identity fixtures only; no real parser or signature verification.
        CertificateRecord(der: der, caStatus: der == Data([2]) ? .endEntity :
            (der == Data([1]) ? .certificateAuthority : .unknown))
    }
}

private struct FailingParser: CertificateParsing {
    func parse(der: Data) async throws -> CertificateRecord {
        throw NSError(domain: "CertGlass.ParserFixture", code: 1)
    }
}

private actor RecordingEvaluator: TrustEvaluating {
    private(set) var requests: [TrustRequest] = []
    let result: Result<ChainReport, CertGlassError>
    init(result: Result<ChainReport, CertGlassError>) { self.result = result }
    func evaluate(_ request: TrustRequest) async throws -> ChainReport {
        requests.append(request)
        return try result.get()
    }
}

private actor GatedEvaluator: TrustEvaluating {
    private var pending: [Data: CheckedContinuation<ChainReport, any Error>] = [:]
    private var observers: [Data: CheckedContinuation<Void, Never>] = [:]

    func evaluate(_ request: TrustRequest) async throws -> ChainReport {
        try await withCheckedThrowingContinuation { continuation in
            pending[request.selectedCertificateDER] = continuation
            observers.removeValue(forKey: request.selectedCertificateDER)?.resume()
        }
    }

    func waitForRequest(_ der: Data) async {
        if pending[der] != nil { return }
        await withCheckedContinuation { observers[der] = $0 }
    }

    func finish(_ der: Data, conclusion: SystemTrustConclusion) {
        pending.removeValue(forKey: der)?.resume(returning: ChainReport(assessment: TrustAssessment(
            executionState: .completed, systemConclusion: conclusion
        )))
    }
}
