import CertGlassCore
import CertGlassInfrastructure
import Foundation
import Security
import Testing

struct TrustEvaluatorTests {
    // 2026-11-15T00:00:00Z — inside the trust fixture validity (2026-10-29 → 2036),
    // after the expired fixture and before the future fixture. Time stays fixed per test policy.
    private let fixedTime = Date(timeIntervalSince1970: 1_794_700_800)

    private func der(_ name: String) throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent(name)
        return try Data(contentsOf: url)
    }

    private func evaluator(isolatingAnchors anchors: [Data]) -> StandardTrustEvaluator {
        StandardTrustEvaluator(parser: StandardCertificateParser()) { trust in
            let certificates = anchors.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
            SecTrustSetAnchorCertificates(trust, certificates as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
        }
    }

    private func request(_ selected: String, _ additional: [String] = []) throws -> TrustRequest {
        TrustRequest(
            selectedCertificateDER: try der(selected),
            additionalCertificatesDER: try additional.map { try der($0) },
            verificationTime: fixedTime
        )
    }

    @Test func completeChainWithIsolatedAnchorIsTrusted() async throws {
        let evaluator = evaluator(isolatingAnchors: [try der("trust-root.cer")])
        let report = try await evaluator.evaluate(try request("trust-leaf.cer", ["trust-inter.cer"]))
        #expect(report.assessment.executionState == .completed)
        #expect(report.assessment.systemConclusion == .trusted)
        #expect(report.pathIsComplete == .yes)
        #expect(report.reachesTrustedAnchor == .yes)
        #expect(report.certificates.count == 3)
        #expect(report.assessment.context?.networkFetchDisabled == true)
        #expect(report.assessment.context?.verificationTime == fixedTime)
        #expect(report.assessment.context?.policy == .basicX509)
    }

    @Test func missingIntermediateIsCompletedButUntrusted() async throws {
        let evaluator = evaluator(isolatingAnchors: [try der("trust-root.cer")])
        let report = try await evaluator.evaluate(try request("trust-leaf.cer"))
        #expect(report.assessment.executionState == .completed)
        #expect(report.assessment.systemConclusion == .untrusted)
        #expect(report.assessment.context?.networkFetchDisabled == true)
        #expect(report.pathIsComplete == .no)
        #expect(report.reachesTrustedAnchor == .unknown)
        #expect(report.assessment.diagnostics.contains { $0.code == .incompleteChain })
    }

    @Test func completeChainWithUntrustedRootKeepsStructuralEvidence() async throws {
        // Full leaf→inter→root chain provided, but no test anchor installed:
        // the system builds the whole path to the self-signed root and rejects
        // it only because that root is not trusted on this machine.
        let evaluator = evaluator(isolatingAnchors: [])
        let report = try await evaluator.evaluate(
            try request("trust-leaf.cer", ["trust-inter.cer", "trust-root.cer"])
        )
        #expect(report.assessment.executionState == .completed)
        #expect(report.assessment.systemConclusion == .untrusted)
        #expect(report.pathIsComplete == .yes)
        #expect(report.reachesTrustedAnchor == .no)
        #expect(report.assessment.diagnostics.contains { $0.code == .untrustedSelfSigned })
    }

    @Test func unanchoredLeafCertificateIsUntrusted() async throws {
        // leaf.cer is issued by a throwaway CA; the isolated anchor is a
        // different root, so the system must reject it.
        let evaluator = evaluator(isolatingAnchors: [try der("trust-root.cer")])
        let report = try await evaluator.evaluate(try request("leaf.cer"))
        #expect(report.assessment.executionState == .completed)
        #expect(report.assessment.systemConclusion == .untrusted)
    }

    @Test func expiredCertificateKeepsExpiredDiagnostic() async throws {
        let evaluator = evaluator(isolatingAnchors: [try der("trust-root.cer")])
        let report = try await evaluator.evaluate(try request("trust-leaf-expired.cer", ["trust-inter.cer"]))
        #expect(report.assessment.executionState == .completed)
        #expect(report.assessment.systemConclusion == .untrusted)
        #expect(report.assessment.diagnostics.contains { $0.code == .expired })
    }

    @Test func futureCertificateKeepsNotYetValidDiagnostic() async throws {
        let evaluator = evaluator(isolatingAnchors: [try der("trust-root.cer")])
        let report = try await evaluator.evaluate(try request("trust-leaf-future.cer", ["trust-inter.cer"]))
        #expect(report.assessment.executionState == .completed)
        #expect(report.assessment.systemConclusion == .untrusted)
        #expect(report.assessment.diagnostics.contains { $0.code == .notYetValid })
    }

    @Test func unacceptableDERIsExecutionFailureWithoutEvaluation() async throws {
        let evaluator = evaluator(isolatingAnchors: [])
        let report = try await evaluator.evaluate(TrustRequest(
            selectedCertificateDER: Data([0x30, 0x03, 0x02, 0x01, 0x00]),
            additionalCertificatesDER: [], verificationTime: fixedTime
        ))
        #expect(report.assessment.executionState == .failed)
        #expect(report.assessment.systemConclusion == .undetermined)
        #expect(report.assessment.diagnostics.first?.source == .systemTrust)
        #expect(report.certificates.isEmpty)
    }

    @Test func unconfiguredProductionEntryNeverInstallsTestAnchors() async throws {
        let evaluator = StandardTrustEvaluator(parser: StandardCertificateParser())
        let report = try await evaluator.evaluate(try request("trust-leaf.cer", ["trust-inter.cer"]))
        // The throwaway root is not trusted by the system, so this must stay untrusted.
        #expect(report.assessment.systemConclusion == .untrusted)
    }
}
