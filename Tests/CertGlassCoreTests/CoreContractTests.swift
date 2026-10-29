import Foundation
import Testing
@testable import CertGlassCore

struct CoreContractTests {
    @Test func emptyInputIsRejected() {
        #expect(throws: CertGlassError.emptyInput) {
            try DocumentInput(data: Data())
        }
    }

    @Test func oversizedInputIsRejected() {
        let limits = InputLimits(maximumFileBytes: 3, maximumCertificates: 2)
        #expect(throws: CertGlassError.inputTooLarge(maximumBytes: 3)) {
            try DocumentInput(data: Data([1, 2, 3, 4]), limits: limits)
        }
    }

    @Test func inputAtLimitPreservesOriginalBytes() throws {
        let bytes = Data([0, 255, 128])
        let input = try DocumentInput(
            data: bytes, displayName: "sample.cer",
            limits: InputLimits(maximumFileBytes: 3, maximumCertificates: 2)
        )
        #expect(input.data == bytes)
        #expect(input.displayName == "sample.cer")
    }

    @Test func certificateIdentityIsSHA256OfOriginalDER() {
        // Identity fixture only; these bytes are intentionally not an X.509 certificate.
        let record = CertificateRecord(der: Data("abc".utf8))
        #expect(record.id.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func unfinishedAssessmentCannotClaimTrust() {
        for state in [EvaluationExecutionState.notStarted, .running, .failed] {
            let assessment = TrustAssessment(executionState: state, systemConclusion: .trusted)
            #expect(assessment.systemConclusion == .undetermined)
        }
    }

    @Test func completedAssessmentPreservesMultipleDiagnostics() {
        let diagnostics = [
            Diagnostic(code: .expired, source: .systemTrust, severity: .error, message: "已过期"),
            Diagnostic(code: .incompleteChain, source: .systemTrust, severity: .error, message: "链不完整")
        ]
        let assessment = TrustAssessment(
            executionState: .completed, systemConclusion: .untrusted, diagnostics: diagnostics
        )
        #expect(assessment.systemConclusion == .untrusted)
        #expect(assessment.diagnostics == diagnostics)
        #expect(assessment.context == nil)
    }
}
