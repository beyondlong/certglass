import Foundation

public enum EvaluationExecutionState: String, Sendable { case notStarted, running, completed, failed }
public enum SystemTrustConclusion: String, Sendable { case trusted, untrusted, undetermined }
public enum EvidenceState: String, Sendable { case yes, no, unknown }
public enum TrustPolicy: String, Sendable { case basicX509WithCachedRevocation }

public struct TrustContext: Sendable, Equatable {
    public let verificationTime: Date
    public let policy: TrustPolicy
    /// nil means the adapter has not confirmed the effective setting.
    public let networkFetchDisabled: Bool?
    public let revocationNetworkAccessDisabled: Bool?
    public let operatingSystemVersion: String

    public init(
        verificationTime: Date, policy: TrustPolicy = .basicX509WithCachedRevocation,
        networkFetchDisabled: Bool? = nil, revocationNetworkAccessDisabled: Bool? = nil,
        operatingSystemVersion: String = ProcessInfo.processInfo.operatingSystemVersionString
    ) {
        self.verificationTime = verificationTime
        self.policy = policy
        self.networkFetchDisabled = networkFetchDisabled
        self.revocationNetworkAccessDisabled = revocationNetworkAccessDisabled
        self.operatingSystemVersion = operatingSystemVersion
    }
}

public struct TrustAssessment: Sendable, Equatable {
    public let executionState: EvaluationExecutionState
    public let systemConclusion: SystemTrustConclusion
    public let diagnostics: [Diagnostic]
    public let context: TrustContext?

    public init(
        executionState: EvaluationExecutionState = .notStarted,
        systemConclusion: SystemTrustConclusion = .undetermined,
        diagnostics: [Diagnostic] = [], context: TrustContext? = nil
    ) {
        self.executionState = executionState
        self.systemConclusion = executionState == .completed ? systemConclusion : .undetermined
        self.diagnostics = diagnostics
        self.context = context
    }
}

public struct ChainReport: Sendable, Equatable {
    public let certificates: [CertificateRecord]
    public let assessment: TrustAssessment
    public let pathIsComplete: EvidenceState
    public let reachesTrustedAnchor: EvidenceState

    public init(
        certificates: [CertificateRecord] = [], assessment: TrustAssessment = TrustAssessment(),
        pathIsComplete: EvidenceState = .unknown, reachesTrustedAnchor: EvidenceState = .unknown
    ) {
        self.certificates = certificates
        self.assessment = assessment
        self.pathIsComplete = pathIsComplete
        self.reachesTrustedAnchor = reachesTrustedAnchor
    }
}

public struct TrustRequest: Sendable, Equatable {
    public let selectedCertificateDER: Data
    public let additionalCertificatesDER: [Data]
    public let verificationTime: Date
    /// Production requests expose no online mode or custom trust anchors.
    public let policy: TrustPolicy = .basicX509WithCachedRevocation

    public init(selectedCertificateDER: Data, additionalCertificatesDER: [Data], verificationTime: Date) {
        self.selectedCertificateDER = selectedCertificateDER
        self.additionalCertificatesDER = additionalCertificatesDER
        self.verificationTime = verificationTime
    }
}
