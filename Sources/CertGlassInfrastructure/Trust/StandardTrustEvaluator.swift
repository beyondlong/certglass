import CertGlassCore
import Foundation
@preconcurrency import Security

/// Offline trust evaluation on top of Security.framework. Only the Basic X.509
/// policy applies — revocation is not checked by design; network path building
/// is explicitly disabled and the configuration is verified before evaluation.
public struct StandardTrustEvaluator: TrustEvaluating {
    private let parser: any CertificateParsing
    private let now: @Sendable () -> Date
    private let trustConfigurationForTesting: (@Sendable (SecTrust) -> Void)?

    public init(parser: any CertificateParsing, now: @escaping @Sendable () -> Date = { Date() }) {
        self.parser = parser
        self.now = now
        self.trustConfigurationForTesting = nil
    }

    /// Testing-only entry point: installs isolated anchors on the trust object
    /// so unit tests never touch the keychain. Production assembly uses the
    /// default initializer.
    public init(
        parser: any CertificateParsing, now: @escaping @Sendable () -> Date = { Date() },
        trustConfigurationForTesting: @escaping @Sendable (SecTrust) -> Void
    ) {
        self.parser = parser
        self.now = now
        self.trustConfigurationForTesting = trustConfigurationForTesting
    }

    public func evaluate(_ request: TrustRequest) async throws -> ChainReport {
        let configured = configure(request)
        switch configured {
        case .failed(let report):
            return report
        case .configured(let trust, let context):
            return await runEvaluation(trust: trust, request: request, context: context)
        }
    }

    // MARK: Configuration

    private enum ConfigurationOutcome {
        case configured(SecTrust, TrustContext)
        case failed(ChainReport)
    }

    private func configure(_ request: TrustRequest) -> ConfigurationOutcome {
        let context = TrustContext(verificationTime: request.verificationTime, networkFetchDisabled: nil)
        func failed(_ diagnostic: Diagnostic) -> ConfigurationOutcome {
            .failed(ChainReport(assessment: TrustAssessment(
                executionState: .failed, diagnostics: [diagnostic], context: context
            )))
        }
        var certificates: [SecCertificate] = []
        for der in [request.selectedCertificateDER] + request.additionalCertificatesDER {
            guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                return failed(Diagnostic(
                    code: .invalidInput, source: .systemTrust, severity: .error,
                    message: "系统无法从原始 DER 创建证书，无法进行本机信任评估。"
                ))
            }
            certificates.append(certificate)
        }
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let creationStatus = SecTrustCreateWithCertificates(
            certificates as CFArray, [policy] as CFArray, &trust
        )
        guard creationStatus == errSecSuccess, let trust else {
            return failed(Diagnostic(
                code: .evaluationFailed, source: .systemTrust, severity: .error,
                message: "无法创建信任评估对象，评估未执行。"
            ))
        }
        SecTrustSetVerifyDate(trust, request.verificationTime as CFDate)

        // Offline limit must be configured and confirmed; any failure stops the
        // evaluation instead of falling back to online-capable settings.
        SecTrustSetNetworkFetchAllowed(trust, false)
        var fetchAllowed = DarwinBoolean(true)
        SecTrustGetNetworkFetchAllowed(trust, &fetchAllowed)
        guard !fetchAllowed.boolValue else {
            return failed(Diagnostic(
                code: .evaluationFailed, source: .systemTrust, severity: .error,
                message: "无法确认网络补链已禁用，评估未执行。"
            ))
        }
        trustConfigurationForTesting?(trust)
        let confirmedContext = TrustContext(
            verificationTime: request.verificationTime,
            networkFetchDisabled: !fetchAllowed.boolValue
        )
        return .configured(trust, confirmedContext)
    }

    // MARK: Evaluation

    private func runEvaluation(
        trust: SecTrust, request: TrustRequest, context: TrustContext
    ) async -> ChainReport {
        let outcome: (trusted: Bool, error: CFError?) = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var evaluationError: CFError?
                let trusted = SecTrustEvaluateWithError(trust, &evaluationError)
                continuation.resume(returning: (trusted, evaluationError))
            }
        }

        var chainCertificates: [Data] = []
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            chainCertificates = chain.compactMap { SecCertificateCopyData($0) as Data? }
        }

        var records: [CertificateRecord] = []
        for der in chainCertificates {
            records.append((try? await parser.parse(der: der)) ?? CertificateRecord(der: der))
        }

        var diagnostics: [Diagnostic] = []
        if !outcome.trusted, let error = outcome.error {
            diagnostics.append(contentsOf: trustDiagnostics(
                for: error, chain: records, verificationTime: context.verificationTime
            ))
        }

        // Evidence derives from the returned chain's structure: a self-signed
        // last certificate means the path was built to a root, even when the
        // system rejected trust. Only a trusted outcome proves a trusted anchor.
        if outcome.trusted {
            let assessment = TrustAssessment(
                executionState: .completed, systemConclusion: .trusted,
                diagnostics: diagnostics, context: context
            )
            return ChainReport(
                certificates: records, assessment: assessment,
                pathIsComplete: .yes, reachesTrustedAnchor: .yes
            )
        }

        let pathIsComplete: EvidenceState
        if let last = records.last, let subject = last.subject {
            pathIsComplete = subject == last.issuer ? .yes : .no
        } else {
            pathIsComplete = .unknown
        }
        let errorCode = outcome.error.map { CFErrorGetCode($0) }
        let reachesTrustedAnchor: EvidenceState
        if pathIsComplete == .yes, errorCode == CFIndex(errSecNotTrusted) {
            reachesTrustedAnchor = .no
        } else {
            reachesTrustedAnchor = .unknown
        }
        let assessment = TrustAssessment(
            executionState: .completed, systemConclusion: .untrusted,
            diagnostics: diagnostics, context: context
        )
        return ChainReport(
            certificates: records, assessment: assessment,
            pathIsComplete: pathIsComplete, reachesTrustedAnchor: reachesTrustedAnchor
        )
    }

    /// Security reports not-yet-valid certificates with the same OSStatus as
    /// expired ones, so the chain's own validity dates disambiguate the code.
    /// A complete chain rejected with errSecNotTrusted means the root itself is
    /// not trusted on this Mac (for example a private CA the user has not
    /// imported); an incomplete chain means parents are missing.
    private func trustDiagnostics(
        for error: CFError, chain: [CertificateRecord], verificationTime: Date
    ) -> [Diagnostic] {
        let code = CFErrorGetCode(error)
        let detail = SystemErrorDetail(
            domain: CFErrorGetDomain(error) as String? ?? "",
            code: code,
            description: CFErrorCopyDescription(error) as String
        )
        var diagnostics: [Diagnostic] = []
        if code == CFIndex(errSecCertificateExpired) {
            let notYetValid = chain.contains { record in
                record.notValidBefore.map { $0 > verificationTime } ?? false
            }
            if notYetValid {
                diagnostics.append(Diagnostic(
                    code: .notYetValid, source: .systemTrust, severity: .error,
                    message: "证书尚未生效，系统拒绝信任。", systemError: detail
                ))
            } else {
                diagnostics.append(Diagnostic(
                    code: .expired, source: .systemTrust, severity: .error,
                    message: "证书已过期，系统拒绝信任。", systemError: detail
                ))
            }
            return diagnostics
        }
        let chainComplete = chain.last.flatMap { record in
            record.subject.map { $0 == record.issuer }
        }
        if chainComplete == true, code == CFIndex(errSecNotTrusted) {
            diagnostics.append(Diagnostic(
                code: .untrustedSelfSigned, source: .systemTrust, severity: .error,
                message: "证书链已完整建立到根证书，但该根不在本机受信任的证书列表中；"
                    + "如需让系统信任此链，请使用钥匙串访问导入并信任根证书。",
                systemError: detail
            ))
        } else if chainComplete == false {
            diagnostics.append(Diagnostic(
                code: .incompleteChain, source: .systemTrust, severity: .error,
                message: "系统未能构建到根证书的完整路径，可能缺少上级 CA 证书；"
                    + "请打开包含完整链的文件（如 PKCS#7）或导入中间 CA 证书。",
                systemError: detail
            ))
        } else {
            diagnostics.append(Diagnostic(
                code: .systemError, source: .systemTrust, severity: .error,
                message: "未通过本机通用 X.509 信任评估；具体原因以系统错误为准。",
                systemError: detail
            ))
        }
        return diagnostics
    }
}
