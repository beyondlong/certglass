import CertGlassCore
import SwiftUI

struct OverviewView: View {
    let certificate: CertificateRecord?
    let assessment: TrustAssessment

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                statusRow
                if let certificate {
                    certificateInfo(certificate)
                    declaredUsageSummary(certificate)
                    compactDiagnostics(certificate)
                } else {
                    Text("证书解析完成后显示主体、颁发者和有效期。")
                        .foregroundStyle(.secondary)
                }
                assessmentDetails
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
        }
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Image(systemName: assessment.systemConclusion == .trusted ? "checkmark.shield" : "shield")
                .font(.title3)
            Text(statusMessage).font(.headline)
            if assessment.executionState == .running {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.bottom, 4)
    }

    private func certificateInfo(_ certificate: CertificateRecord) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            infoRow("颁发给", certificate.subject?.displayValue ?? "尚未解析")
            infoRow("颁发者", certificate.issuer?.displayValue ?? "尚未解析")
            if let serial = certificate.serialNumber, !serial.isEmpty {
                infoRow("序列号", serial.hexString, monospaced: true)
            }
            if let before = certificate.notValidBefore, let after = certificate.notValidAfter {
                infoRow("有效期", "\(Self.formatter.string(from: before)) 至 \(Self.formatter.string(from: after))")
            }
            infoRow("SHA-256", certificate.id.sha256, monospaced: true)
        }
    }

    private func declaredUsageSummary(_ certificate: CertificateRecord) -> some View {
        let basic = certificate.extensionDetails.first { $0.oid == "2.5.29.19" }
        let keyUsage = certificate.extensionDetails.first { $0.oid == "2.5.29.15" }
        let eku = certificate.extensionDetails.first { $0.oid == "2.5.29.37" }
        let san = certificate.extensionDetails.first { $0.oid == "2.5.29.17" }
        let rows: [(String, String)] = [
            ("证书类型", basic?.summary),
            ("密钥用法", keyUsage?.summary),
            ("扩展密钥用法", eku?.summary),
            ("主题备用名称", san.map { "\($0.items.count) 项" })
        ].compactMap { label, value in value.map { (label, $0) } }

        return VStack(alignment: .leading, spacing: 7) {
            Text("证书声明").font(.headline)
            ForEach(rows, id: \.0) { label, value in
                infoRow(label, value)
            }
            Text("以上是证书声明，不是系统信任结论。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 4)
    }

    @ViewBuilder
    private func compactDiagnostics(_ certificate: CertificateRecord) -> some View {
        if certificate.parseStatus == .partial || !certificate.diagnostics.isEmpty {
            DisclosureGroup("解析提示（\(certificate.diagnostics.count)）") {
                ForEach(certificate.diagnostics) { diagnostic in
                    Text(diagnostic.message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, 3)
                }
            }
        }
    }

    @ViewBuilder
    private var assessmentDetails: some View {
        if let context = assessment.context {
            DisclosureGroup("评估详情") {
                VStack(alignment: .leading, spacing: 6) {
                    infoRow("评估时间", Self.formatter.string(from: context.verificationTime))
                    infoRow("策略", "通用 X.509；不验证吊销列表")
                    Text("不验证吊销列表；结论只反映本机 X.509 链验证与信任锚，特定用途是否受信任仍需单独判断。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(assessment.diagnostics) { diagnostic in
                        Label(diagnostic.message, systemImage: "exclamationmark.circle")
                            .font(.caption)
                    }
                }
                .padding(.top, 5)
            }
        } else if !assessment.diagnostics.isEmpty {
            DisclosureGroup("评估诊断（\(assessment.diagnostics.count)）") {
                ForEach(assessment.diagnostics) { diagnostic in
                    Text(diagnostic.message).font(.caption).padding(.top, 3)
                }
            }
        }
    }

    private func infoRow(_ label: String, _ value: String, monospaced: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .frame(width: 92, alignment: .trailing)
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .system(.body, design: .monospaced) : .body)
                .lineLimit(3)
            Spacer(minLength: 0)
        }
    }

    private var statusMessage: String {
        switch assessment.executionState {
        case .notStarted: "尚未进行信任评估"
        case .running: "正在进行本机信任评估"
        case .failed: "无法完成本机信任评估"
        case .completed:
            switch assessment.systemConclusion {
            case .trusted: "通过本机通用 X.509 信任评估"
            case .untrusted: "未通过本机通用 X.509 信任评估"
            case .undetermined: "无法确定本机信任结论"
            }
        }
    }

    static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()
}
