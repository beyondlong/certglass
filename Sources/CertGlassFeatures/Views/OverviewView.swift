import CertGlassCore
import SwiftUI

struct OverviewView: View {
    let certificate: CertificateRecord?
    let assessment: TrustAssessment

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label(statusMessage, systemImage: "shield")
                    .font(.headline)
                if assessment.executionState == .running { ProgressView() }
                if let certificate {
                    LabeledContent("颁发给", value: certificate.subject?.displayValue ?? "尚未解析")
                    LabeledContent("颁发者", value: certificate.issuer?.displayValue ?? "尚未解析")
                    LabeledContent("SHA-256") {
                        Text(certificate.id.sha256).font(.system(.caption, design: .monospaced))
                    }
                    if certificate.parseStatus == .partial {
                        Text("部分解析：无法解释的字段保留原始值。")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(certificate.diagnostics) { diagnostic in
                        Text(diagnostic.message).foregroundStyle(.secondary)
                    }
                } else {
                    Text("证书解析完成后，此处显示主体、颁发者和有效期等信息。")
                        .foregroundStyle(.secondary)
                }
                ForEach(assessment.diagnostics) { diagnostic in
                    Label(diagnostic.message, systemImage: "exclamationmark.circle")
                }
                if let context = assessment.context {
                    LabeledContent("评估时间") { Text(context.verificationTime, style: .date) }
                    Text("策略：通用 X.509；吊销查询仅限本地缓存。")
                        .font(.caption).foregroundStyle(.secondary)
                    if context.networkFetchDisabled != true || context.revocationNetworkAccessDisabled != true {
                        Text("离线配置尚未确认。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text("未执行在线吊销查询。通用 X.509 评估不代表特定用途均受信任。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding().frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
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
}
