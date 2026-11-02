import CertGlassCore
import SwiftUI

struct CertificationPathView: View {
    let report: ChainReport?
    /// Presented for CA nodes (root / intermediates): view that certificate
    /// fully in the overview/details pages, like Windows' 查看证书.
    var onViewCertificate: ((CertificateID) -> Void)?
    @State private var selectedNodeID: CertificateID?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let report {
                summary(report)
                Divider()
                HSplitView {
                    pathList(report)
                        .frame(minWidth: 220, idealWidth: 280)

                    detailPane(report)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding(12)
                }
            } else {
                Text("系统评估完成后显示实际返回的证书路径，不生成推测节点。")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
            }
        }
    }

    private func pathList(_ report: ChainReport) -> some View {
        List(selection: Binding(
            get: { selectedNodeID ?? report.certificates.first?.id },
            set: { selectedNodeID = $0 }
        )) {
            Section("证书路径") {
                ForEach(pathNodes(report.certificates)) { node in
                    pathRow(node).tag(node.certificate.id)
                }
                if report.certificates.isEmpty {
                    Text("系统未返回证书路径。").foregroundStyle(.secondary)
                }
            }
        }
    }

    private func pathRow(_ node: PathNode) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 0) {
                ForEach(0..<node.depth, id: \.self) { level in
                    TreeGuide(showsElbow: level == node.depth - 1)
                }
                Label(
                    node.certificate.subject?.displayValue ?? node.certificate.id.sha256,
                    systemImage: node.certificate.caStatus == .certificateAuthority
                        ? "checkmark.shield" : "doc.badge.gearshape"
                )
                .lineLimit(1)
            }
            if !node.certificate.diagnostics.isEmpty {
                Text("\(node.certificate.diagnostics.count) 条诊断")
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.leading, CGFloat(node.depth) * 14 + 20)
            }
        }
    }

    private func detailPane(_ report: ChainReport) -> some View {
        Group {
            if let effectiveID = selectedNodeID ?? report.certificates.first?.id,
               let selected = report.certificates.first(where: { $0.id == effectiveID }) {
                nodeDetails(selected)
            } else {
                Text("选择左侧路径节点查看其详情。")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    private func summary(_ report: ChainReport) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent("路径完整性") { Text(completenessDescription(report.pathIsComplete)) }
            LabeledContent("到达受信锚点") { Text(completenessDescription(report.reachesTrustedAnchor)) }
            ForEach(report.assessment.diagnostics) { diagnostic in
                Label(diagnostic.message, systemImage: "exclamationmark.circle")
            }
        }
        .padding(12)
    }

    private func nodeDetails(_ certificate: CertificateRecord) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(certificate.subject?.displayValue ?? "证书 \(certificate.id.sha256.prefix(12))")
                    .font(.headline)
                if certificate.caStatus == .certificateAuthority, let onViewCertificate {
                    Button {
                        onViewCertificate(certificate.id)
                    } label: {
                        Label("查看证书", systemImage: "doc.text.magnifyingglass")
                    }
                    .buttonStyle(.bordered)
                    .help("用系统证书查看器（钥匙串访问同款面板）查看这张证书")
                }
                LabeledContent("主体", value: certificate.subject?.displayValue ?? "尚未解析")
                LabeledContent("颁发者", value: certificate.issuer?.displayValue ?? "尚未解析")
                LabeledContent("SHA-256") {
                    Text(certificate.id.sha256).font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                if let before = certificate.notValidBefore, let after = certificate.notValidAfter {
                    LabeledContent("有效期") {
                        Text("\(Self.formatter.string(from: before)) 至 \(Self.formatter.string(from: after))")
                    }
                }
                LabeledContent("解析状态") {
                    Text(certificate.parseStatus == .complete ? "完整解析" : "部分解析")
                }
                declaredUsageSummaries(certificate)
                ForEach(certificate.diagnostics) { diagnostic in
                    Label(diagnostic.message, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
        }
    }

    /// Same detail model as the details page, so path nodes never disagree
    /// with the interpretation shown elsewhere. Declaration only, not trust.
    private func declaredUsageSummaries(_ certificate: CertificateRecord) -> some View {
        let ordered: [(String, String)] = ["2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17"].compactMap { oid in
            guard let detail = certificate.extensionDetails.first(where: { $0.oid == oid }) else { return nil }
            let title: String
            switch oid {
            case "2.5.29.19": title = "证书类型（声明）"
            case "2.5.29.15": title = "密钥用法（声明）"
            case "2.5.29.37": title = "扩展密钥用法（声明）"
            default: title = "SAN（声明）"
            }
            return (title, detail.summary)
        }
        return GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Text("声明用途（证书声明，非系统信任结论）")
                    .font(.caption).foregroundStyle(.secondary)
                if ordered.isEmpty {
                    Text("该节点未包含已结构化解释的用途扩展。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(ordered, id: \.0) { title, summary in
                    LabeledContent(title) { Text(summary) }
                }
            }
        }
    }

    private func completenessDescription(_ value: EvidenceState) -> String {
        switch value {
        case .yes: "是"
        case .no: "否"
        case .unknown: "无法确定"
        }
    }
    static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

/// 系统返回的路径叶子在前；展示按 Windows 习惯自根向下逐级缩进。
private struct PathNode: Identifiable {
    let depth: Int
    let certificate: CertificateRecord
    var id: CertificateID { certificate.id }
}

private func pathNodes(_ certificates: [CertificateRecord]) -> [PathNode] {
    certificates.reversed().enumerated().map { index, certificate in
        PathNode(depth: index, certificate: certificate)
    }
}

private struct TreeGuide: View {
    var showsElbow: Bool

    var body: some View {
        let line = Color.secondary.opacity(0.35)
        ZStack(alignment: .topLeading) {
            if showsElbow {
                Rectangle().fill(line).frame(width: 1, height: 12)
                Rectangle().fill(line).frame(width: 13, height: 1).offset(y: 11)
            } else {
                Rectangle().fill(line).frame(width: 1)
                    .frame(maxHeight: .infinity, alignment: .top)
            }
        }
        .frame(width: 14, alignment: .topLeading)
    }
}
