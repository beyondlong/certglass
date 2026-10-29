import CertGlassCore
import SwiftUI

public struct InspectorView: View {
    private let input: DocumentInput
    private let displayName: String
    @StateObject private var store: InspectorStore

    public init(input: DocumentInput, displayName: String? = nil, services: InspectorServices) {
        self.input = input
        self.displayName = displayName ?? input.displayName ?? "证书文件"
        _store = StateObject(wrappedValue: InspectorStore(services: services))
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: Binding(
                get: { store.selectedCertificateID },
                set: { id in
                    guard let id else { return }
                    Task { await store.selectCertificate(id) }
                }
            )) {
                Section("证书集合") {
                    ForEach(store.certificates) { certificate in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(certificate.subject?.displayValue ?? "证书 \(certificate.id.sha256.prefix(12))")
                                .lineLimit(2)
                            Text(certificate.caStatus == .certificateAuthority ? "CA 证书" :
                                (certificate.caStatus == .endEntity ? "终端实体证书" : "类型待确认"))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .tag(certificate.id)
                    }
                    if store.certificates.isEmpty {
                        Text("尚未解析出证书").foregroundStyle(.secondary)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
        } detail: {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(displayName).font(.title2).lineLimit(1)
                        Text("\(input.data.count) 字节 · 只读")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if store.isLoadingDocument { ProgressView().controlSize(.small) }
                }
                if let error = store.documentError {
                    Label(error.message, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange).textSelection(.enabled)
                }
                TabView {
                    OverviewView(certificate: store.selectedCertificate, assessment: store.assessment)
                        .tabItem { Label("概览", systemImage: "doc.text") }
                    CertificateDetailsView(certificate: store.selectedCertificate)
                        .tabItem { Label("详细信息", systemImage: "list.bullet.rectangle") }
                    CertificationPathView(report: store.chainReport)
                        .tabItem { Label("证书路径", systemImage: "link") }
                }
                Text("基础脚手架：证书解析、系统信任评估和导出功能尚未实现。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(20)
        }
        .frame(minWidth: 800, minHeight: 520)
        .task(id: input) { await store.open(input) }
    }
}
