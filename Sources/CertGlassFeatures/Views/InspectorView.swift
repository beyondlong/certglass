import AppKit
import CertGlassCore
import SwiftUI
import UniformTypeIdentifiers

public struct InspectorView: View {
    private enum DetailPage: Hashable { case overview, details, path }

    @ObservedObject var store: InspectorStore
    @State private var isExporting = false
    @State private var selectedPage: DetailPage = .overview
    @State private var columnVisibility: NavigationSplitViewVisibility = .detailOnly

    public init(store: InspectorStore) {
        self.store = store
    }

    public var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            List(selection: Binding(
                get: { store.selectedCertificateID },
                set: { id in
                    guard let id else { return }
                    Task { await store.selectCertificate(id) }
                }
            )) {
                Section("证书集合") {
                    ForEach(store.certificates) { certificate in
                        Text(commonName(of: certificate))
                            .lineLimit(1)
                            .tag(certificate.id)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
        } detail: {
            if store.certificates.isEmpty {
                emptyState
            } else {
                collectionDetail
            }
        }
        .frame(minWidth: 800, minHeight: 520)
        .dropDestination(for: URL.self) { urls, _ in
            Task {
                for url in urls { await store.openFile(at: url) }
            }
            return true
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "doc.badge.plus")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("打开证书文件开始查看").font(.title3)
            Text("支持 DER / PEM / PKCS#7（含无 PEM 头的裸 Base64），可一次选择多个文件。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("打开证书文件…") {
                Task { await CertificateFileOpener.presentAndOpen(into: store) }
            }
            .buttonStyle(.borderedProminent)
            Text("也可以把文件拖进窗口；再次打开文件会追加到左侧证书集合。")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            if let error = store.documentError {
                Label(error.message, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(12)
    }

    private var collectionDetail: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(headerTitle).font(.title2).lineLimit(1)
                    Text(headerSubtitle)
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if store.isLoadingDocument { ProgressView().controlSize(.small) }
            }
            if let error = store.documentError {
                Label(error.message, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange).textSelection(.enabled)
            }
            TabView(selection: $selectedPage) {
                OverviewView(certificate: store.selectedCertificate, assessment: store.assessment)
                    .tabItem { Label("概览", systemImage: "doc.text") }
                    .tag(DetailPage.overview)
                CertificateDetailsView(certificate: store.selectedCertificate)
                    .tabItem { Label("详细信息", systemImage: "list.bullet.rectangle") }
                    .tag(DetailPage.details)
                CertificationPathView(report: store.chainReport) { id in
                    store.showCertificateViewer(for: id)
                }
                .tabItem { Label("证书路径", systemImage: "link") }
                .tag(DetailPage.path)
            }
        }
        .padding(12)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await CertificateFileOpener.presentAndOpen(into: store) }
                } label: {
                    Label("打开证书文件", systemImage: "plus")
                }
                .help("把更多证书文件追加到左侧证书集合")
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("导出为 DER（.cer）") { Task { await export(as: .der, fileExtension: "cer") } }
                    Button("导出为 PEM（.pem）") { Task { await export(as: .pem, fileExtension: "pem") } }
                } label: {
                    if isExporting { ProgressView().controlSize(.small) } else {
                        Label("导出", systemImage: "square.and.arrow.up")
                    }
                }
                .disabled(store.selectedCertificate == nil || isExporting)
                .accessibilityIdentifier("export-menu")
            }
        }
        .alert(
            "导出失败", isPresented: Binding(
                get: { store.exportError != nil },
                set: { if !$0 { store.clearExportError() } }
            ), presenting: store.exportError
        ) { _ in
            Button("好", role: .cancel) {}
        } message: { error in
            Text(error.message)
        }
    }

    private var headerTitle: String {
        store.selectedFileInfo?.displayName ?? "证书集合"
    }

    private var headerSubtitle: String {
        var parts = ["\(store.loadedFiles.count) 个文件 · \(store.certificates.count) 张证书 · 只读"]
        if let info = store.selectedFileInfo {
            parts.insert("\(info.byteCount) 字节", at: 0)
        }
        return parts.joined(separator: " · ")
    }

    /// Sidebar shows the common name (CN) only; fall back to the full subject
    /// line, then the certificate hash when no name was parsed.
    private func commonName(of certificate: CertificateRecord) -> String {
        if let subject = certificate.subject {
            for rdn in subject.relativeDistinguishedNames {
                for attribute in rdn where attribute.oid == "2.5.4.3" {
                    if let value = attribute.value, !value.isEmpty { return value }
                }
            }
            return subject.displayValue
        }
        return "证书 \(certificate.id.sha256.prefix(12))"
    }

    @MainActor
    private func export(as format: CertificateExportFormat, fileExtension: String) async {
        guard store.selectedCertificate != nil else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = suggestedFileName(extension: fileExtension)
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        isExporting = true
        defer { isExporting = false }
        guard let data = await store.exportSelectedCertificate(as: format) else { return }
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            let nsError = error as NSError
            store.reportExportFailure(Diagnostic(
                code: .exportFailed, source: .application, severity: .error,
                message: "无法写入导出文件：\(nsError.localizedDescription)",
                systemError: SystemErrorDetail(
                    domain: nsError.domain, code: nsError.code, description: nsError.localizedDescription
                )
            ))
        }
    }

    private func suggestedFileName(extension fileExtension: String) -> String {
        let base = (headerTitle as NSString).deletingPathExtension
        let cleaned = base.isEmpty || base == "证书集合" ? "certificate" : base
        return "\(cleaned).\(fileExtension)"
    }
}
