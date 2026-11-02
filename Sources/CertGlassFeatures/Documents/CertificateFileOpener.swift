import AppKit
import CertGlassCore
import UniformTypeIdentifiers

@MainActor
public enum CertificateFileOpener {
    /// Shows an open panel and adds every chosen file to the collection.
    public static func presentAndOpen(into store: InspectorStore) async {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = CertificateFileTypes.readableContentTypes
        panel.message = "选择要加入证书集合的文件"
        guard await panel.begin() == .OK else { return }
        for url in panel.urls {
            await store.openFile(at: url)
        }
    }
}
