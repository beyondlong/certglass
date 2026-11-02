import CertGlassFeatures
import CertGlassInfrastructure
import SwiftUI

@main
struct CertGlassApp: App {
    @StateObject private var store = InspectorStore(services: ScaffoldServices.make())

    var body: some Scene {
        WindowGroup {
            InspectorView(store: store)
                .onOpenURL { url in
                    Task { await store.openFile(at: url) }
                }
        }
        .defaultSize(width: 980, height: 640)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("打开证书文件…") {
                    Task { await CertificateFileOpener.presentAndOpen(into: store) }
                }
                .keyboardShortcut("o")
            }
        }
    }
}
