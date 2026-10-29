import CertGlassFeatures
import CertGlassInfrastructure
import SwiftUI

@main
struct CertGlassApp: App {
    var body: some Scene {
        DocumentGroup(viewing: CertificateDocument.self) { configuration in
            InspectorView(
                input: configuration.document.input,
                displayName: configuration.fileURL?.lastPathComponent,
                services: ScaffoldServices.make()
            )
        }
        .defaultSize(width: 980, height: 640)
    }
}
