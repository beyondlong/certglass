import AppKit
import CertGlassCore
import Security
import SecurityInterface

/// System certificate viewer panel (the same view Keychain Access presents
/// when double-clicking a certificate). Read-only display; the panel never
/// modifies keychain items or trust settings.
@MainActor
public struct StandardCertificateViewer: CertificateViewing {
    public nonisolated init() {}

    public func showCertificate(der: Data) {
        guard let panel = SFCertificatePanel.shared() else { return }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return }
        if let window = NSApp.keyWindow {
            // SecurityInterface exposes the certificate-array sheet API on
            // the supported macOS SDKs. The panel is read-only and does not
            // import the certificate into the keychain.
            panel.beginSheet(
                for: window, modalDelegate: nil, didEnd: nil, contextInfo: nil,
                certificates: [certificate], showGroup: false
            )
            return
        }

        // The modal API accepts a SecTrust rather than a certificate array.
        // Keep the same offline Basic X.509 setup for this no-window branch.
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(
            certificate as CFTypeRef, SecPolicyCreateBasicX509(), &trust
        ) == errSecSuccess, let trust else { return }
        SecTrustSetNetworkFetchAllowed(trust, false)
        _ = panel.runModal(for: trust, showGroup: false)
    }
}
