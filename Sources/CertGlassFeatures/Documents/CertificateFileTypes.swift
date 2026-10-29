import UniformTypeIdentifiers

public enum CertificateFileTypes {
    public static let filenameExtensions = ["cer", "crt", "pem", "p7b", "p7c"]

    /// Imported fallback types are also declared in the application's Info.plist.
    public static var readableContentTypes: [UTType] {
        let declared = [
            UTType(importedAs: "app.certglass.x509-certificate", conformingTo: .data),
            UTType(importedAs: "app.certglass.pem", conformingTo: .data),
            UTType(importedAs: "app.certglass.pkcs7", conformingTo: .data)
        ]
        // Respect types already known to this Mac (for example, from Keychain Access).
        return declared + filenameExtensions.compactMap { UTType(filenameExtension: $0) }
    }
}
