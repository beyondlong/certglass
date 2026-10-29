import CertGlassCore
import Foundation
import SwiftUI
import UniformTypeIdentifiers

public struct CertificateDocument: FileDocument {
    public static var readableContentTypes: [UTType] { CertificateFileTypes.readableContentTypes }
    public static var writableContentTypes: [UTType] { [] }
    public let input: DocumentInput

    public init(configuration: ReadConfiguration) throws {
        guard configuration.file.isRegularFile,
              let data = configuration.file.regularFileContents else {
            throw CertGlassError.unsupportedFile
        }
        // FileDocument supplies an already materialized FileWrapper. This is a post-read limit.
        // HANDOFF A: investigate bounded URL loading before promising a hard memory limit.
        input = try DocumentInput(data: data, displayName: configuration.file.preferredFilename)
    }

    public func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        throw CertGlassError.readOnlyDocument
    }
}
