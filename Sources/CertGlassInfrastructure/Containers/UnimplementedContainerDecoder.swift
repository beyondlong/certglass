import CertGlassCore

public struct UnimplementedContainerDecoder: ContainerDecoding {
    public init() {}

    public func decode(_ input: DocumentInput) async throws -> DecodedContainer {
        // HANDOFF A: sniff bytes and decode DER, PEM and certificate-only PKCS#7.
        throw CertGlassError.notImplemented(feature: "DER / PEM / PKCS#7 容器解码")
    }
}
