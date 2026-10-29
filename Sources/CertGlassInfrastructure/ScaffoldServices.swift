import CertGlassCore

public enum ScaffoldServices {
    /// The single composition point. Replace adapters here as real implementations land.
    public static func make() -> InspectorServices {
        InspectorServices(
            containerDecoder: UnimplementedContainerDecoder(),
            certificateParser: UnimplementedCertificateParser(),
            trustEvaluator: UnimplementedTrustEvaluator(),
            certificateExporter: UnimplementedCertificateExporter()
        )
    }
}
