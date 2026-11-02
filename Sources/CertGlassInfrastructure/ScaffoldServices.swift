import CertGlassCore

public enum ScaffoldServices {
    /// The single composition point. Replace adapters here as real implementations land.
    public static func make() -> InspectorServices {
        InspectorServices(
            containerDecoder: StandardContainerDecoder(),
            certificateParser: StandardCertificateParser(),
            trustEvaluator: StandardTrustEvaluator(parser: StandardCertificateParser()),
            certificateExporter: StandardCertificateExporter(),
            certificateViewer: StandardCertificateViewer()
        )
    }
}
