// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CertGlass",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CertGlassCore", targets: ["CertGlassCore"]),
        .library(name: "CertGlassInfrastructure", targets: ["CertGlassInfrastructure"]),
        .library(name: "CertGlassFeatures", targets: ["CertGlassFeatures"]),
        .executable(name: "CertGlass", targets: ["CertGlass"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.8.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
        // The newest swift-crypto manifest fails to compile with the local CLT
        // toolchain; 3.11.2 is the minimum required by swift-certificates 1.8.
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.11.2")
    ],
    targets: [
        .target(name: "CertGlassCore"),
        .target(
            name: "CertGlassInfrastructure",
            dependencies: [
                "CertGlassCore",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        ),
        .target(name: "CertGlassFeatures", dependencies: ["CertGlassCore"]),
        .executableTarget(
            name: "CertGlass", dependencies: ["CertGlassFeatures", "CertGlassInfrastructure"],
            path: "App/CertGlass", exclude: ["Info.plist", "CertGlass.entitlements", "Assets.xcassets"]
        ),
        .testTarget(name: "CertGlassCoreTests", dependencies: ["CertGlassCore"]),
        .testTarget(
            name: "CertGlassInfrastructureTests",
            dependencies: ["CertGlassCore", "CertGlassInfrastructure"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "CertGlassFeaturesTests",
            dependencies: ["CertGlassCore", "CertGlassFeatures", "CertGlassInfrastructure"]
        )
    ],
    swiftLanguageModes: [.v6]
)
