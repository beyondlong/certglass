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
    targets: [
        .target(name: "CertGlassCore"),
        .target(name: "CertGlassInfrastructure", dependencies: ["CertGlassCore"]),
        .target(name: "CertGlassFeatures", dependencies: ["CertGlassCore"]),
        .executableTarget(
            name: "CertGlass", dependencies: ["CertGlassFeatures", "CertGlassInfrastructure"],
            path: "App/CertGlass", exclude: ["Info.plist", "CertGlass.entitlements"]
        ),
        .testTarget(name: "CertGlassCoreTests", dependencies: ["CertGlassCore"]),
        .testTarget(
            name: "CertGlassFeaturesTests",
            dependencies: ["CertGlassCore", "CertGlassFeatures", "CertGlassInfrastructure"]
        )
    ],
    swiftLanguageModes: [.v6]
)
