// swift-tools-version:5.3
import PackageDescription

let clibsodiumTarget: Target
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
    clibsodiumTarget = .binaryTarget(
        name: "Clibsodium",
        path: "Clibsodium.xcframework")
#else
    clibsodiumTarget = .systemLibrary(
        name: "Clibsodium",
        path: "Clibsodium",
        pkgConfig: "libsodium",
        providers: [
            .apt(["libsodium-dev"]),
            .brew(["libsodium"])
        ])
#endif

let package = Package(
    name: "Sodium",
    products: [
        .library(
            name: "Clibsodium",
            targets: ["Clibsodium"]),
        .library(
            name: "Sodium",
            targets: ["Sodium"]),
    ],
    targets: [
        clibsodiumTarget,
        .target(
            name: "Sodium",
            dependencies: ["Clibsodium"],
            path: "Sodium",
            exclude: ["libsodium", "Info.plist"]),
        .testTarget(
            name: "SodiumTests",
            dependencies: ["Sodium"],
            exclude: ["Info.plist"]),
    ]
)
