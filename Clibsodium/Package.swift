// swift-tools-version:5.3
import PackageDescription

let clibsodiumTarget: Target
#if os(OSX) || os(macOS) || os(tvOS) || os(watchOS) || os(iOS)
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
            .brew(["libsodium"]),
            .yum(["libsodium-devel"])
        ])
#endif


let package = Package(
    name: "Clibsodium",
    products: [
        .library(
            name: "Clibsodium",
            targets: ["Clibsodium"]),
    ],
    targets: [
        clibsodiumTarget,
    ]
)
