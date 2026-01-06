// swift-tools-version: 5.8
import PackageDescription

let package = Package(
    name: "Sodium",
    products: [
        .library(
            name: "Clibsodium",
            targets: ["_Clibsodium"]),
        .library(
            name: "Sodium",
            targets: ["Sodium"]),
    ],
    targets: [
        .target(
            name: "_Clibsodium",
            dependencies: [
                .target(name: "ClibsodiumBinary", condition: .when(platforms: [
                    .macOS,
                    .macCatalyst,
                    .iOS,
                    .watchOS,
                    .tvOS,
                    .visionOS,
                ])),
                .target(name: "ClibsodiumSystem", condition: .when(platforms: [
                    .linux,
                    .android,
                    .windows,
                    .openbsd,
                ])),
            ]),
        .binaryTarget(
            name: "ClibsodiumBinary",
            path: "Clibsodium.xcframework"),
        .systemLibrary(
            name: "ClibsodiumSystem",
            pkgConfig: "libsodium",
            providers: [
                .apt(["libsodium-dev"]),
                .brew(["libsodium"]),
                .yum(["libsodium-devel"]),
            ]),
        .target(
            name: "Sodium",
            dependencies: ["_Clibsodium"]),
        .testTarget(
            name: "SodiumTests",
            dependencies: ["Sodium"]),
    ]
)
