// swift-tools-version: 5.4
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
                .byName(
                    name: "ClibsodiumBinary",
                    condition: .when(platforms: [
                            .macOS,
                            .macCatalyst,
                            .iOS,
                            .watchOS,
                            .tvOS,
                            .visionOS,
                        ])),
                .byName(
                    name: "ClibsodiumSystem",
                    condition: .when(platforms: [
                        .android,
                        .linux,
                        .wasi,
                        .windows,
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
            dependencies: ["_Clibsodium"],
            exclude: ["libsodium", "Info.plist"]),
        .testTarget(
            name: "SodiumTests",
            dependencies: ["Sodium"],
            exclude: ["Info.plist"]),
    ]
)
