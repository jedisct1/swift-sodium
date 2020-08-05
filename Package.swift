// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Sodium",
    products: [
        .library(
            name: "Sodium",
            targets: ["Sodium"]),
    ],
    targets: [
        .binaryTarget(
            name: "Clibsodium",
            path: "Clibsodium.xcframework"),
        .target(
            name: "Sodium",
            dependencies: [],
            path: "Sodium",
            exclude: ["libsodium"]),
        .testTarget(
            name: "SodiumTests",
            dependencies: ["Sodium"]),
    ]
)
