// swift-tools-version:5.3
import PackageDescription

var products: [Product] = [.library(name: "Sodium", targets: ["Sodium"])]
var dependencies: [Package.Dependency] = []
var targets: [Target] = [
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


#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
products.append(.library(name: "Clibsodium", targets: ["Clibsodium"]))
targets.append(.binaryTarget(name: "Clibsodium", path: "Clibsodium.xcframework"))
#else
dependencies.append(.package(name: "Clibsodium", url: "https://github.com/TICESoftware/Clibsodium.git", from: "1.0.0"))
#endif

let package = Package(
    name: "Sodium",
    products: products,
    dependencies: dependencies,
    targets: targets
)
