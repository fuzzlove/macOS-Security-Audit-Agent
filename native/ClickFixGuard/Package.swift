// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MSAAClickFixGuard",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ClickFixGuardShared", targets: ["ClickFixGuardShared"]),
        .library(name: "MSAAEndpointMonitor", targets: ["MSAAEndpointMonitor"]),
        .executable(name: "MSAAClickFixGuardAgent", targets: ["ClickFixGuardAgent"]),
    ],
    targets: [
        .target(name: "ClickFixGuardShared"),
        .target(name: "MSAAEndpointMonitor"),
        .executableTarget(name: "ClickFixGuardAgent", dependencies: ["ClickFixGuardShared"], resources: [.copy("Resources")]),
        .testTarget(name: "ClickFixGuardTests", dependencies: ["ClickFixGuardAgent", "ClickFixGuardShared"]),
    ]
)
