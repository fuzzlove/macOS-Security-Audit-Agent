// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MSAAAssurance",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MSAAAssuranceCore", targets: ["MSAAAssuranceCore"]),
        .executable(name: "MSAAAssuranceApp", targets: ["MSAAAssuranceApp"]),
        .executable(name: "msaa-verify", targets: ["MSAAVerify"]),
        .executable(name: "msaa-assurance-selftest", targets: ["MSAAAssuranceCoreTests"]),
    ],
    targets: [
        .target(name: "MSAAAssuranceCore"),
        .executableTarget(name: "MSAAAssuranceApp", dependencies: ["MSAAAssuranceCore"]),
        .executableTarget(name: "MSAAVerify", dependencies: ["MSAAAssuranceCore"]),
        .executableTarget(name: "MSAAAssuranceCoreTests", dependencies: ["MSAAAssuranceCore"], path: "Tests/MSAAAssuranceCoreTests"),
    ]
)
