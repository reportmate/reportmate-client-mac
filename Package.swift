// swift-tools-version: 6.0
// ReportMate macOS Client - Swift Package Manager configuration

import PackageDescription

let package = Package(
    name: "ReportMate",
    platforms: [
        .macOS(.v14) // macOS Sonoma minimum for Swift 6.2 features
    ],
    products: [
        .executable(
            name: "runner",
            targets: ["ReportMate"]
        ),
    ],
    dependencies: [
        // Swift Argument Parser for CLI
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        // Swift Log for structured logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        // Async HTTP Client
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.19.0"),
    ],
    targets: [
        .executableTarget(
            name: "ReportMate",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
            ],
            path: "Sources/ReportMate",
            resources: [
                .copy("Resources")
            ]
        ),
        .testTarget(
            name: "ReportMateTests",
            dependencies: ["ReportMate"],
            path: "Tests/ReportMateTests"
        ),
    ]
)