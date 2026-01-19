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
            name: "managedreportsrunner",
            targets: ["ReportMate"]
        ),
        .executable(
            name: "reportmate-appusage",
            targets: ["AppUsageWatcher"]
        ),
    ],
    dependencies: [
        // Swift Argument Parser for CLI
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        // Swift Log for structured logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        // Async HTTP Client
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.19.0"),
        // SQLite.swift for app usage persistence
        .package(url: "https://github.com/stephencelis/SQLite.swift.git", from: "0.15.4"),
    ],
    targets: [
        .executableTarget(
            name: "ReportMate",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources",
            exclude: ["AppUsageWatcher"],
            resources: [
                .copy("Resources")
            ]
        ),
        .executableTarget(
            name: "AppUsageWatcher",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources/AppUsageWatcher"
        ),
    ]
)