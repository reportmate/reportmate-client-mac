// swift-tools-version: 6.0
// ReportMate macOS Client - Swift Package Manager configuration

import PackageDescription

let package = Package(
    name: "ReportMate",
    platforms: [
        .macOS(.v14) // macOS Sonoma minimum for Swift 6.2 features
    ],
    products: [
        // The one executable: the app's CFBundleExecutable. It opens the window,
        // runs the privileged helper (--helper), the usage watcher (--appusage)
        // or the collector, chosen by its arguments (Sources/App/AppEntry.swift).
        .executable(
            name: "managedreportsrunner",
            targets: ["App"]
        ),
        .library(
            name: "ReportMateXPC",
            targets: ["ReportMateXPC"]
        ),
        .library(
            name: "ReportMateLogging",
            targets: ["ReportMateLogging"]
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
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.1.0"),
    ],
    targets: [
        .target(
            name: "ReportMateXPC",
            dependencies: [],
            path: "Sources/ReportMateXPC"
        ),
        .target(
            name: "ReportMateLogging",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/ReportMateLogging"
        ),
        // The collector, as a library the app's executable runs.
        .target(
            name: "ReportMate",
            dependencies: [
                "ReportMateLogging",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "SQLite", package: "SQLite.swift"),
                .product(name: "Yams", package: "Yams"),
            ],
            path: "Sources",
            exclude: ["Watcher", "App", "ReportMateXPC", "Helper", "ReportMateLogging"],
            resources: [
                .copy("Resources")
            ]
        ),
        .target(
            name: "Watcher",
            dependencies: [
                "ReportMateLogging",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources/Watcher"
        ),
        .executableTarget(
            name: "App",
            dependencies: ["ReportMateXPC", "ReportMate", "Helper", "Watcher"],
            path: "Sources/App"
        ),
        .target(
            name: "Helper",
            dependencies: ["ReportMateXPC"],
            path: "Sources/Helper"
        ),
        .testTarget(
            name: "ReportMateXPCTests",
            dependencies: ["ReportMateXPC"],
            path: "Tests/ReportMateXPCTests"
        ),
        .testTarget(
            name: "ReportMateLoggingTests",
            dependencies: ["ReportMateLogging"],
            path: "Tests/ReportMateLoggingTests"
        ),
        .testTarget(
            name: "AppTests",
            dependencies: ["App"],
            path: "Tests/AppTests"
        ),
        .testTarget(
            name: "ReportMateTests",
            dependencies: ["ReportMate"],
            path: "Tests/ReportMateTests"
        ),
    ]
)