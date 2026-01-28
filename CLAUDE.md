# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## IMPORTANT: Allowed Technologies

**DO NOT USE PYTHON.** This is a native macOS application. Only the following technologies are permitted:

- **Native Swift** (Swift 6.0+, Swift SDK, Foundation, macOS frameworks)
- **osquery** (primary data collection engine)
- **macadmins osquery extension** (additional macOS-specific tables)
- **Bash** (shell commands as fallback for data collection)

Any new code or modifications MUST use these technologies only. The legacy `PythonService.swift` exists but should not be extended or used for new functionality.

### Example: Use `jq` NOT Python for JSON Processing

When parsing system data, use `jq` with bash commands instead of Python:

```bash
# CORRECT: Use jq for JSON processing
system_profiler SPPrintersDataType -json 2>/dev/null | jq '[.SPPrintersDataType[]? | {
    name: (._name // "Unknown"),
    status: (.status // "Unknown"),
    uri: (.uri // ""),
    ppd: (.ppd // ""),
    driverVersion: (.driverversion // ""),
    postScriptVersion: (.psversion // ""),
    cupsVersion: (.cupsversion // ""),
    cupsFilters: [."cups filters"[]? | {
        name: (._name // ""),
        path: (."filter path" // ""),
        version: (."filter version" // "")
    }]
}]'

# WRONG: Never use Python
# python3 -c "import json; ..."  # DO NOT DO THIS
```

The Swift binary should call bash/jq commands via `BashService.swift`, never Python.

## Project Overview

ReportMate macOS Client - A native Swift 6.0 application that collects device telemetry data from macOS endpoints and transmits it to the ReportMate API. Uses osquery as the primary data collection engine with bash fallbacks.

## Build Commands

```bash
# Development build
swift build
make build

# Release build
swift build --configuration release
make release

# Run tests
swift test
make test

# Build with code signing
./build.sh --sign

# Full distribution build with notarization
./build.sh --clean --notarize --version 2025.01.15

# Build and install locally for testing
make install
```

## Running the Application

The binary requires root privileges for full system data collection:

```bash
# Run all modules
sudo .build/release/managedreportsrunner

# Run specific module
sudo .build/release/managedreportsrunner --run-module security

# Run multiple modules
sudo .build/release/managedreportsrunner --run-modules security,network,hardware

# Test configuration
sudo .build/release/managedreportsrunner --test

# Collect only (no transmission)
sudo .build/release/managedreportsrunner --collect-only
```

## Architecture

### Source Structure

```
Sources/
├── ReportMateClient.swift       # CLI entry point (@main), argument parsing
├── Core/
│   ├── ReportMateCore.swift     # Main coordinator, orchestrates services
│   ├── AppVersion.swift         # Auto-generated at build time (do not edit)
│   ├── Configuration/           # ConfigurationManager - plist/env/CLI config hierarchy
│   ├── Services/
│   │   ├── APIClient.swift      # HTTP client for ReportMate API
│   │   ├── BashService.swift    # Shell command execution
│   │   └── PythonService.swift  # LEGACY - do not use or extend
│   └── Utils/                   # SystemUtils for device info
├── DataCollection/
│   ├── DataCollectionService.swift  # Coordinates module execution
│   ├── OSQueryService.swift         # osquery integration with macadmins extension
│   ├── Modules/                     # Module processors (one per data type)
│   │   ├── ModuleProcessor.swift    # Base protocol + executeWithFallback()
│   │   ├── HardwareModuleProcessor.swift
│   │   ├── SecurityModuleProcessor.swift
│   │   └── ...
│   └── Services/
│       └── ApplicationUsageService.swift  # SQLite app usage tracking
├── Models/
│   ├── DeviceModels.swift       # DeviceInfo, EventMetadata, UnifiedDevicePayload
│   └── Modules/                 # Data models for each module type
└── AppUsageWatcher/             # Separate executable for app usage tracking
```

### Data Collection Flow

1. `ReportMateClient` parses CLI args, initializes `ConfigurationManager`
2. `ConfigurationManager` loads settings: defaults → plist → environment → CLI args
3. For each enabled module, creates a `ModuleProcessor` subclass
4. `ModuleProcessor.executeWithFallback()` tries: osquery → bash (no Python for new code)
5. Results aggregated into `UnifiedDevicePayload` matching Windows client format
6. `APIClient` transmits to ReportMate API

### Module Processors

Each module processor extends `BaseModuleProcessor` and implements `collectData()`. The base class provides `executeWithFallback(osquery:bash:)` - use only osquery and bash for data collection.

Available modules: `hardware`, `system`, `network`, `security`, `applications`, `management`, `inventory`, `displays`, `printers`, `peripherals`, `installs`, `profiles`

### Configuration Hierarchy (highest to lowest precedence)

1. Command-line arguments
2. Environment variables (`REPORTMATE_*` prefix)
3. System plist (`/Library/Application Support/ReportMate/reportmate.plist`)
4. User plist (`~/Library/Application Support/ReportMate/reportmate.plist`)
5. Embedded defaults

## Key Dependencies

- **swift-argument-parser**: CLI argument parsing
- **swift-log**: Structured logging
- **async-http-client**: API communication
- **SQLite.swift**: App usage persistence

## Build Script Notes

- `build.sh` generates `AppVersion.swift` with the version at build time and restores placeholder on exit
- Signing requires `.env` file with `SIGNING_IDENTITY_APP` and `SIGNING_IDENTITY_INSTALLER`
- PKG installer creates an app bundle at `/usr/local/reportmate/ReportMate.app`
- LaunchDaemons are embedded in the app bundle and installed by postinstall script

## LaunchDaemons

The installer creates multiple daemons with different schedules:
- `com.github.reportmate.boot` - Full collection at boot
- `com.github.reportmate.hourly` - security, profiles, network, management
- `com.github.reportmate.fourhourly` - applications, inventory, system
- `com.github.reportmate.daily` - hardware, displays (at 9 AM)
