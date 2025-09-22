# ReportMate macOS Client

ReportMate Client-side macOS application for gathering endpoint telemetry for monitoring dashboard using `osquery`.

Written in Swift 6.2. Designed to run as a native macOS binary with async/await and modern concurrency. It collects detailed device information using `osquery` with bash and Python fallbacks, and securely transmits it to the ReportMate API.

## Quick Start

### Prerequisites

- macOS 14.0+ (Sonoma)
- Xcode 15.0+ with Swift 6.2
- Swift Package Manager
- osquery (recommended via Homebrew: `brew install osquery`)

### Quick Build

```bash
# Simple build
make build

# Release build
make release

# Create distribution packages
make package

# Build and code sign
make sign
```

### Building ReportMate

The project uses Swift Package Manager with automated build scripts:

```bash
# Simple build
./build.sh

# Build specific version  
./build.sh --version "2024.06.27"

# Clean build for release
./build.sh --clean --version "2024.06.27" --api-url "https://api.reportmate.com" --sign
```

### Detailed Build Process

#### Development Build

```bash
# Build in debug mode
swift build

# Run tests
swift test

# Install locally for testing
make install
```

#### Release Build

```bash
# Build optimized binary
swift build --configuration release

# Create all distribution packages
./build.sh --version "1.0.0" --sign
```

#### Custom Build Options

```bash
# Build with specific version
./build.sh --version "2024.06.27"

# Clean build
./build.sh --clean --version "1.0.0"

# Build with API URL preset
./build.sh --api-url "https://api.reportmate.com" --sign

# Verbose build output
./build.sh --verbose
```

**📦 Output Packages:**

The build process creates three deployment formats:

1. **PKG Installer (Recommended)**
   - File: `ReportMate-{version}.pkg`
   - Use: Standard macOS installation via Installer.app
   - Deployment: Double-click to install, or `sudo installer -pkg ReportMate.pkg -target /`

2. **ZIP Archive**
   - File: `ReportMate-{version}.zip`
   - Use: Manual installation and automation
   - Deployment: Extract and copy files to appropriate locations

3. **DMG Disk Image**
   - File: `ReportMate-{version}.dmg`
   - Use: Distribution and manual installation
   - Deployment: Mount DMG and run Install.sh script

## Architecture

ReportMate for macOS follows a modular architecture similar to the Windows client, but optimized for macOS with native Swift async/await patterns:

```
┌─────────────────────────────────────────────────────────────────┐
│                      ReportMate macOS                         │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │    Main     │ │Configuration│ │ Data        │ │   osquery   │ │
│ │ Coordinator │ │  Manager    │ │ Collection  │ │   Service   │ │ 
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │     API     │ │ System Info │ │   Module    │ │   Logging   │ │
│ │   Client    │ │   Service   │ │ Processors  │ │ & Telemetry │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Data Collection                             │
├─────────────────────────────────────────────────────────────────┤
│ • System Information (system_profiler + osquery)               │
│ • Security Status (System Extensions, Gatekeeper, FileVault)   │
│ • Hardware Inventory (CPU, Memory, Disks, Peripherals)         │
│ • Software Inventory (Applications, Frameworks, Homebrew)      │
│ • Network Configuration (Interfaces, DNS, Proxies)             │
│ • Management Information (MDM, Profiles, Certificates)         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   ReportMate API (Azure)                       │
├─────────────────────────────────────────────────────────────────┤
│ • Secure HTTPS transmission                                     │
│ • Authentication & authorization                                │
│ • Real-time dashboard updates                                   │
│ • Data storage & analytics                                      │
└─────────────────────────────────────────────────────────────────┘
```

## Installation Locations

After deployment, files are organized following macOS conventions:

### Standard Installation
```
/usr/local/reportmate/
├── runner                          # Main executable
├── version.plist                   # Version information
└── config/
    ├── reportmate.plist           # Default configuration
    └── osquery/
        └── modules/               # Query modules

/Library/Application Support/ReportMate/
├── reportmate.plist               # System configuration
├── osquery/                       # osquery configurations
└── profiles/                      # Configuration Profile templates

/Library/LaunchDaemons/
└── com.reportmate.client.plist    # Launch daemon configuration
```

### Binaries (`/usr/local/reportmate/`)

- `runner` - Main ReportMate executable (Swift binary)
- `version.plist` - Build and version information
- `config/` - Default configuration files

### Working Data (`~/Library/Application Support/ReportMate/`)

- `reportmate.plist` - User-specific configuration
- `cache/` - Temporary cache files
- `logs/` - Application logs

### System Configuration (`/Library/Application Support/ReportMate/`)

- `reportmate.plist` - System-wide configuration
- `osquery/` - Modular osquery configuration directory
  - `enabled-modules.json` - Module configuration  
  - `modules/` - Individual module query files
- `profiles/` - Configuration Profile templates

## Key Features

### Core Functionality

- **Native Swift Performance**: Compiled Swift 6.2 binary with modern async/await
- **osquery Integration**: Primary data collection via osquery with intelligent fallbacks
- **Modular Architecture**: Individual processors for different data collection modules
- **macOS Native**: Leverages SystemConfiguration, IOKit, and macOS frameworks
- **Configuration Profiles**: Full support for MDM deployment via Configuration Profiles
- **Security Hardened**: Code-signed, sandboxed where appropriate, minimal privileges

### Data Collection Modules

- **Hardware Module**: CPU, memory, storage, peripherals via IOKit
- **System Module**: OS version, uptime, users, processes
- **Network Module**: Interfaces, routing, DNS, proxies
- **Security Module**: FileVault, Gatekeeper, System Integrity Protection
- **Applications Module**: Installed apps, Homebrew packages, App Store apps
- **Management Module**: MDM enrollment, Configuration Profiles, certificates
- **Inventory Module**: Device identification, asset tags, location services

### Enterprise Features

- **PKG Installer**: Standard macOS installer package
- **Configuration Profiles**: Native MDM configuration support
- **Logging & Monitoring**: Structured logging with os_log integration
- **Error Handling**: Comprehensive error recovery and reporting
- **Scheduled Execution**: LaunchDaemon integration for automated runs

## Installation Paths

### Standard Installation
```
/usr/local/reportmate/
├── runner                          # Main executable
├── version.plist                   # Version information
└── config/
    ├── reportmate.plist           # Default configuration
    └── osquery/
        └── modules/               # Query modules

/Library/Application Support/ReportMate/
├── reportmate.plist               # System configuration
├── osquery/                       # osquery configurations
└── profiles/                      # Configuration Profile templates

/Library/LaunchDaemons/
└── com.reportmate.client.plist    # Launch daemon configuration
```

## Command Line Interface

```bash
# Run data collection (default action)
/usr/local/reportmate/runner run [--force] [--device-id ID] [--api-url URL]

# Test configuration and connectivity  
/usr/local/reportmate/runner test [--verbose]

# Display system information
/usr/local/reportmate/runner info [--json]

# Install and configure
sudo /usr/local/reportmate/runner install --api-url URL [--device-id ID] [--api-key KEY]
```

## Configuration Management

The application uses a configuration hierarchy optimized for macOS:

1. **Command-line arguments** (highest precedence)
2. **Environment variables** (`REPORTMATE_*`)
3. **Configuration Profiles** (MDM-managed)
4. **System plist** (`/Library/Application Support/ReportMate/reportmate.plist`)
5. **User plist** (`~/Library/Application Support/ReportMate/reportmate.plist`)
6. **Default configuration** (embedded in binary)

### Configuration Profile Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.reportmate.client</string>
            <key>PayloadIdentifier</key>
            <string>com.reportmate.client.settings</string>
            <key>PayloadUUID</key>
            <string>12345678-1234-1234-1234-123456789012</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ApiUrl</key>
            <string>https://api.reportmate.yourdomain.com</string>
            <key>CollectionInterval</key>
            <integer>3600</integer>
            <key>LogLevel</key>
            <string>info</string>
            <key>EnabledModules</key>
            <array>
                <string>hardware</string>
                <string>system</string>
                <string>network</string>
                <string>security</string>
                <string>applications</string>
                <string>management</string>
            </array>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>ReportMate Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.reportmate.client</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>87654321-4321-4321-4321-210987654321</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

## Requirements

### Runtime Requirements
- macOS 14.0+ (Sonoma)
- Administrator privileges for full data collection
- Network connectivity to ReportMate API
- osquery (automatically installed if missing)

### Build Requirements  
- macOS 14.0+
- Xcode 15.0+ with Swift 6.2
- Swift Package Manager
- Homebrew (for dependencies)

## Building and Development

### Code Signing

#### Automatic Code Signing

The build script automatically detects available Developer ID certificates:

```bash
./build.sh --sign
```

#### Manual Code Signing

```bash
# List available identities
security find-identity -v -p codesigning

# Sign with specific identity
codesign --sign "Developer ID Application: Your Name" --force --options runtime build/runner
```

### Development Workflow

#### Setup Development Environment

```bash
# Install dependencies
make dev-setup

# Format code
make format

# Lint code  
make lint

# Clone and setup
git clone <repo-url>
cd reportmate-client-mac

# Install dependencies
brew install osquery

# Build and test
swift build
swift test

# Create release build
./build.sh --configuration release --sign
```

### Testing

```bash
# Run unit tests
swift test
make test

# Integration tests  
./test.sh --integration

# Manual testing
swift run runner test --verbose

# Test binary directly
.build/release/runner --help
.build/release/runner test --verbose
```

#### Local Installation for Testing

```bash
# Install locally
make install

# Test installation
/usr/local/reportmate/runner info
```

### Build Environment Variables

The build process recognizes these environment variables:

- `VERSION` - Override build version
- `API_URL` - Default API endpoint for configuration
- `CONFIGURATION` - Build configuration (debug/release)

Example:
```bash
VERSION=1.0.0 API_URL=https://api.reportmate.com ./build.sh --sign
```

### Performance

#### Build Times
- Debug build: ~30 seconds
- Release build: ~60 seconds  
- Package creation: ~30 seconds

#### Binary Size
- Debug build: ~15MB
- Release build: ~8MB
- Compressed in ZIP: ~3MB

### Troubleshooting

#### Common Build Issues

1. **Swift Version Mismatch**
   ```bash
   # Check Swift version
   swift --version
   # Should be 6.0+
   ```

2. **Missing Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

3. **Package Dependencies**
   ```bash
   # Clean and rebuild packages
   swift package clean
   swift package resolve
   ```

#### Code Signing Issues

1. **No Identity Found**
   - Install Xcode and sign in with Apple Developer account
   - Or create self-signed certificate for testing

2. **Unsigned Binary Warnings**
   - Use `--sign` flag during build
   - Or manually sign after build

#### Runtime Issues

1. **Permission Denied**
   ```bash
   chmod +x /usr/local/reportmate/runner
   ```

2. **osquery Not Found**
   ```bash
   brew install osquery
   # Or set custom path in configuration
   ```

### CI/CD Integration

#### GitHub Actions Example

```yaml
name: Build ReportMate macOS Client

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: macos-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build
      run: |
        ./build.sh --version ${GITHUB_REF#refs/tags/v} --sign
    - name: Upload Artifacts
      uses: actions/upload-artifact@v3
      with:
        name: ReportMate-packages
        path: build/output/
```

### Security Considerations

1. **Code Signing**: Always sign production binaries
2. **Notarization**: Consider notarizing for wider distribution
3. **Sandboxing**: Evaluate sandboxing requirements
4. **Permissions**: Binary requires admin privileges for full data collection

This project represents a complete rewrite optimized for macOS while maintaining compatibility with the ReportMate ecosystem. The build system provides a complete solution for developing, testing, and distributing the ReportMate macOS client with comprehensive tooling for code signing, packaging, and deployment.
