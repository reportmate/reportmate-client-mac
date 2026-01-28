#!/bin/bash

# ReportMate Unified Build Script
# One-stop build script that replicates the CI pipeline locally.
# Builds PKG installer, signs, and optionally notarizes for distribution.

set -e

# Load environment variables from .env if it exists
if [ -f "${BASH_SOURCE%/*}/.env" ]; then
    echo "[INFO] Loading configuration from .env"
    set -a
    source "${BASH_SOURCE%/*}/.env"
    set +a
fi

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

PROJECT_NAME="ReportMate"
PRODUCT_NAME="managedreportsrunner"
BUNDLE_ID="com.github.reportmate.managedreportsrunner"
PKG_IDENTIFIER="ca.ecuad.reportmate.client"

# Signing configuration - must be provided via .env or flags
# No defaults to avoid exposing personal/org info in public repo
TEAM_ID="${TEAM_ID:-}"
SIGNING_IDENTITY_APP="${SIGNING_IDENTITY_APP:-}"
SIGNING_IDENTITY_INSTALLER="${SIGNING_IDENTITY_INSTALLER:-}"
SIGNING_TIMESTAMP="${SIGNING_TIMESTAMP:-true}"
SIGNING_KEYCHAIN="${SIGNING_KEYCHAIN:-}"
NOTARIZATION_APPLE_ID="${NOTARIZATION_APPLE_ID:-}"
NOTARIZATION_PASSWORD="${NOTARIZATION_PASSWORD:-}"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
PKG_DIR="${BUILD_DIR}/pkg"
RESOURCES_DIR="${BUILD_DIR}/resources"
DIST_DIR="${SCRIPT_DIR}/dist"
OUTPUT_DIR="${BUILD_DIR}/output"

# ═══════════════════════════════════════════════════════════════════════════
# DEFAULT OPTIONS
# ═══════════════════════════════════════════════════════════════════════════

VERSION=""
CONFIGURATION="release"
CLEAN=false
SIGN=false
DISTRIBUTION=false
NOTARIZE=false
SKIP_BUILD=false
SKIP_PKG=false
SKIP_ZIP=false
SKIP_DMG=false
API_URL=""
VERBOSE=false
INSTALL=false
CREATE_TAG=false
CREATE_RELEASE=false

# ═══════════════════════════════════════════════════════════════════════════
# COLORS & LOGGING
# ═══════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
log_warn()    { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error()   { echo -e "${RED}[ERROR] $1${NC}"; }
log_info()    { echo -e "${CYAN}[INFO] $1${NC}"; }
log_header()  { echo -e "${MAGENTA}$1${NC}"; }
log_step()    { echo -e "${YELLOW}$1${NC}"; }

# ═══════════════════════════════════════════════════════════════════════════
# HELP
# ═══════════════════════════════════════════════════════════════════════════

show_help() {
    cat << EOF
ReportMate Unified Build Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --version <VERSION>     Version to build (default: YYYY.MM.DD.HHMM)
    --debug                 Build in debug configuration
    --release               Build in release configuration (default)
    
    --clean                 Clean all build artifacts first
    --skip-build            Skip the Swift build step
    --skip-pkg              Skip PKG installer creation
    --skip-zip              Skip ZIP creation
    --skip-dmg              Skip DMG creation
    
    --sign                  Sign executable for development
    --distribution          Sign with Developer ID for distribution
    --notarize              Sign, notarize, and staple for distribution
    
    --api-url <URL>         Default API URL to configure in the installer
    --install               Install the built package after building
    
    --create-tag            Create and push a git tag
    --create-release        Create a GitHub release (requires gh CLI)
    
    --verbose               Enable verbose output
    --help                  Show this help message

EXAMPLES:
    # Simple build
    $0

    # Clean release build with signing
    $0 --clean --sign

    # Full distribution build with notarization
    $0 --clean --notarize --version 2025.11.30

    # Build and install locally
    $0 --sign --install

    # Build specific version with API URL
    $0 --version "2025.11.30" --api-url "https://reportmate.ecuad.ca"

    # Create release
    $0 --notarize --create-tag --create-release

EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════
# PARSE ARGUMENTS
# ═══════════════════════════════════════════════════════════════════════════

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --debug)
            CONFIGURATION="debug"
            shift
            ;;
        --release)
            CONFIGURATION="release"
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-pkg)
            SKIP_PKG=true
            shift
            ;;
        --skip-zip)
            SKIP_ZIP=true
            shift
            ;;
        --skip-dmg)
            SKIP_DMG=true
            shift
            ;;
        --sign)
            SIGN=true
            shift
            ;;
        --distribution)
            DISTRIBUTION=true
            SIGN=true
            shift
            ;;
        --notarize)
            NOTARIZE=true
            DISTRIBUTION=true
            SIGN=true
            shift
            ;;
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --install)
            INSTALL=true
            shift
            ;;
        --create-tag)
            CREATE_TAG=true
            shift
            ;;
        --create-release)
            CREATE_RELEASE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Change to script directory to ensure relative paths work
cd "$SCRIPT_DIR"

# ═══════════════════════════════════════════════════════════════════════════
# VERSION
# ═══════════════════════════════════════════════════════════════════════════

# Generate version dynamically: YYYY.MM.DD.HHMM
if [ -z "$VERSION" ]; then
    VERSION="$(date +%Y.%m.%d.%H%M)"
fi

# Export as REPORTMATE_VERSION for envsubst substitution in scripts and build-info.yaml
export REPORTMATE_VERSION="$VERSION"

# ═══════════════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════════════

log_header "ReportMate macOS Build Script"
echo ""
log_info "Version: ${VERSION}"
log_info "Configuration: ${CONFIGURATION}"
log_info "Sign: ${SIGN}"
log_info "Distribution: ${DISTRIBUTION}"
log_info "Notarize: ${NOTARIZE}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PREREQUISITES
# ═══════════════════════════════════════════════════════════════════════════

log_step "Checking prerequisites..."

if ! command -v swift &> /dev/null; then
    log_error "Swift is not installed or not in PATH"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    log_error "Xcode command line tools are not installed"
    exit 1
fi

SWIFT_VERSION=$(swift --version 2>&1 | head -n 1 | sed 's/.*Swift version \([0-9]\+\.[0-9]\+\).*/\1/')
log_success "Swift version: ${SWIFT_VERSION}"

# ═══════════════════════════════════════════════════════════════════════════
# CLEAN
# ═══════════════════════════════════════════════════════════════════════════

if [ "$CLEAN" = true ]; then
    log_step "Cleaning build artifacts..."
    swift package clean 2>/dev/null || true
    rm -rf "${OUTPUT_DIR}" "${DIST_DIR}" .build/release .build/debug
    log_success "Clean complete"
fi

# Create directories
mkdir -p "${OUTPUT_DIR}" "${DIST_DIR}"

# ═══════════════════════════════════════════════════════════════════════════
# GENERATE VERSION FILE
# ═══════════════════════════════════════════════════════════════════════════

# Generate AppVersion.swift with hardcoded version at build time
cat > "${SCRIPT_DIR}/Sources/Core/AppVersion.swift" << EOF
import Foundation

/// Centralized version management for ReportMate macOS client
/// Version format: YYYY.MM.DD.HHMM (build timestamp)
/// This file is auto-generated at build time - do not edit manually
public enum AppVersion {
    /// The current application version (generated at build time)
    public static let current: String = "${VERSION}"
    
    /// Short version for display
    public static var short: String {
        let parts = current.split(separator: ".")
        if parts.count >= 3 {
            return "\\(parts[0]).\\(parts[1]).\\(parts[2])"
        }
        return current
    }
    
    /// Build number (HHMM portion or full version)
    public static var build: String {
        let parts = current.split(separator: ".")
        if parts.count >= 4 {
            return String(parts[3])
        }
        return current
    }
}
EOF

log_info "Generated AppVersion.swift with version: ${VERSION}"

# Function to restore AppVersion.swift placeholder
restore_version_placeholder() {
    cat > "${SCRIPT_DIR}/Sources/Core/AppVersion.swift" << 'EOF'
import Foundation

/// Centralized version management for ReportMate macOS client
/// Version format: YYYY.MM.DD.HHMM (build timestamp)
/// This file is auto-generated at build time - do not edit manually
public enum AppVersion {
    /// The current application version (generated at build time)
    public static let current: String = "YYYY.MM.DD.HHMM"
    
    /// Short version for display
    public static var short: String {
        let parts = current.split(separator: ".")
        if parts.count >= 3 {
            return "\(parts[0]).\(parts[1]).\(parts[2])"
        }
        return current
    }
    
    /// Build number (HHMM portion or full version)
    public static var build: String {
        let parts = current.split(separator: ".")
        if parts.count >= 4 {
            return String(parts[3])
        }
        return current
    }
}
EOF
    log_info "Restored AppVersion.swift placeholder"
}

# Set trap to restore placeholder on exit
trap restore_version_placeholder EXIT

# ═══════════════════════════════════════════════════════════════════════════
# BUILD
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SKIP_BUILD" = false ]; then
    log_step "Building ${PROJECT_NAME}..."
    
    BUILD_FLAGS="-c ${CONFIGURATION}"
    if [ "$VERBOSE" = true ]; then
        BUILD_FLAGS="${BUILD_FLAGS} --verbose"
    fi
    
    # Pass version to Swift via environment variable
    export REPORTMATE_VERSION="$VERSION"
    
    swift build ${BUILD_FLAGS}
    
    if [ "$CONFIGURATION" = "release" ]; then
        # Try arm64 first, fall back to x86_64
        if [ -d ".build/arm64-apple-macosx/release" ]; then
            BUILD_PATH=".build/arm64-apple-macosx/release"
        elif [ -d ".build/x86_64-apple-macosx/release" ]; then
            BUILD_PATH=".build/x86_64-apple-macosx/release"
        else
            BUILD_PATH=".build/release"
        fi
    else
        if [ -d ".build/arm64-apple-macosx/debug" ]; then
            BUILD_PATH=".build/arm64-apple-macosx/debug"
        elif [ -d ".build/x86_64-apple-macosx/debug" ]; then
            BUILD_PATH=".build/x86_64-apple-macosx/debug"
        else
            BUILD_PATH=".build/debug"
        fi
    fi
    
    EXECUTABLE_PATH="${BUILD_PATH}/${PRODUCT_NAME}"
    
    if [ ! -f "$EXECUTABLE_PATH" ]; then
        log_error "Build failed - executable not found at: $EXECUTABLE_PATH"
        exit 1
    fi
    
    log_success "Build completed: ${EXECUTABLE_PATH}"
else
    log_info "Skipping build step"
    if [ "$CONFIGURATION" = "release" ]; then
        BUILD_PATH=".build/arm64-apple-macosx/release"
        [ ! -d "$BUILD_PATH" ] && BUILD_PATH=".build/release"
    else
        BUILD_PATH=".build/arm64-apple-macosx/debug"
        [ ! -d "$BUILD_PATH" ] && BUILD_PATH=".build/debug"
    fi
    EXECUTABLE_PATH="${BUILD_PATH}/${PRODUCT_NAME}"
fi

# Copy binary to dist
cp "$EXECUTABLE_PATH" "${DIST_DIR}/${PRODUCT_NAME}"

# ═══════════════════════════════════════════════════════════════════════════
# CODE SIGNING
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SIGN" = true ]; then
    log_step "Code signing..."
    
    # Validate signing identity is provided
    if [ -z "$SIGNING_IDENTITY_APP" ]; then
        log_error "SIGNING_IDENTITY_APP not set. Please configure in .env or export it."
        exit 1
    fi
    
    if [ "$DISTRIBUTION" = true ]; then
        SIGNING_IDENTITY="$SIGNING_IDENTITY_APP"
        ENTITLEMENTS_FILE="${SCRIPT_DIR}/ReportMate-Distribution.entitlements"
        log_info "Signing for distribution with: ${SIGNING_IDENTITY}"
    else
        SIGNING_IDENTITY="$SIGNING_IDENTITY_APP"
        ENTITLEMENTS_FILE="${SCRIPT_DIR}/ReportMate.entitlements"
        log_info "Signing for development with: ${SIGNING_IDENTITY}"
    fi
    
    CODESIGN_ARGS=(
        --force
        --sign "$SIGNING_IDENTITY"
        --entitlements "$ENTITLEMENTS_FILE"
        --options runtime
    )
    
    if [ "$SIGNING_TIMESTAMP" = "true" ]; then
        CODESIGN_ARGS+=(--timestamp)
    fi
    
    if [ -n "$SIGNING_KEYCHAIN" ]; then
        CODESIGN_ARGS+=(--keychain "$SIGNING_KEYCHAIN")
    fi
    
    if [ -n "$VERBOSE" ]; then
        CODESIGN_ARGS+=(--verbose)
    fi
    
    codesign "${CODESIGN_ARGS[@]}" "${DIST_DIR}/${PRODUCT_NAME}"
    
    # Verify signature
    codesign --verify --verbose=2 "${DIST_DIR}/${PRODUCT_NAME}"
    log_success "Code signing complete"
fi

# Version info embedded in binary via AppVersion.swift

# ═══════════════════════════════════════════════════════════════════════════
# PKG INSTALLER
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SKIP_PKG" = false ]; then
    log_step "Creating PKG installer with .app bundle..."
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CREATE APP BUNDLE STRUCTURE (like macadmins/outset)
    # ═══════════════════════════════════════════════════════════════════════════
    
    PACKAGE_ROOT="${OUTPUT_DIR}/package_root"
    rm -rf "$PACKAGE_ROOT"
    
    # App bundle structure
    APP_BUNDLE="${PACKAGE_ROOT}/usr/local/reportmate/ReportMate.app"
    APP_CONTENTS="${APP_BUNDLE}/Contents"
    APP_MACOS="${APP_CONTENTS}/MacOS"
    APP_RESOURCES="${APP_CONTENTS}/Resources"
    APP_LAUNCHDAEMONS="${APP_CONTENTS}/Library/LaunchDaemons"
    
    mkdir -p "$APP_MACOS"
    mkdir -p "$APP_RESOURCES"
    mkdir -p "$APP_LAUNCHDAEMONS"
    mkdir -p "$PACKAGE_ROOT/Library/Managed Reports/logs"
    mkdir -p "$PACKAGE_ROOT/etc/paths.d"
    
    # Add reportmate to PATH
    echo "/usr/local/reportmate" > "$PACKAGE_ROOT/etc/paths.d/reportmate"
    
    # Copy executable to app bundle
    cp "${DIST_DIR}/${PRODUCT_NAME}" "$APP_MACOS/"
    
    # Create wrapper script for CLI access
    cat > "$PACKAGE_ROOT/usr/local/reportmate/managedreportsrunner" << 'WRAPPER'
#!/bin/sh
# ReportMate CLI wrapper
/usr/local/reportmate/ReportMate.app/Contents/MacOS/managedreportsrunner "${@}"
WRAPPER
    chmod 755 "$PACKAGE_ROOT/usr/local/reportmate/managedreportsrunner"

    # ═══════════════════════════════════════════════════════════════════════════
    # OSQUERY MACADMINS EXTENSION
    # ═══════════════════════════════════════════════════════════════════════════

    EXTENSION_SOURCE="${SCRIPT_DIR}/Sources/Resources/extensions/macadmins_extension.ext"
    if [ -f "$EXTENSION_SOURCE" ]; then
        log_info "Bundling macadmins osquery extension..."
        cp "$EXTENSION_SOURCE" "$PACKAGE_ROOT/usr/local/reportmate/"
        chmod 755 "$PACKAGE_ROOT/usr/local/reportmate/macadmins_extension.ext"
        log_success "Extension bundled: macadmins_extension.ext"
    else
        log_warn "macadmins extension not found at: $EXTENSION_SOURCE"
        log_info "Download from: https://github.com/macadmins/osquery-extension/releases"
    fi

    # Create Info.plist for app bundle
    cat > "$APP_CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>managedreportsrunner</string>
    <key>CFBundleIconFile</key>
    <string>ReportMate</string>
    <key>CFBundleIconName</key>
    <string>ReportMate</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>ReportMate</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSBackgroundOnly</key>
    <true/>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2025 ReportMate Contributors. All rights reserved.</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
EOF
    
    # Create PkgInfo
    echo "APPL????" > "$APP_CONTENTS/PkgInfo"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # LAUNCHDAEMONS (embedded in app bundle like Outset)
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Boot daemon - runs all modules at system startup
    cat > "$APP_LAUNCHDAEMONS/com.github.reportmate.boot.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.reportmate.boot</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/reportmate/ReportMate.app/Contents/MacOS/managedreportsrunner</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LaunchOnlyOnce</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Managed Reports/logs/reportmate-boot.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Managed Reports/logs/reportmate-boot.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>Nice</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>AssociatedBundleIdentifiers</key>
    <string>com.github.reportmate.managedreportsrunner</string>
</dict>
</plist>
EOF

    # Hourly daemon - security, profiles, network, management
    cat > "$APP_LAUNCHDAEMONS/com.github.reportmate.hourly.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.reportmate.hourly</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/reportmate/ReportMate.app/Contents/MacOS/managedreportsrunner</string>
        <string>--run-modules</string>
        <string>security,profiles,network,management</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/Library/Managed Reports/logs/reportmate-hourly.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Managed Reports/logs/reportmate-hourly.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>Nice</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>AssociatedBundleIdentifiers</key>
    <string>com.github.reportmate.managedreportsrunner</string>
</dict>
</plist>
EOF

    # 4-hourly daemon - applications, inventory, system
    cat > "$APP_LAUNCHDAEMONS/com.github.reportmate.fourhourly.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.reportmate.fourhourly</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/reportmate/ReportMate.app/Contents/MacOS/managedreportsrunner</string>
        <string>--run-modules</string>
        <string>applications,inventory,system</string>
    </array>
    <key>StartInterval</key>
    <integer>14400</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/Library/Managed Reports/logs/reportmate-4hourly.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Managed Reports/logs/reportmate-4hourly.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>Nice</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>AssociatedBundleIdentifiers</key>
    <string>com.github.reportmate.managedreportsrunner</string>
</dict>
</plist>
EOF

    # Daily daemon - hardware, displays (at 9 AM)
    cat > "$APP_LAUNCHDAEMONS/com.github.reportmate.daily.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.reportmate.daily</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/reportmate/ReportMate.app/Contents/MacOS/managedreportsrunner</string>
        <string>--run-modules</string>
        <string>hardware,displays</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>9</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/Library/Managed Reports/logs/reportmate-daily.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Managed Reports/logs/reportmate-daily.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>Nice</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>AssociatedBundleIdentifiers</key>
    <string>com.github.reportmate.managedreportsrunner</string>
</dict>
</plist>
EOF

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE SCHEDULES CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    cat > "$APP_RESOURCES/module-schedules.json" << 'EOF'
{
  "schedules": {
    "hourly": {
      "modules": ["security", "profiles", "network", "management"],
      "interval_seconds": 3600,
      "launchd_label": "com.github.reportmate.hourly",
      "description": "Modules that need frequent updates for security monitoring"
    },
    "fourhourly": {
      "modules": ["applications", "inventory", "system"],
      "interval_seconds": 14400,
      "launchd_label": "com.github.reportmate.fourhourly",
      "description": "Modules that change moderately - software and device info"
    },
    "daily": {
      "modules": ["hardware", "displays"],
      "calendar_interval": {"hour": 9, "minute": 0},
      "launchd_label": "com.github.reportmate.daily",
      "description": "Modules that rarely change - physical hardware"
    },
    "boot": {
      "modules": "all",
      "run_at_load": true,
      "launch_only_once": true,
      "launchd_label": "com.github.reportmate.boot",
    "description": "Full collection at boot to establish baseline"
    }
  },
  "version": "1.0.0",
  "platform": "macOS"
}
EOF

    # ═══════════════════════════════════════════════════════════════════════════
    # MUNKI POSTFLIGHT RESOURCES
    # ═══════════════════════════════════════════════════════════════════════════
    
    MUNKI_RESOURCES_SRC="${BUILD_DIR}/resources/munki"
    MUNKI_RESOURCES_DST="${APP_RESOURCES}/munki"
    
    if [ -d "$MUNKI_RESOURCES_SRC" ]; then
        log_info "Bundling Munki postflight integration scripts..."
        mkdir -p "$MUNKI_RESOURCES_DST"
        cp "$MUNKI_RESOURCES_SRC"/* "$MUNKI_RESOURCES_DST/"
        chmod 755 "$MUNKI_RESOURCES_DST"/*
        log_success "Munki postflight scripts bundled"
    else
        log_warn "Munki resources not found at: $MUNKI_RESOURCES_SRC"
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # APP ICON (Liquid Glass / Tahoe icon pipeline for macOS Sequoia+)
    # ═══════════════════════════════════════════════════════════════════════════
    
    ICON_SOURCE="${SCRIPT_DIR}/packages/client/Resources/ReportMate.icon"
    if [ -d "$ICON_SOURCE" ]; then
        log_info "Compiling Liquid Glass icon (.icon → Assets.car)"
        
        # Create temporary directory for icon compilation
        ICON_BUILD_DIR="${BUILD_DIR}/icon_assets"
        mkdir -p "$ICON_BUILD_DIR"
        
        # Compile .icon to Assets.car using actool
        # The .icon directory is the modern Liquid Glass format from Icon Composer
        xcrun actool "$ICON_SOURCE" \
            --compile "$ICON_BUILD_DIR" \
            --app-icon "ReportMate" \
            --enable-on-demand-resources NO \
            --development-region en \
            --target-device mac \
            --platform macosx \
            --minimum-deployment-target 14.0 \
            --include-all-app-icons \
            --output-partial-info-plist /dev/null 2>&1 || true
        
        # Copy compiled Assets.car to app bundle (actool may emit warnings but still produce Assets.car)
        if [ -f "$ICON_BUILD_DIR/Assets.car" ]; then
            cp "$ICON_BUILD_DIR/Assets.car" "$APP_RESOURCES/Assets.car"
            log_success "Icon compiled and installed: Assets.car"
            
            # Also copy the .icns fallback if generated (for pre-Sequoia compatibility)
            if [ -f "$ICON_BUILD_DIR/ReportMate.icns" ]; then
                cp "$ICON_BUILD_DIR/ReportMate.icns" "$APP_RESOURCES/ReportMate.icns"
                log_info "Legacy .icns fallback also installed"
            fi
        else
            log_error "Failed to compile icon - Assets.car not generated"
            exit 1
        fi
    else
        log_warn "Icon not found at ${ICON_SOURCE}"
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # DEFAULT CONFIGURATION PLIST
    # ═══════════════════════════════════════════════════════════════════════════
    
    cat > "$PACKAGE_ROOT/Library/Managed Reports/reportmate.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
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
        <string>inventory</string>
        <string>profiles</string>
        <string>displays</string>
    </array>
    <key>OsqueryPath</key>
    <string>/usr/local/bin/osqueryi</string>
    <key>OsqueryExtensionPath</key>
    <string>/usr/local/reportmate/macadmins_extension.ext</string>
    <key>ExtensionEnabled</key>
    <true/>
    <key>ValidateSSL</key>
    <true/>
    <key>Timeout</key>
    <integer>300</integer>
$([ -n "$API_URL" ] && echo "    <key>ApiUrl</key>
    <string>$API_URL</string>")
</dict>
</plist>
EOF

    # ═══════════════════════════════════════════════════════════════════════════
    # SIGN THE APP BUNDLE (if signing enabled)
    # ═══════════════════════════════════════════════════════════════════════════
    
    if [ "$SIGN" = true ]; then
        log_step "Signing app bundle..."
        
        SIGNING_IDENTITY="$SIGNING_IDENTITY_APP"
        if [ "$DISTRIBUTION" = true ]; then
            ENTITLEMENTS_FILE="${SCRIPT_DIR}/ReportMate-Distribution.entitlements"
            log_info "Signing app bundle for distribution"
        else
            ENTITLEMENTS_FILE="${SCRIPT_DIR}/ReportMate.entitlements"
            log_info "Signing app bundle for development"
        fi
        
        CODESIGN_ARGS=(
            --force
            --sign "$SIGNING_IDENTITY"
            --entitlements "$ENTITLEMENTS_FILE"
            --options runtime
        )
        
        if [ "$SIGNING_TIMESTAMP" = "true" ]; then
            CODESIGN_ARGS+=(--timestamp)
        fi
        
        if [ -n "$SIGNING_KEYCHAIN" ]; then
            CODESIGN_ARGS+=(--keychain "$SIGNING_KEYCHAIN")
        fi
        
        if [ -n "$VERBOSE" ]; then
            CODESIGN_ARGS+=(--verbose)
        fi
        
        # Sign the main executable
        codesign "${CODESIGN_ARGS[@]}" "$APP_MACOS/${PRODUCT_NAME}"
        
        # Sign the app bundle
        codesign "${CODESIGN_ARGS[@]}" --deep "$APP_BUNDLE"
        
        # Verify
        codesign --verify --verbose=2 "$APP_BUNDLE"
        log_success "App bundle signed"
    fi

    # Copy scripts from packages/client/Scripts (new location) or build/pkg/scripts (legacy)
    SCRIPTS_DIR="${OUTPUT_DIR}/scripts"
    rm -rf "$SCRIPTS_DIR"
    mkdir -p "$SCRIPTS_DIR"
    
    # Use new packages/client/Scripts if available, otherwise fall back to legacy
    PKG_SCRIPTS_DIR="${SCRIPT_DIR}/packages/client/Scripts"
    if [ -d "$PKG_SCRIPTS_DIR" ]; then
        log_info "Using packages/client/Scripts for installer scripts"
        for script in "$PKG_SCRIPTS_DIR/"*; do
            if [ -f "$script" ]; then
                script_name=$(basename "$script")
                if [ "$script_name" = "managedreportsrunner" ]; then
                    continue  # Skip the wrapper script
                fi
                cp "$script" "$SCRIPTS_DIR/$script_name"
                chmod +x "$SCRIPTS_DIR/$script_name"
            fi
        done
    elif [ -d "${PKG_DIR}/scripts" ]; then
        # Legacy: Load .env file if it exists for variable substitution
        if [ -f "${PKG_DIR}/.env" ]; then
            log_info "Loading environment from ${PKG_DIR}/.env"
            set -a
            source "${PKG_DIR}/.env"
            set +a
        fi
        
        SUBST_VARS='${REPORTMATE_CUSTOM_DOMAIN_NAME} ${REPORTMATE_CLIENT_PASSPHRASE} ${REPORTMATE_VERSION}'
        
        for script in "${PKG_DIR}/scripts/"*; do
            if [ -f "$script" ] && [ "$(basename "$script")" != "README.md" ]; then
                script_name=$(basename "$script")
                envsubst "$SUBST_VARS" < "$script" > "$SCRIPTS_DIR/$script_name"
                chmod +x "$SCRIPTS_DIR/$script_name"
            fi
        done
    else
        # Create default postinstall script
        log_info "Creating default postinstall script"
        cat > "$SCRIPTS_DIR/postinstall" << 'POSTINSTALL_SCRIPT'
#!/bin/zsh
# ReportMate Postinstall
LD_ROOT="/Library/LaunchDaemons"
APP_PATH="/usr/local/reportmate/ReportMate.app"
APP_ROOT="${APP_PATH}/Contents"
LOG_DIR="/Library/Managed Reports/logs"

log_message() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

log_message "Starting ReportMate postinstall..."

mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# ═══════════════════════════════════════════════════════════════════════════
# INSTALL OSQUERY IF MISSING
# ═══════════════════════════════════════════════════════════════════════════

OSQUERY_PATH="/usr/local/bin/osqueryi"
OSQUERY_VERSION="5.21.0"  # Pin to known compatible version with macadmins extension

if [ ! -f "$OSQUERY_PATH" ]; then
    log_message "osquery not found, installing..."

    # Determine architecture
    ARCH=$(uname -m)
    if [ "$ARCH" = "arm64" ]; then
        PKG_URL="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery-${OSQUERY_VERSION}.pkg"
    else
        PKG_URL="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery-${OSQUERY_VERSION}.pkg"
    fi

    TEMP_PKG="/tmp/osquery-${OSQUERY_VERSION}.pkg"

    log_message "Downloading osquery ${OSQUERY_VERSION}..."
    if /usr/bin/curl -L -s -o "$TEMP_PKG" "$PKG_URL"; then
        log_message "Installing osquery..."
        if /usr/sbin/installer -pkg "$TEMP_PKG" -target / >/dev/null 2>&1; then
            log_message "osquery installed successfully"
        else
            log_message "WARNING: osquery installation failed"
        fi
        rm -f "$TEMP_PKG"
    else
        log_message "WARNING: Failed to download osquery"
    fi
else
    log_message "osquery already installed at $OSQUERY_PATH"
fi

# Make extension executable
chmod 755 /usr/local/reportmate/macadmins_extension.ext 2>/dev/null

# Register app bundle
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister "${APP_PATH}"

# LaunchDaemons to install
DAEMONS=(
    "com.github.reportmate.boot.plist"
    "com.github.reportmate.hourly.plist"
    "com.github.reportmate.fourhourly.plist"
    "com.github.reportmate.daily.plist"
)

# Remove legacy daemon
if [ -e "${LD_ROOT}/com.github.reportmate.plist" ]; then
    log_message "Removing legacy daemon..."
    /bin/launchctl bootout system "${LD_ROOT}/com.github.reportmate.plist" 2>/dev/null
    rm -f "${LD_ROOT}/com.github.reportmate.plist"
fi

# Unload existing and install new daemons
for daemon in ${DAEMONS}; do
    daemon_path="${LD_ROOT}/${daemon}"
    if [ -e "${daemon_path}" ]; then
        /bin/launchctl bootout system "${daemon_path}" 2>/dev/null
        rm -f "${daemon_path}"
    fi
done

for daemon in ${DAEMONS}; do
    source_path="${APP_ROOT}/Library/LaunchDaemons/${daemon}"
    dest_path="${LD_ROOT}/${daemon}"
    
    if [ -e "${source_path}" ]; then
        log_message "Installing: ${daemon}"
        cp "${source_path}" "${dest_path}"
        chmod 644 "${dest_path}"
        chown root:wheel "${dest_path}"
        /bin/launchctl bootstrap system "${dest_path}"
    fi
done

# Make wrapper executable
chmod 755 /usr/local/reportmate/managedreportsrunner 2>/dev/null

# Create/update symlink in /usr/local/bin to ensure the latest binary is used
# This handles upgrades where an old binary might exist in /usr/local/bin
log_message "Creating symlink in /usr/local/bin..."
mkdir -p /usr/local/bin
rm -f /usr/local/bin/managedreportsrunner 2>/dev/null
ln -sf "${APP_PATH}/Contents/MacOS/managedreportsrunner" /usr/local/bin/managedreportsrunner
log_message "Symlink created: /usr/local/bin/managedreportsrunner -> ${APP_PATH}/Contents/MacOS/managedreportsrunner"

# PATH entry (keep for backward compatibility with wrapper)
echo "/usr/local/reportmate" > /etc/paths.d/reportmate 2>/dev/null

# ═══════════════════════════════════════════════════════════════════════════
# MUNKI POSTFLIGHT INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════
# Install wrapper postflight that implements postflight.d/ directory support
# This allows both MunkiReport and ReportMate to run after Munki updates

MUNKI_DIR="/usr/local/munki"
POSTFLIGHT_D="${MUNKI_DIR}/postflight.d"
POSTFLIGHT="${MUNKI_DIR}/postflight"
MUNKI_RESOURCES="${APP_ROOT}/Resources/munki"

# Only install if Munki is present
if [ -d "$MUNKI_DIR" ]; then
    log_message "Munki detected, installing postflight integration..."
    
    # Create postflight.d directory
    mkdir -p "$POSTFLIGHT_D"
    chmod 755 "$POSTFLIGHT_D"
    
    # Backup existing postflight if it exists and isn't our wrapper
    if [ -f "$POSTFLIGHT" ]; then
        if ! grep -q "postflight.d wrapper" "$POSTFLIGHT" 2>/dev/null; then
            log_message "Backing up existing postflight to postflight.d/00-original.sh"
            mv "$POSTFLIGHT" "${POSTFLIGHT_D}/00-original.sh"
            chmod 755 "${POSTFLIGHT_D}/00-original.sh"
        fi
    fi
    
    # Install wrapper postflight (implements .d/ directory iteration)
    if [ -f "${MUNKI_RESOURCES}/postflight-wrapper" ]; then
        log_message "Installing postflight wrapper..."
        cp "${MUNKI_RESOURCES}/postflight-wrapper" "$POSTFLIGHT"
        chmod 755 "$POSTFLIGHT"
        chown root:wheel "$POSTFLIGHT"
    fi
    
    # Install ReportMate postflight script
    if [ -f "${MUNKI_RESOURCES}/reportmate.sh" ]; then
        log_message "Installing ReportMate postflight script..."
        cp "${MUNKI_RESOURCES}/reportmate.sh" "${POSTFLIGHT_D}/reportmate.sh"
        chmod 755 "${POSTFLIGHT_D}/reportmate.sh"
        chown root:wheel "${POSTFLIGHT_D}/reportmate.sh"
    fi
    
    log_message "Munki postflight integration installed"
else
    log_message "Munki not detected, skipping postflight integration"
fi

log_message "ReportMate postinstall complete."
exit 0
POSTINSTALL_SCRIPT
        chmod +x "$SCRIPTS_DIR/postinstall"
        
        # Create preinstall
        cat > "$SCRIPTS_DIR/preinstall" << 'PREINSTALL_SCRIPT'
#!/bin/zsh
# ReportMate Preinstall
LD_ROOT="/Library/LaunchDaemons"

log_message() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
log_message "Starting ReportMate preinstall..."

# Legacy daemon
[ -e "${LD_ROOT}/com.github.reportmate.plist" ] && {
    /bin/launchctl bootout system "${LD_ROOT}/com.github.reportmate.plist" 2>/dev/null
    rm -f "${LD_ROOT}/com.github.reportmate.plist"
}

# Current daemons
for daemon in com.github.reportmate.boot com.github.reportmate.hourly com.github.reportmate.fourhourly com.github.reportmate.daily; do
    daemon_path="${LD_ROOT}/${daemon}.plist"
    [ -e "${daemon_path}" ] && {
        /bin/launchctl bootout system "${daemon_path}" 2>/dev/null
        rm -f "${daemon_path}"
    }
done

pkill -f "managedreportsrunner" 2>/dev/null || true
log_message "ReportMate preinstall complete."
exit 0
PREINSTALL_SCRIPT
        chmod +x "$SCRIPTS_DIR/preinstall"
    fi
    
    # Create component plist to prevent bundle relocation
    COMPONENT_PLIST="${OUTPUT_DIR}/component.plist"
    cat > "$COMPONENT_PLIST" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key>
        <true/>
        <key>BundleIsRelocatable</key>
        <false/>
        <key>BundleIsVersionChecked</key>
        <true/>
        <key>BundleOverwriteAction</key>
        <string>upgrade</string>
        <key>RootRelativeBundlePath</key>
        <string>usr/local/reportmate/ReportMate.app</string>
    </dict>
</array>
</plist>
EOF
    
    # Build PKG
    PKG_NAME="ReportMate-${VERSION}.pkg"
    
    pkgbuild --root "${PACKAGE_ROOT}" \
             --identifier "${PKG_IDENTIFIER}" \
             --version "${VERSION}" \
             --install-location "/" \
             --scripts "${SCRIPTS_DIR}" \
             --component-plist "${COMPONENT_PLIST}" \
             "${DIST_DIR}/${PKG_NAME}"
    
    log_success "PKG created: ${DIST_DIR}/${PKG_NAME}"
    
    # Sign the PKG if distribution
    if [ "$DISTRIBUTION" = true ] && [ "$SIGN" = true ]; then
        log_step "Signing PKG for distribution..."
        
        # Validate installer signing identity is provided
        if [ -z "$SIGNING_IDENTITY_INSTALLER" ]; then
            log_error "SIGNING_IDENTITY_INSTALLER not set. Please configure in .env or export it."
            exit 1
        fi
        
        SIGNED_PKG="${DIST_DIR}/ReportMate-${VERSION}-signed.pkg"
        
        PRODUCTSIGN_ARGS=(
            --sign "$SIGNING_IDENTITY_INSTALLER"
        )
        
        if [ "$SIGNING_TIMESTAMP" = "true" ]; then
            PRODUCTSIGN_ARGS+=(--timestamp)
        fi
        
        if [ -n "$SIGNING_KEYCHAIN" ]; then
            PRODUCTSIGN_ARGS+=(--keychain "$SIGNING_KEYCHAIN")
        fi
        
        productsign "${PRODUCTSIGN_ARGS[@]}" \
            "${DIST_DIR}/${PKG_NAME}" \
            "${SIGNED_PKG}"
        
        mv "${SIGNED_PKG}" "${DIST_DIR}/${PKG_NAME}"
        log_success "PKG signed with: ${SIGNING_IDENTITY_INSTALLER}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# NOTARIZATION
# ═══════════════════════════════════════════════════════════════════════════

if [ "$NOTARIZE" = true ] && [ "$SKIP_PKG" = false ]; then
    log_step "Submitting for notarization..."
    
    # Validate notarization credentials are configured
    if [ -z "$NOTARIZATION_APPLE_ID" ] || [ -z "$NOTARIZATION_PASSWORD" ] || [ -z "$TEAM_ID" ]; then
        log_error "Notarization credentials not set. Please configure in .env:"
        log_info "  NOTARIZATION_APPLE_ID=\"your@email.com\""
        log_info "  NOTARIZATION_PASSWORD=\"xxxx-xxxx-xxxx-xxxx\""
        log_info "  TEAM_ID=\"XXXXXXXXXX\""
        log_info ""
        log_info "Generate app-specific password at: https://appleid.apple.com/account/manage"
        exit 1
    fi
    
    PKG_PATH="${DIST_DIR}/ReportMate-${VERSION}.pkg"
    
    NOTARYTOOL_ARGS=(
        --apple-id "$NOTARIZATION_APPLE_ID"
        --password "$NOTARIZATION_PASSWORD"
        --team-id "$TEAM_ID"
        --wait
    )
    
    NOTARY_OUTPUT=$(xcrun notarytool submit "$PKG_PATH" "${NOTARYTOOL_ARGS[@]}" 2>&1)
    
    if echo "$NOTARY_OUTPUT" | grep -q "status: Accepted"; then
        log_success "Notarization accepted!"
        
        log_step "Stapling ticket..."
        xcrun stapler staple "$PKG_PATH"
        
        # Verify
        xcrun stapler validate "$PKG_PATH"
        log_success "Stapling complete"
    else
        log_error "Notarization failed"
        echo "$NOTARY_OUTPUT"
        SUBMISSION_ID=$(echo "$NOTARY_OUTPUT" | grep "id:" | head -1 | awk '{print $2}')
        if [ -n "$SUBMISSION_ID" ]; then
            log_info "Getting detailed log..."
            xcrun notarytool log "$SUBMISSION_ID" --apple-id "$NOTARIZATION_APPLE_ID" --password "$NOTARIZATION_PASSWORD" --team-id "$TEAM_ID"
        fi
        exit 1
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# ZIP PACKAGE
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SKIP_ZIP" = false ]; then
    log_step "Creating ZIP package..."
    
    ZIP_NAME="ReportMate-${VERSION}.zip"
    
    cd "${DIST_DIR}"
    zip -r "${ZIP_NAME}" "${PRODUCT_NAME}"
    cd "${SCRIPT_DIR}"
    
    log_success "ZIP created: ${DIST_DIR}/${ZIP_NAME}"
fi

# ═══════════════════════════════════════════════════════════════════════════
# DMG IMAGE
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SKIP_DMG" = false ] && command -v hdiutil &> /dev/null; then
    log_step "Creating DMG disk image..."
    
    DMG_NAME="ReportMate-${VERSION}.dmg"
    DMG_DIR="${OUTPUT_DIR}/dmg"
    
    rm -rf "$DMG_DIR"
    mkdir -p "$DMG_DIR/ReportMate"
    
    cp "${DIST_DIR}/${PRODUCT_NAME}" "$DMG_DIR/ReportMate/"
    
    # Create install script
    cat > "$DMG_DIR/Install.sh" << 'EOF'
#!/bin/bash
echo "Installing ReportMate..."
sudo mkdir -p /usr/local/reportmate
sudo cp -R "ReportMate/"* /usr/local/reportmate/
sudo chmod +x /usr/local/reportmate/managedreportsrunner
echo "ReportMate installed successfully!"
echo "Configure with: sudo /usr/local/reportmate/managedreportsrunner install --api-url YOUR_API_URL"
EOF
    chmod +x "$DMG_DIR/Install.sh"
    
    hdiutil create -volname "ReportMate ${VERSION}" \
                   -srcfolder "$DMG_DIR" \
                   -ov -format UDZO \
                   "${DIST_DIR}/${DMG_NAME}"
    
    log_success "DMG created: ${DIST_DIR}/${DMG_NAME}"
fi

# ═══════════════════════════════════════════════════════════════════════════
# GIT TAG
# ═══════════════════════════════════════════════════════════════════════════

if [ "$CREATE_TAG" = true ]; then
    log_step "Creating git tag..."
    
    TAG_NAME="v${VERSION}"
    
    if git tag -l | grep -q "^${TAG_NAME}$"; then
        log_warn "Tag ${TAG_NAME} already exists, skipping"
    else
        git tag -a "${TAG_NAME}" -m "Release ${VERSION}"
        git push origin "${TAG_NAME}"
        log_success "Tag created and pushed: ${TAG_NAME}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# GITHUB RELEASE
# ═══════════════════════════════════════════════════════════════════════════

if [ "$CREATE_RELEASE" = true ]; then
    log_step "Creating GitHub release..."
    
    if ! command -v gh &> /dev/null; then
        log_error "GitHub CLI (gh) is not installed"
        exit 1
    fi
    
    RELEASE_NOTES="## ReportMate macOS Client v${VERSION}

### Changes
- Built on $(date -u)
- Swift version: ${SWIFT_VERSION}

### Installation
Download \`ReportMate-${VERSION}.pkg\` and run the installer.

### Checksums
\`\`\`
$(cd "${DIST_DIR}" && shasum -a 256 ReportMate-${VERSION}.*)
\`\`\`
"
    
    gh release create "v${VERSION}" \
        --title "ReportMate macOS ${VERSION}" \
        --notes "$RELEASE_NOTES" \
        "${DIST_DIR}/ReportMate-${VERSION}".*
    
    log_success "GitHub release created"
fi

# ═══════════════════════════════════════════════════════════════════════════
# INSTALL
# ═══════════════════════════════════════════════════════════════════════════

if [ "$INSTALL" = true ]; then
    log_step "Installing package..."
    
    PKG_PATH="${DIST_DIR}/ReportMate-${VERSION}.pkg"
    
    if [ -f "$PKG_PATH" ]; then
        sudo installer -pkg "$PKG_PATH" -target /
        log_success "Package installed"
    else
        log_warn "PKG not found, copying binary directly..."
        sudo mkdir -p /usr/local/reportmate
        sudo cp "${DIST_DIR}/${PRODUCT_NAME}" /usr/local/reportmate/
        sudo chmod +x /usr/local/reportmate/${PRODUCT_NAME}
        log_success "Binary installed to /usr/local/reportmate/"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CLEANUP OLD VERSIONS
# ═══════════════════════════════════════════════════════════════════════════

log_step "Cleaning up old versions..."

# Remove old versioned artifacts (keep only current version)
find "${DIST_DIR}" -name "ReportMate-*.pkg" ! -name "ReportMate-${VERSION}.pkg" -delete
find "${DIST_DIR}" -name "ReportMate-*.zip" ! -name "ReportMate-${VERSION}.zip" -delete
find "${DIST_DIR}" -name "ReportMate-*.dmg" ! -name "ReportMate-${VERSION}.dmg" -delete

# Remove old binaries (keep only the current product name and standard file types)
find "${DIST_DIR}" -type f -perm +111 ! -name "${PRODUCT_NAME}" ! -name "*.pkg" ! -name "*.zip" ! -name "*.dmg" ! -name "*.txt" -delete

log_success "Old versions cleaned up"

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
log_header "Build Complete!"
echo ""
log_info "Artifacts created in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
echo ""
log_info "Test the binary with: ${DIST_DIR}/${PRODUCT_NAME} --help"
