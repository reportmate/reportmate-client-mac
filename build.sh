#!/bin/bash

# ReportMate Unified Build Script
# One-stop build script that replicates the CI pipeline locally.
# Builds PKG installer, signs, and optionally notarizes for distribution.

set -e

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

PROJECT_NAME="ReportMate"
PRODUCT_NAME="managedreportsrunner"
BUNDLE_ID="com.reportmate.managedreportsrunner"
PKG_IDENTIFIER="ca.ecuad.reportmate.client"
TEAM_ID="7TF6CSP83S"  # Emily Carr University team ID
DEVELOPER_ID_APP_HASH="C0277EBA633F1AA2BC2855E45B3B38A1840053BA"
APPLE_DEV_ID="Apple Development: Rod Christiansen (A7LDGJ26G8)"

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

log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warn()    { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error()   { echo -e "${RED}❌ $1${NC}"; }
log_info()    { echo -e "${CYAN}ℹ️  $1${NC}"; }
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
# BUILD
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SKIP_BUILD" = false ]; then
    log_step "Building ${PROJECT_NAME}..."
    
    BUILD_FLAGS="-c ${CONFIGURATION}"
    if [ "$VERBOSE" = true ]; then
        BUILD_FLAGS="${BUILD_FLAGS} --verbose"
    fi
    
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
    
    if [ "$DISTRIBUTION" = true ]; then
        SIGNING_IDENTITY="$DEVELOPER_ID_APP_HASH"
        ENTITLEMENTS_FILE="${SCRIPT_DIR}/ReportMate-Distribution.entitlements"
        log_info "Signing for distribution with Developer ID"
    else
        SIGNING_IDENTITY="$APPLE_DEV_ID"
        ENTITLEMENTS_FILE="${SCRIPT_DIR}/ReportMate.entitlements"
        log_info "Signing for development"
    fi
    
    codesign --force \
        --sign "$SIGNING_IDENTITY" \
        --entitlements "$ENTITLEMENTS_FILE" \
        --timestamp \
        --options runtime \
        ${VERBOSE:+--verbose} \
        "${DIST_DIR}/${PRODUCT_NAME}"
    
    # Verify signature
    codesign --verify --verbose=2 "${DIST_DIR}/${PRODUCT_NAME}"
    log_success "Code signing complete"
fi

# ═══════════════════════════════════════════════════════════════════════════
# CREATE VERSION FILE
# ═══════════════════════════════════════════════════════════════════════════

cat > "${DIST_DIR}/version.txt" << EOF
Version: ${VERSION}
Build Date: $(date -u)
Build Host: $(hostname)
Swift Version: ${SWIFT_VERSION}
Configuration: ${CONFIGURATION}
EOF

# ═══════════════════════════════════════════════════════════════════════════
# PKG INSTALLER
# ═══════════════════════════════════════════════════════════════════════════

if [ "$SKIP_PKG" = false ]; then
    log_step "Creating PKG installer..."
    
    # Create package root structure
    PACKAGE_ROOT="${OUTPUT_DIR}/package_root"
    rm -rf "$PACKAGE_ROOT"
    mkdir -p "$PACKAGE_ROOT/usr/local/reportmate"
    mkdir -p "$PACKAGE_ROOT/Library/Managed Reports"
    mkdir -p "$PACKAGE_ROOT/Library/LaunchDaemons"
    mkdir -p "$PACKAGE_ROOT/etc/paths.d"
    
    # Add reportmate to PATH
    echo "/usr/local/reportmate" > "$PACKAGE_ROOT/etc/paths.d/reportmate"
    
    # Copy executable
    cp "${DIST_DIR}/${PRODUCT_NAME}" "$PACKAGE_ROOT/usr/local/reportmate/"
    cp "${DIST_DIR}/version.txt" "$PACKAGE_ROOT/usr/local/reportmate/"
    
    # Create default configuration plist
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
    </array>
    <key>OsqueryPath</key>
    <string>/usr/local/bin/osqueryi</string>
    <key>ValidateSSL</key>
    <true/>
    <key>Timeout</key>
    <integer>300</integer>
$([ -n "$API_URL" ] && echo "    <key>ApiUrl</key>
    <string>$API_URL</string>")
</dict>
</plist>
EOF

    # Create LaunchDaemon
    cat > "$PACKAGE_ROOT/Library/LaunchDaemons/com.github.reportmate.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.reportmate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/reportmate/managedreportsrunner</string>
        <string>run</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/Library/Managed Reports/logs/reportmate.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Managed Reports/logs/reportmate.error.log</string>
</dict>
</plist>
EOF

    # Copy scripts from build/pkg/scripts
    SCRIPTS_DIR="${OUTPUT_DIR}/scripts"
    rm -rf "$SCRIPTS_DIR"
    mkdir -p "$SCRIPTS_DIR"
    
    if [ -d "${PKG_DIR}/scripts" ]; then
        # Load .env file if it exists for variable substitution
        if [ -f "${PKG_DIR}/.env" ]; then
            log_info "Loading environment from ${PKG_DIR}/.env"
            set -a
            source "${PKG_DIR}/.env"
            set +a
        fi
        
        # Copy and substitute ONLY specific environment variables in scripts
        # This prevents local bash variables like ${DOMAIN} from being substituted
        SUBST_VARS='${REPORTMATE_CUSTOM_DOMAIN_NAME} ${REPORTMATE_CLIENT_PASSPHRASE} ${REPORTMATE_VERSION}'
        
        for script in "${PKG_DIR}/scripts/"*; do
            if [ -f "$script" ] && [ "$(basename "$script")" != "README.md" ]; then
                script_name=$(basename "$script")
                # Substitute only specific environment variables
                envsubst "$SUBST_VARS" < "$script" > "$SCRIPTS_DIR/$script_name"
                chmod +x "$SCRIPTS_DIR/$script_name"
            fi
        done
    fi
    
    # Build PKG
    PKG_NAME="ReportMate-${VERSION}.pkg"
    
    pkgbuild --root "${PACKAGE_ROOT}" \
             --identifier "${PKG_IDENTIFIER}" \
             --version "${VERSION}" \
             --install-location "/" \
             --scripts "${SCRIPTS_DIR}" \
             "${DIST_DIR}/${PKG_NAME}"
    
    log_success "PKG created: ${DIST_DIR}/${PKG_NAME}"
    
    # Sign the PKG if distribution
    if [ "$DISTRIBUTION" = true ]; then
        log_step "Signing PKG for distribution..."
        SIGNED_PKG="${DIST_DIR}/ReportMate-${VERSION}-signed.pkg"
        
        productsign --sign "Developer ID Installer: Emily Carr University (${TEAM_ID})" \
            "${DIST_DIR}/${PKG_NAME}" \
            "${SIGNED_PKG}"
        
        mv "${SIGNED_PKG}" "${DIST_DIR}/${PKG_NAME}"
        log_success "PKG signed"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# NOTARIZATION
# ═══════════════════════════════════════════════════════════════════════════

if [ "$NOTARIZE" = true ] && [ "$SKIP_PKG" = false ]; then
    log_step "Submitting for notarization..."
    
    PKG_PATH="${DIST_DIR}/ReportMate-${VERSION}.pkg"
    
    NOTARY_OUTPUT=$(xcrun notarytool submit "$PKG_PATH" \
        --keychain-profile "notarization_credentials" \
        --wait 2>&1)
    
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
            xcrun notarytool log "$SUBMISSION_ID" --keychain-profile "notarization_credentials"
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
    zip -r "${ZIP_NAME}" "${PRODUCT_NAME}" version.txt
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
    cp "${DIST_DIR}/version.txt" "$DMG_DIR/ReportMate/"
    
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
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
log_header "Build Complete!"
echo ""
log_info "Artifacts created in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
echo ""
log_info "Test the binary with: ${DIST_DIR}/${PRODUCT_NAME} --help"
