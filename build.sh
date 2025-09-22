#!/bin/bash

# ReportMate macOS Build Script
# Builds the Swift package and creates deployment packages

set -e

# Configuration
PROJECT_NAME="ReportMate"
PRODUCT_NAME="runner"
VERSION="${1:-$(date +%Y.%m.%d.%H%M)}"
CONFIGURATION="release"
BUILD_DIR="build"
OUTPUT_DIR="${BUILD_DIR}/output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
CLEAN=false
SIGN=false
API_URL=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --sign)
            SIGN=true
            shift
            ;;
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info "ReportMate macOS Build Script"
log_info "Version: ${VERSION}"
log_info "Configuration: ${CONFIGURATION}"

# Clean if requested
if [ "$CLEAN" = true ]; then
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Create build directories
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v swift &> /dev/null; then
    log_error "Swift is not installed or not in PATH"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    log_error "Xcode command line tools are not installed"
    exit 1
fi

# Check Swift version (should be 6.0+)
SWIFT_VERSION=$(swift --version | head -n 1 | sed 's/.*Swift version \([0-9]\+\.[0-9]\+\).*/\1/')
log_info "Swift version: ${SWIFT_VERSION}"

# Build the project
log_info "Building ${PROJECT_NAME}..."

if [ "$VERBOSE" = true ]; then
    swift build --configuration release --verbose
else
    swift build --configuration release
fi

if [ $? -ne 0 ]; then
    log_error "Build failed"
    exit 1
fi

# Copy binary to build directory
BINARY_PATH=".build/release/${PRODUCT_NAME}"
if [ -f "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" "${BUILD_DIR}/"
    log_info "Binary copied to ${BUILD_DIR}/${PRODUCT_NAME}"
else
    log_error "Binary not found at ${BINARY_PATH}"
    exit 1
fi

# Code signing if requested
if [ "$SIGN" = true ]; then
    log_info "Code signing binary..."
    
    # Try to find a valid code signing identity
    IDENTITY=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -n 1 | cut -d '"' -f 2)
    
    if [ -n "$IDENTITY" ]; then
        codesign --sign "$IDENTITY" --force --options runtime "${BUILD_DIR}/${PRODUCT_NAME}"
        log_info "Binary signed with identity: $IDENTITY"
    else
        log_warn "No valid code signing identity found. Binary will be unsigned."
    fi
fi

# Create version file
echo "Version: ${VERSION}" > "${BUILD_DIR}/version.txt"
echo "Build Date: $(date -u)" >> "${BUILD_DIR}/version.txt"
echo "Build Host: $(hostname)" >> "${BUILD_DIR}/version.txt"
echo "Swift Version: ${SWIFT_VERSION}" >> "${BUILD_DIR}/version.txt"

# Create directory structure for packaging
PACKAGE_ROOT="${BUILD_DIR}/package_root"
mkdir -p "$PACKAGE_ROOT/usr/local/reportmate"
mkdir -p "$PACKAGE_ROOT/Library/Application Support/ReportMate"
mkdir -p "$PACKAGE_ROOT/Library/LaunchDaemons"

# Copy files to package structure
cp "${BUILD_DIR}/${PRODUCT_NAME}" "$PACKAGE_ROOT/usr/local/reportmate/"
cp "${BUILD_DIR}/version.txt" "$PACKAGE_ROOT/usr/local/reportmate/"

# Create default configuration
cat > "$PACKAGE_ROOT/Library/Application Support/ReportMate/reportmate.plist" << EOF
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
EOF

if [ -n "$API_URL" ]; then
    echo "    <key>ApiUrl</key>" >> "$PACKAGE_ROOT/Library/Application Support/ReportMate/reportmate.plist"
    echo "    <string>$API_URL</string>" >> "$PACKAGE_ROOT/Library/Application Support/ReportMate/reportmate.plist"
fi

cat >> "$PACKAGE_ROOT/Library/Application Support/ReportMate/reportmate.plist" << EOF
</dict>
</plist>
EOF

# Create LaunchDaemon plist
cat > "$PACKAGE_ROOT/Library/LaunchDaemons/com.reportmate.client.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.reportmate.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/reportmate/runner</string>
        <string>run</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/reportmate.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/reportmate.error.log</string>
</dict>
</plist>
EOF

# Create ZIP package
log_info "Creating ZIP package..."
ZIP_NAME="ReportMate-${VERSION}.zip"
cd "$BUILD_DIR"
zip -r "$OUTPUT_DIR/$ZIP_NAME" package_root/
cd ..

log_info "ZIP package created: ${OUTPUT_DIR}/${ZIP_NAME}"

# Create PKG installer (requires macOS)
if command -v pkgbuild &> /dev/null; then
    log_info "Creating PKG installer..."
    
    PKG_NAME="ReportMate-${VERSION}.pkg"
    
    pkgbuild --root "${PACKAGE_ROOT}" \
             --identifier "com.reportmate.client" \
             --version "${VERSION}" \
             --install-location "/" \
             "${OUTPUT_DIR}/${PKG_NAME}"
    
    log_info "PKG installer created: ${OUTPUT_DIR}/${PKG_NAME}"
else
    log_warn "pkgbuild not available, skipping PKG creation"
fi

# Create DMG (requires macOS and additional tools)
if command -v hdiutil &> /dev/null; then
    log_info "Creating DMG disk image..."
    
    DMG_NAME="ReportMate-${VERSION}.dmg"
    DMG_DIR="${BUILD_DIR}/dmg"
    
    mkdir -p "$DMG_DIR"
    cp -R "${PACKAGE_ROOT}/usr/local/reportmate" "$DMG_DIR/ReportMate"
    
    # Create install script
    cat > "$DMG_DIR/Install.sh" << EOF
#!/bin/bash
echo "Installing ReportMate..."
sudo cp -R "ReportMate" "/usr/local/reportmate"
sudo chmod +x "/usr/local/reportmate/runner"
echo "ReportMate installed successfully!"
echo "Configure with: sudo /usr/local/reportmate/runner install --api-url YOUR_API_URL"
EOF
    
    chmod +x "$DMG_DIR/Install.sh"
    
    hdiutil create -volname "ReportMate $VERSION" \
                   -srcfolder "$DMG_DIR" \
                   -ov -format UDZO \
                   "${OUTPUT_DIR}/${DMG_NAME}"
    
    log_info "DMG disk image created: ${OUTPUT_DIR}/${DMG_NAME}"
else
    log_warn "hdiutil not available, skipping DMG creation"
fi

# Summary
log_info "Build completed successfully!"
log_info "Artifacts created in ${OUTPUT_DIR}:"
ls -la "$OUTPUT_DIR"

log_info "Test the binary with: ${BUILD_DIR}/${PRODUCT_NAME} --help"