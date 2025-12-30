#!/bin/zsh
# =============================================================================
# ReportMatePrefs Package Builder
# =============================================================================
# Uses munkipkg to build a preferences-only PKG installer
# Injects .env values into postinstall script via envsubst at build time
#
# Usage:
#   ./build.sh                     # Build unsigned
#   ./build.sh --sign              # Build with signing
#   ./build.sh --sign --notarize   # Build, sign, and notarize
#
# Requirements:
#   - munkipkg installed (https://github.com/munki/munki-pkg)
#   - envsubst (part of gettext: brew install gettext)
#   - .env file with REPORTMATE_API_URL and REPORTMATE_PASSPHRASE
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo "${BLUE}[INFO]${NC} $1"; }
log_success() { echo "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Parse Arguments
# =============================================================================

SIGN_PKG=false
NOTARIZE_PKG=false
ENV_FILE=".env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign|-s)
            SIGN_PKG=true
            shift
            ;;
        --notarize|-n)
            NOTARIZE_PKG=true
            SIGN_PKG=true  # Notarization requires signing
            shift
            ;;
        --env|-e)
            ENV_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --sign, -s        Sign the package with Developer ID Installer"
            echo "  --notarize, -n    Notarize the package (implies --sign)"
            echo "  --env, -e FILE    Use specified .env file (default: .env)"
            echo "  --help, -h        Show this help message"
            echo ""
            echo "Required environment variables in .env:"
            echo "  REPORTMATE_API_URL        API endpoint URL"
            echo "  REPORTMATE_PASSPHRASE     Client authentication passphrase"
            echo ""
            echo "Optional environment variables:"
            echo "  REPORTMATE_COLLECTION_INTERVAL  Collection interval in seconds (default: 3600)"
            echo "  REPORTMATE_LOG_LEVEL            Log level: debug, info, warning, error (default: info)"
            echo "  SIGNING_IDENTITY_INSTALLER      Developer ID Installer identity for signing"
            echo "  NOTARIZATION_KEYCHAIN_PROFILE   Keychain profile for notarization"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# Check Prerequisites
# =============================================================================

log_info "Checking prerequisites..."

# Check for munkipkg
if ! command -v munkipkg &> /dev/null; then
    log_error "munkipkg not found. Install it from: https://github.com/munki/munki-pkg"
    log_info "  brew install munkipkg  OR  pip install munkipkg"
    exit 1
fi
log_info "  munkipkg: $(which munkipkg)"

# Check for envsubst
if ! command -v envsubst &> /dev/null; then
    log_error "envsubst not found. Install gettext:"
    log_info "  brew install gettext"
    exit 1
fi
log_info "  envsubst: $(which envsubst)"

# =============================================================================
# Load Environment Variables
# =============================================================================

log_info "Loading environment from: $ENV_FILE"

if [[ ! -f "$ENV_FILE" ]]; then
    log_error "Environment file not found: $ENV_FILE"
    log_info "Create .env with:"
    log_info "  REPORTMATE_API_URL=https://your-api-url"
    log_info "  REPORTMATE_PASSPHRASE=your-passphrase"
    exit 1
fi

# Source the .env file
set -a
source "$ENV_FILE"
set +a

# Validate required variables
MISSING_VARS=()

if [[ -z "$REPORTMATE_API_URL" ]]; then
    MISSING_VARS+=("REPORTMATE_API_URL")
fi

if [[ -z "$REPORTMATE_PASSPHRASE" ]]; then
    MISSING_VARS+=("REPORTMATE_PASSPHRASE")
fi

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    log_error "Missing required environment variables:"
    for var in "${MISSING_VARS[@]}"; do
        log_error "  - $var"
    done
    exit 1
fi

# Set defaults for optional variables
export REPORTMATE_COLLECTION_INTERVAL="${REPORTMATE_COLLECTION_INTERVAL:-3600}"
export REPORTMATE_LOG_LEVEL="${REPORTMATE_LOG_LEVEL:-info}"

log_success "Environment loaded:"
log_info "  API URL: $REPORTMATE_API_URL"
log_info "  Passphrase: [REDACTED - ${#REPORTMATE_PASSPHRASE} chars]"
log_info "  Collection Interval: $REPORTMATE_COLLECTION_INTERVAL"
log_info "  Log Level: $REPORTMATE_LOG_LEVEL"

# =============================================================================
# Generate postinstall from Template
# =============================================================================

log_info "Generating postinstall script from template..."

TEMPLATE_FILE="scripts/postinstall.template"
OUTPUT_FILE="scripts/postinstall"

if [[ ! -f "$TEMPLATE_FILE" ]]; then
    log_error "Template file not found: $TEMPLATE_FILE"
    exit 1
fi

# Use envsubst to substitute only our specific variables
# This prevents substitution of shell variables like $EUID, $1, etc.
envsubst '${REPORTMATE_API_URL} ${REPORTMATE_PASSPHRASE} ${REPORTMATE_COLLECTION_INTERVAL} ${REPORTMATE_LOG_LEVEL}' \
    < "$TEMPLATE_FILE" \
    > "$OUTPUT_FILE"

chmod +x "$OUTPUT_FILE"

log_success "Generated: $OUTPUT_FILE"

# Verify the substitution worked
if grep -q '${REPORTMATE_API_URL}' "$OUTPUT_FILE"; then
    log_error "envsubst failed - template variables not substituted"
    exit 1
fi

# =============================================================================
# Update build-info.yaml with Version
# =============================================================================

log_info "Updating package version..."

VERSION=$(date +"%Y.%m.%d.%H%M")
export VERSION

# Create build-info.yaml if it doesn't exist or update version
cat > build-info.yaml << EOF
# munkipkg build configuration for ReportMatePrefs
# Auto-generated - do not edit manually
# Generated: $(date -Iseconds)

name: ReportMatePrefs-${VERSION}.pkg
identifier: ca.ecuad.reportmate.prefs
version: "${VERSION}"
install_location: /
ownership: preserve

# Distribution style creates a flat package
distribution_style: true

# No payload - scripts only
suppress_bundle_relocation: true
EOF

# Add signing info if requested
if [[ "$SIGN_PKG" == "true" ]]; then
    SIGNING_IDENTITY="${SIGNING_IDENTITY_INSTALLER:-Developer ID Installer}"
    
    cat >> build-info.yaml << EOF

signing_info:
    identity: "${SIGNING_IDENTITY}"
    timestamp: true
EOF
    log_info "Signing enabled with identity: $SIGNING_IDENTITY"
fi

# Add notarization info if requested
if [[ "$NOTARIZE_PKG" == "true" ]]; then
    NOTARIZATION_PROFILE="${NOTARIZATION_KEYCHAIN_PROFILE:-ReportMate}"
    
    cat >> build-info.yaml << EOF

notarization_info:
    keychain_profile: "${NOTARIZATION_PROFILE}"
EOF
    log_info "Notarization enabled with profile: $NOTARIZATION_PROFILE"
fi

log_success "Package version: $VERSION"

# =============================================================================
# Build Package with munkipkg
# =============================================================================

log_info "Building package with munkipkg..."

# Create build output directory
mkdir -p build

# Run munkipkg
munkipkg .

# Find the built package
PKG_NAME="ReportMatePrefs-${VERSION}.pkg"
BUILT_PKG="build/${PKG_NAME}"

if [[ -f "$BUILT_PKG" ]]; then
    log_success "Package built: $BUILT_PKG"
    log_info "Package size: $(du -h "$BUILT_PKG" | cut -f1)"
else
    log_error "Package build failed - output not found"
    exit 1
fi

# =============================================================================
# Verify Package
# =============================================================================

log_info "Verifying package..."

# Check package info
pkgutil --check-signature "$BUILT_PKG" 2>/dev/null || true

# List package contents
log_info "Package scripts:"
pkgutil --payload-files "$BUILT_PKG" 2>/dev/null | head -20 || true

# =============================================================================
# Cleanup
# =============================================================================

log_info "Cleaning up generated files..."

# Remove generated postinstall (keep template)
rm -f scripts/postinstall

log_success "Build complete!"
echo ""
echo "Package: $BUILT_PKG"
echo ""
echo "To install:"
echo "  sudo installer -pkg \"$BUILT_PKG\" -target /"
echo ""
echo "To verify installation:"
echo "  defaults read /Library/Preferences/com.github.reportmate"
echo ""
