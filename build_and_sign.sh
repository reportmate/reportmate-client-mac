#!/bin/bash

# ReportMate macOS Build and Sign Script
# This script builds, signs, and optionally notarizes the ReportMate runner

set -e

# Configuration
PRODUCT_NAME="runner"
BUNDLE_ID="com.reportmate.runner"
TEAM_ID="7TF6CSP83S"  # Emily Carr University team ID
DEVELOPER_ID_APP_HASH="C0277EBA633F1AA2BC2855E45B3B38A1840053BA"  # Use hash for unambiguous selection
APPLE_DEV_ID="Apple Development: Rod Christiansen (A7LDGJ26G8)"

# Build configuration
BUILD_CONFIG="release"
SIGN_FOR_DISTRIBUTION=false
NOTARIZE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_CONFIG="release"
            shift
            ;;
        --debug)
            BUILD_CONFIG="debug"
            shift
            ;;
        --distribution)
            SIGN_FOR_DISTRIBUTION=true
            shift
            ;;
        --notarize)
            NOTARIZE=true
            SIGN_FOR_DISTRIBUTION=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--debug|--release] [--distribution] [--notarize]"
            echo "  --debug       Build in debug configuration (default)"
            echo "  --release     Build in release configuration"
            echo "  --distribution Sign with Developer ID for distribution"
            echo "  --notarize    Sign and notarize for distribution"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Building ReportMate Runner..."
echo "Configuration: $BUILD_CONFIG"
echo "Sign for distribution: $SIGN_FOR_DISTRIBUTION"
echo "Notarize: $NOTARIZE"
echo

# Clean previous builds
echo "Cleaning previous builds..."
swift package clean

# Build the project
echo "Building Swift package..."
if [ "$BUILD_CONFIG" = "release" ]; then
    swift build -c release
    BUILD_PATH=".build/arm64-apple-macosx/release"
else
    swift build
    BUILD_PATH=".build/arm64-apple-macosx/debug"
fi

EXECUTABLE_PATH="$BUILD_PATH/$PRODUCT_NAME"

if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "Build failed - executable not found at: $EXECUTABLE_PATH"
    exit 1
fi

echo "Build completed successfully"
echo "Executable location: $EXECUTABLE_PATH"

# Code signing
if [ "$SIGN_FOR_DISTRIBUTION" = true ]; then
    SIGNING_IDENTITY="$DEVELOPER_ID_APP_HASH"
    ENTITLEMENTS_FILE="ReportMate-Distribution.entitlements"
    echo "Signing for distribution with Developer ID..."
else
    SIGNING_IDENTITY="$APPLE_DEV_ID"
    ENTITLEMENTS_FILE="ReportMate.entitlements"
    echo "Signing for development..."
fi

echo "Signing identity: $SIGNING_IDENTITY"
echo "Entitlements file: $ENTITLEMENTS_FILE"

# Sign the executable with appropriate entitlements
codesign --force \
    --sign "$SIGNING_IDENTITY" \
    --entitlements "$ENTITLEMENTS_FILE" \
    --timestamp \
    --options runtime \
    --verbose \
    "$EXECUTABLE_PATH"

# Verify signature
echo "Verifying code signature..."
codesign --verify --verbose=2 "$EXECUTABLE_PATH"
codesign --display --verbose=2 "$EXECUTABLE_PATH"

echo "Code signing completed"

# Create distribution package if signing for distribution
if [ "$SIGN_FOR_DISTRIBUTION" = true ]; then
    DIST_DIR="dist"
    ZIP_NAME="ReportMate-Runner-$(date +%Y%m%d-%H%M%S).zip"
    
    echo "Creating distribution package..."
    mkdir -p "$DIST_DIR"
    cp "$EXECUTABLE_PATH" "$DIST_DIR/"
    
    # Create zip for notarization
    cd "$DIST_DIR"
    zip -r "../$ZIP_NAME" "$PRODUCT_NAME"
    cd ..
    
    echo "Distribution package created: $ZIP_NAME"
    
    # Notarization
    if [ "$NOTARIZE" = true ]; then
        echo "Submitting for notarization..."
        echo "Using existing notarization_credentials profile"
        
        # Submit for notarization using existing credentials
        echo "Submitting $ZIP_NAME for notarization..."
        NOTARY_OUTPUT=$(xcrun notarytool submit "$ZIP_NAME" --keychain-profile "notarization_credentials" --wait)
        SUBMISSION_ID=$(echo "$NOTARY_OUTPUT" | grep "id:" | head -1 | awk '{print $2}')
        
        if echo "$NOTARY_OUTPUT" | grep -q "status: Accepted"; then
            echo "Notarization successful! Stapling ticket..."
            xcrun stapler staple "$DIST_DIR/$PRODUCT_NAME"
            echo "Stapling completed"
            
            # Verify stapled executable
            echo "Verifying stapled executable..."
            xcrun stapler validate "$DIST_DIR/$PRODUCT_NAME"
        else
            echo "Notarization failed"
            if [ ! -z "$SUBMISSION_ID" ]; then
                echo "Getting detailed log for submission $SUBMISSION_ID..."
                xcrun notarytool log "$SUBMISSION_ID" --keychain-profile "notarization_credentials"
            fi
            exit 1
        fi
    fi
fi

# Test the signed executable
echo "Testing signed executable..."
if "$EXECUTABLE_PATH" --version 2>/dev/null; then
    echo "Executable runs successfully"
else
    echo "Executable test failed (may be normal if --version not implemented)"
fi

echo
echo "Build and sign process completed!"
echo "Signed executable: $EXECUTABLE_PATH"
if [ "$SIGN_FOR_DISTRIBUTION" = true ]; then
    echo "Distribution package: $ZIP_NAME"
fi
echo
echo "Usage examples:"
echo "   # Development testing:"
echo "   $EXECUTABLE_PATH --help"
echo "   # Run with specific module:"
echo "   $EXECUTABLE_PATH --run-module hardware --verbose 2"
echo "   # Collect only (no transmission):"
echo "   $EXECUTABLE_PATH --collect-only --verbose 1"