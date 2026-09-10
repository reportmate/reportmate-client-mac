#!/bin/bash
set -euo pipefail

# Builds the ReportMate fleet app (the SwiftUI counterpart of the web
# dashboard) into a .app bundle at .build/app/ReportMate.app.
#
#   scripts/build-app.sh            release build
#   scripts/build-app.sh --debug    debug build
#   scripts/build-app.sh --open     build, then launch
#   scripts/build-app.sh --sign     codesign with SIGNING_IDENTITY_APP from .env
#
# The Managed Reports Runner (the per-device client) is built by build.sh;
# this script only produces the operator app.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Command Line Tools on a macOS beta can ship an SDK whose SwiftUI macros
# plugin is missing; the previous SDK still builds the app. Prefer an explicit
# SDKROOT, then the newest SDK that carries the plugin.
if [ -z "${SDKROOT:-}" ] && [ ! -d "$(xcrun --show-sdk-path 2>/dev/null)/../../../../usr/lib/swift/host/plugins" ]; then
    for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk /Library/Developer/CommandLineTools/SDKs/MacOSX15.sdk; do
        if [ -d "$sdk" ]; then export SDKROOT="$sdk"; break; fi
    done
fi

CONFIG="release"
OPEN=0
SIGN=0
VERSION="${VERSION:-$(date +%Y.%m.%d.%H%M)}"
for arg in "$@"; do
    case "$arg" in
        --debug) CONFIG="debug" ;;
        --open) OPEN=1 ;;
        --sign) SIGN=1 ;;
        --version=*) VERSION="${arg#--version=}" ;;
    esac
done

swift build -c "$CONFIG" --product ReportMateMac

BIN=".build/$CONFIG/ReportMateMac"
if [ ! -f "$BIN" ]; then
    BIN="$(swift build -c "$CONFIG" --show-bin-path)/ReportMateMac"
fi
[ -f "$BIN" ] || { echo "ReportMateMac binary not found"; exit 1; }

APP=".build/app/ReportMate.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/ReportMate"
chmod +x "$APP/Contents/MacOS/ReportMate"
sed -e "s|<string>0.1.0</string>|<string>$VERSION</string>|" Sources/ReportMateMac/Info.plist > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
if [ -f "Sources/ReportMateMac/Resources/AppIcon.icns" ]; then
    cp "Sources/ReportMateMac/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
fi

if [ "$SIGN" = "1" ]; then
    if [ -f .env ]; then
        set -a; . ./.env; set +a
    fi
    : "${SIGNING_IDENTITY_APP:?SIGNING_IDENTITY_APP is not set (put it in .env)}"
    codesign --force --deep --options runtime --timestamp --sign "$SIGNING_IDENTITY_APP" "$APP"
    codesign --verify --verbose=2 "$APP"
else
    codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
fi

echo "Built $APP ($CONFIG, $VERSION)"
if [ "$OPEN" = "1" ]; then
    open "$APP"
fi
