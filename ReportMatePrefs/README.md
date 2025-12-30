# ReportMatePrefs Package

A munkipkg-based installer package that configures ReportMate client credentials on macOS.

## Purpose

This package mirrors the Windows `ReportMatePrefs` cimipkg pattern - it's a separate preferences-only package that:
- Writes API credentials to `/Library/Preferences/com.github.reportmate.plist`
- Sets secure file permissions (chmod 600)
- Does NOT install the ReportMate client itself

## Build Process

1. **Create `.env` file:**
   ```bash
   cp .env.example .env
   # Edit .env with your production values
   ```

2. **Build unsigned (for testing):**
   ```bash
   ./build.sh
   ```

3. **Build signed (for production):**
   ```bash
   ./build.sh --sign
   ```

4. **Build, sign, and notarize (for distribution):**
   ```bash
   ./build.sh --sign --notarize
   ```

## Environment Variables

### Required
- `REPORTMATE_API_URL` - API endpoint URL
- `REPORTMATE_PASSPHRASE` - Client authentication passphrase (X-Client-Passphrase header)

### Optional
- `REPORTMATE_COLLECTION_INTERVAL` - Collection interval in seconds (default: 3600)
- `REPORTMATE_LOG_LEVEL` - Log level: debug, info, warning, error (default: info)

### For Signing/Notarization
- `SIGNING_IDENTITY_INSTALLER` - Developer ID Installer identity
- `NOTARIZATION_KEYCHAIN_PROFILE` - Keychain profile for notarization

## How It Works

1. `build.sh` loads `.env` and exports variables
2. `envsubst` substitutes variables into `scripts/postinstall.template`
3. `munkipkg` builds the PKG with the generated postinstall script
4. The PKG is self-contained with credentials baked in

## Installation

After building:
```bash
sudo installer -pkg "build/ReportMatePrefs-*.pkg" -target /
```

Verify:
```bash
defaults read /Library/Preferences/com.github.reportmate
```

## Security Notes

- `.env` file contains secrets - never commit to repository
- Plist is written with `chmod 600` (root read only)
- Passphrase is baked into PKG at build time - treat PKG as sensitive
- Template file contains only placeholders, safe to commit

## CI/CD Integration

For GitHub Actions:
```yaml
- name: Build ReportMatePrefs
  env:
    REPORTMATE_API_URL: ${{ secrets.REPORTMATE_API_URL }}
    REPORTMATE_PASSPHRASE: ${{ secrets.REPORTMATE_PASSPHRASE }}
  run: |
    cd clients/macintosh/ReportMatePrefs
    echo "REPORTMATE_API_URL=$REPORTMATE_API_URL" > .env
    echo "REPORTMATE_PASSPHRASE=$REPORTMATE_PASSPHRASE" >> .env
    ./build.sh --sign
```
