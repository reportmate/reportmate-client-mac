# macadmins Extension Maintenance Guide

## Current Version
- **Version**: v1.2.7 (November 3, 2024)
- **Location**: `Sources/Resources/extensions/macadmins_extension.ext`
- **Size**: ~15MB (universal binary: x86_64 + arm64)
- **SHA256**: `612277353644b4a9a3502d70ce8fcd705e77da63ac29687e2b2d30cfee490f05`

## Update Process

### 1. Check for New Releases
Monitor the official repository for updates:
- **GitHub**: https://github.com/macadmins/osquery-extension/releases
- **Release Notes**: Review changelog for new tables, bug fixes, and breaking changes
- **Frequency**: Check monthly or when new macOS versions are released

### 2. Download Latest Release
```bash
cd /tmp
VERSION="1.2.7"  # Update to latest version
wget "https://github.com/macadmins/osquery-extension/releases/download/v${VERSION}/macadmins_extension.ext"

# Verify it's a valid Mach-O universal binary
file macadmins_extension.ext
# Expected: macadmins_extension.ext: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64:Mach-O 64-bit executable arm64]

# Check code signature
codesign -dvv macadmins_extension.ext
# Expected: signed by Mac Admins Open Source (T4SK8ZXCXG)

# Generate SHA256 for documentation
shasum -a 256 macadmins_extension.ext
```

### 3. Test Before Committing
```bash
# Copy to dev location
cp macadmins_extension.ext ~/DevOps/ReportMate/clients/macintosh/Sources/Resources/extensions/

# Build and test
cd ~/DevOps/ReportMate/clients/macintosh
swift build --configuration release

# Test all extension-dependent modules
sudo ./.build/release/managedreportsrunner --collect-only --run-module security --verbose
sudo ./.build/release/managedreportsrunner --collect-only --run-module profiles --verbose
sudo ./.build/release/managedreportsrunner --collect-only --run-module system --verbose
sudo ./.build/release/managedreportsrunner --collect-only --run-module management --verbose

# Verify no errors and data is collected correctly
```

### 4. Update Documentation
Update this file with:
- New version number
- Release date
- New SHA256 checksum
- Any new tables or breaking changes

### 5. Commit to Repository
```bash
git add Sources/Resources/extensions/macadmins_extension.ext
git add EXTENSION_MAINTENANCE.md
git commit -m "Update macadmins extension to v${VERSION}

- Updated from v1.2.7 to v${VERSION}
- SHA256: [new checksum]
- Changes: [summary from release notes]
"
git push origin main
```

## Version History

| Version | Date | SHA256 | Notes |
|---------|------|--------|-------|
| v1.2.7 | 2024-11-03 | 612277353644b4a9a3502d70ce8fcd705e77da63ac29687e2b2d30cfee490f05 | Initial integration with ReportMate |

## Currently Used Tables

**Security Module:**
- ✅ `filevault_users` - FileVault user information
- ✅ `macos_profiles` - Configuration profiles with enhanced fields
- ✅ `authdb` - Authorization database rights for security auditing
- ✅ `sofa_unpatched_cves` - CVE vulnerability tracking from Sofa feed
- ✅ `sofa_security_release_info` - Security release data for current OS version

**System Module:**
- ✅ `pending_apple_updates` - Pending Apple software updates

**Network Module:**
- ✅ `alt_system_info` - Alternative system info (avoids macOS 15 network permission prompt)
- ✅ `network_quality` - Network speed/quality testing (macOS 12+)
- ✅ `wifi_network` - Current WiFi SSID and details

**Management Module:**
- ✅ `mdm` - MDM enrollment info (requires osqueryd daemon)

## Potential Future Enhancements

### Security Hardening
- **`authdb`** - Track authorization rights changes
- **`sofa_unpatched_cves`** - Automatic CVE detection for installed OS
- **`sofa_security_release_info`** - Security release compliance tracking
- **`crowdstrike_falcon`** - EDR sensor status (if deployed)

### System Monitoring
- **`unified_log`** - Parse system logs for security events
- **`wifi_network`** - Track network connectivity (SSID changes)
- **`network_quality`** - Monitor network performance
- **`alt_system_info`** - Avoid macOS 15 permission prompts

### Configuration Management
- **`munki_info` / `munki_installs`** - Track software deployments
- **`puppet_*`** - Puppet configuration state (if used)
- **`google_chrome_profiles`** - Enterprise browser configuration

## Troubleshooting

### Extension Won't Load
```bash
# Check extension exists
ls -lh Sources/Resources/extensions/macadmins_extension.ext

# Verify in bundle after build
ls -lh .build/release/ReportMate_ReportMate.bundle/Resources/extensions/

# Test manually with osquery
osquery --extension Sources/Resources/extensions/macadmins_extension.ext --allow_unsafe "SELECT * FROM filevault_users;"
```

### Tables Not Available
Some tables require specific conditions:
- **`mdm`** - Requires osqueryd daemon (not osquery command-line)
- **`munki_*`** - Requires Munki installed
- **`puppet_*`** - Requires Puppet installed
- **`crowdstrike_falcon`** - Requires CrowdStrike Falcon installed
- **`network_quality`** - macOS 12+ only
- **`unified_log`** - Requires proper predicates to avoid performance issues

### Socket Conflicts
If you see "Address already in use" errors:
- The OSQueryService automatically creates unique sockets per process
- Socket path: `/tmp/osquery-reportmate-{PID}.em`
- Old sockets are cleaned up automatically by the OS

## Support & Issues

- **Extension Issues**: https://github.com/macadmins/osquery-extension/issues
- **ReportMate Integration**: Check OSQueryService.swift logs with `--verbose` flag
- **Community**: MacAdmins Slack #osquery channel

## Security Considerations

- Extension binary is code-signed by Mac Admins Open Source (Team ID: T4SK8ZXCXG)
- Always verify signature after downloading: `codesign -dvv macadmins_extension.ext`
- Extension runs with same privileges as ReportMate client (typically root via LaunchDaemon)
- Review release notes for security fixes before updating
