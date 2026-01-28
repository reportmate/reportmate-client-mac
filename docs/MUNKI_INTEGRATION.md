# Munki Integration: MunkiReport + ReportMate Coexistence

## Overview

ReportMate macOS client seamlessly integrates with Munki's postflight mechanism to collect managed installs data after every `managedsoftwareupdate` run. This document explains how MunkiReport and ReportMate run alongside each other without conflicts.

## The Problem

Munki's postflight mechanism only supports a **single script** at `/usr/local/munki/postflight`. Organizations running MunkiReport already have this slot occupied, creating a conflict when deploying additional tools like ReportMate.

## The Solution

ReportMate implements a **postflight.d directory pattern** (similar to `preflight.d`, `login.d`, etc.) that allows multiple scripts to run sequentially after Munki operations.

### Architecture

```
/usr/local/munki/
├── postflight                         # Wrapper script (replaces original)
└── postflight.d/                      # Script directory
    ├── 00-original.sh                 # Original MunkiReport postflight (backed up)
    └── reportmate.sh                  # ReportMate installs module
```
]
## How It Works

### 1. Installation Process

When `ReportMate.pkg` is installed on a Mac with Munki:

```bash
# Postinstall detects Munki
if [ -d "/usr/local/munki" ]; then
    # 1. Create postflight.d directory
    mkdir -p /usr/local/munki/postflight.d
    
    # 2. Backup existing postflight (e.g., MunkiReport)
    if [ -f /usr/local/munki/postflight ]; then
        mv /usr/local/munki/postflight \
           /usr/local/munki/postflight.d/00-original.sh
    fi
    
    # 3. Install wrapper as new postflight
    cp Resources/munki/postflight-wrapper /usr/local/munki/postflight
    
    # 4. Install ReportMate script
    cp Resources/munki/reportmate.sh \
       /usr/local/munki/postflight.d/reportmate.sh
fi
```

**Result:** Original MunkiReport functionality is preserved and runs first, followed by ReportMate.

### 2. Execution Flow

Every time Munki runs (`managedsoftwareupdate`):

```mermaid
graph TD
    A[managedsoftwareupdate completes] --> B[/usr/local/munki/postflight]
    B --> C[Postflight Wrapper]
    C --> D[Enumerate postflight.d/]
    D --> E[Run 00-original.sh]
    E --> F[MunkiReport submits data]
    F --> G[Run reportmate.sh]
    G --> H[ReportMate --run-module installs]
    H --> I[ReportMate submits managed installs data]
    I --> J[postflight complete]
```

**Execution order:** Scripts run in alphanumeric order by filename.

### 3. Script Details

#### Postflight Wrapper

**Location:** `/usr/local/munki/postflight`

**Purpose:** Implements postflight.d/ directory iteration

**Key features:**
- Runs executable scripts in alphanumeric order
- Skips hidden files (`.dotfiles`)
- Passes `$RUNTYPE` argument to each script
- Logs execution to `/Library/Managed Reports/logs/munki-postflight.log`
- Non-blocking: failure in one script doesn't prevent others from running

**Source:** Bundled in `ReportMate.app/Contents/Resources/munki/postflight-wrapper`

#### 00-original.sh (MunkiReport)

**Location:** `/usr/local/munki/postflight.d/00-original.sh`

**Purpose:** Original MunkiReport postflight (backed up automatically)

**What it does:**
- Collects Munki managed installs data
- Submits to MunkiReport server
- Runs **before** ReportMate (alphabetically first)

**Note:** Named `00-original.sh` to ensure it runs first in sort order.

#### reportmate.sh (ReportMate)

**Location:** `/usr/local/munki/postflight.d/reportmate.sh`

**Purpose:** ReportMate installs module collection

**What it does:**
```bash
# Run installs module (collects AND transmits)
/usr/local/reportmate/managedreportsrunner --run-module installs
```

**Data collected:**
- Munki managed installs status
- Pending updates
- Installation history
- Cimian inventory (Windows equivalent)
- Homebrew packages
- App Store apps

**Source:** Bundled in `ReportMate.app/Contents/Resources/munki/reportmate.sh`

## Coexistence Benefits

| Feature | MunkiReport | ReportMate | Notes |
|---------|-------------|------------|-------|
| **Execution order** | 1st | 2nd | Guaranteed by filename |
| **Data isolation** | MunkiReport server | ReportMate API | Separate endpoints |
| **No conflicts** | ✅ | ✅ | Both can succeed/fail independently |
| **Logging** | MunkiReport logs | ReportMate logs | Separate log files |
| **Performance** | ~2-5 seconds | ~3-8 seconds | Sequential, not parallel |

**Total overhead:** ~5-13 seconds after each Munki run (acceptable for most environments).

## Verification

### Check Installation

```bash
# Verify postflight structure
ls -la /usr/local/munki/postflight.d/

# Expected output:
# -rwxr-xr-x  1 root  wheel  2109 Jan 22 00:00 00-original.sh
# -rwxr-xr-x  1 root  wheel  2052 Jan 22 00:00 reportmate.sh

# Verify wrapper is in place
head -5 /usr/local/munki/postflight

# Should contain: "# Wrapper script that implements postflight.d/"
```

### Test Execution

```bash
# Run postflight manually (simulates Munki run)
sudo /usr/local/munki/postflight auto

# Check logs
tail -50 /Library/Managed Reports/logs/munki-postflight.log
tail -50 /Library/Managed Reports/logs/reportmate-munki-postflight.log
```

**Expected log output:**
```
[2026-01-22 11:30:00] Munki postflight started (runtype: auto)
[2026-01-22 11:30:00] Found 2 script(s) in postflight.d
[2026-01-22 11:30:00] Running: 00-original.sh
[2026-01-22 11:30:03]   00-original.sh completed successfully
[2026-01-22 11:30:03] Running: reportmate.sh
[2026-01-22 11:30:08]   reportmate.sh completed successfully
[2026-01-22 11:30:08] Munki postflight completed
```

### Verify Data Submission

**MunkiReport:**
- Check MunkiReport dashboard for device updates
- Last check-in should match postflight run time

**ReportMate:**
- Check ReportMate dashboard "Managed Installs" widget
- Should show latest Munki data (pending updates, install count, etc.)

## Troubleshooting

### MunkiReport Not Running

**Symptom:** MunkiReport stops receiving data after ReportMate installation

**Diagnosis:**
```bash
# Check if original script exists
ls -la /usr/local/munki/postflight.d/00-original.sh

# Check if it's executable
stat -f "%Sp" /usr/local/munki/postflight.d/00-original.sh
# Should be: -rwxr-xr-x
```

**Fix:**
```bash
# Make executable
sudo chmod 755 /usr/local/munki/postflight.d/00-original.sh

# Test manually
sudo /usr/local/munki/postflight.d/00-original.sh auto
```

### ReportMate Not Running

**Symptom:** ReportMate doesn't collect installs data after Munki runs

**Diagnosis:**
```bash
# Check if reportmate.sh exists
ls -la /usr/local/munki/postflight.d/reportmate.sh

# Check if ReportMate binary exists
ls -la /usr/local/reportmate/managedreportsrunner
```

**Fix:**
```bash
# Make executable
sudo chmod 755 /usr/local/munki/postflight.d/reportmate.sh

# Test manually
sudo /usr/local/munki/postflight.d/reportmate.sh auto
```

### Both Scripts Not Running

**Symptom:** Neither MunkiReport nor ReportMate collect data after Munki runs

**Diagnosis:**
```bash
# Check if wrapper exists
ls -la /usr/local/munki/postflight

# Check wrapper contents
head -5 /usr/local/munki/postflight
```

**Fix:**
```bash
# Reinstall ReportMate.pkg or manually copy wrapper
sudo cp /usr/local/reportmate/ReportMate.app/Contents/Resources/munki/postflight-wrapper \
        /usr/local/munki/postflight
sudo chmod 755 /usr/local/munki/postflight
sudo chown root:wheel /usr/local/munki/postflight
```

### High Latency / Performance Issues

**Symptom:** Munki runs take significantly longer after ReportMate installation

**Diagnosis:**
```bash
# Check execution time in logs
grep "completed" /Library/Managed Reports/logs/munki-postflight.log
```

**Tuning:**
- Move ReportMate to a separate scheduled collection (remove from postflight.d)
- Use LaunchDaemon-based collection instead (every 4 hours)
- Disable specific modules in ReportMate that overlap with MunkiReport

## Adding Additional Scripts

The postflight.d pattern supports unlimited scripts:

```bash
# Add a new script
sudo nano /usr/local/munki/postflight.d/50-custom-script.sh

# Make executable
sudo chmod 755 /usr/local/munki/postflight.d/50-custom-script.sh

# Test
sudo /usr/local/munki/postflight auto
```

**Naming convention:**
- Use numeric prefixes for ordering: `10-first.sh`, `50-second.sh`, `99-last.sh`
- Lower numbers run first
- MunkiReport: `00-original.sh` (runs first)
- ReportMate: `reportmate.sh` (no prefix, runs after numbered scripts)

## Uninstallation

To remove ReportMate's Munki integration:

```bash
# Remove ReportMate script
sudo rm /usr/local/munki/postflight.d/reportmate.sh

# Optional: Restore original MunkiReport postflight
sudo mv /usr/local/munki/postflight.d/00-original.sh \
        /usr/local/munki/postflight

# Or keep the wrapper for future tools
# (leaves wrapper + 00-original.sh in place)
```

## Security Considerations

1. **Root execution:** All postflight scripts run as `root` (via Munki's LaunchDaemon)
2. **Script validation:** Only executable files in `postflight.d/` are run
3. **Hidden files skipped:** `.dotfiles` and non-executable files are ignored
4. **Logging:** All execution is logged for audit trails

## Related Documentation

- [ReportMate Modules Documentation](MODULES.md)
- [ReportMate LaunchDaemons Schedule](LAUNCHDAEMONS.md)
- [MunkiReport Official Docs](https://github.com/munkireport/munkireport-php/wiki)
- [Munki Wiki - Postflight Scripts](https://github.com/munki/munki/wiki/Preflight-And-Postflight-Scripts)

## Summary

The ReportMate postflight integration:
- ✅ Preserves existing MunkiReport functionality
- ✅ Runs automatically after every Munki operation
- ✅ Supports unlimited additional scripts
- ✅ Provides detailed logging
- ✅ Handles errors gracefully (non-blocking)
- ✅ Zero configuration required after installation

Both systems collect complementary data and submit to their respective servers without conflicts.
