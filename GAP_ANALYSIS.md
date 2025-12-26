# Gap Analysis: Swift Client vs Reference JSON Schema

## Overview
This document outlines the discrepancies between the Swift client's data models (`clients/macintosh/Sources/Models/Modules/*.swift`) and the reference JSON schema (`device_MJ0KP6ER.json`).

> **Related Documents:**
> - `docs/MAC_COLLECTION_STRATEGY.md` - Collection priority and approach
> - `docs/MAC_COLLECTION_CHECKLIST.md` - Full Windows vs Mac feature parity tracking

## Collection Strategy

**Priority Order:**
1. **osquery** (Primary) - Cross-platform, SQL-like queries
2. **MunkiReport modules** (Secondary) - github.com/munkireport repos
3. **Native macOS commands** (Fallback) - system_profiler, sysctl, etc.

## Findings by Module

### 1. Hardware Module
**Status**: Significant Mismatch
- **Swift (`HardwareModels.swift`)**:
  - Focuses on internal hardware (`cpu`, `memory`, `storage`).
  - Missing: `usbDevices`, `npu`.
- **JSON**:
  - Includes `usbDevices` (peripherals) and `npu`.
- **Action**:
  - Update `HardwareInfo` to include `usbDevices` and `npu`.
  - Move USB logic from `PeripheralsModuleProcessor` (if it exists) to `HardwareModuleProcessor` or aggregate it.

### 2. System Module
**Status**: Structural Mismatch
- **Swift (`SystemModels.swift`)**:
  - Uses nested structs: `uptimeInfo`, `osVersion`, `environmentVariables`, `startupItems`, `launchdServices`.
- **JSON**:
  - Flatter structure or different naming: `uptime` (int), `uptimeString`, `operatingSystem`, `environment`, `scheduledTasks`, `services`.
- **Action**:
  - Refactor `SystemModuleInfo` to match JSON keys.
  - Map `uptimeInfo.uptime` to `uptime`.
  - Map `osVersion` to `operatingSystem`.
  - Map `environmentVariables` to `environment`.
  - Map `startupItems` to `scheduledTasks`.
  - Map `launchdServices` to `services`.

### 3. Network Module
**Status**: Partial Mismatch
- **Swift (`NetworkModels.swift`)**:
  - `NetworkInfo` has `interfaces`, `routes`, `dnsConfiguration`, `wifiInfo`.
  - Missing: `activeConnection`, `vpnConnections`.
- **JSON**:
  - `activeConnection`, `vpnConnections`.
  - `interfaces` seems to be a subset of Swift's `interfaces`.
- **Action**:
  - Add `activeConnection` and `vpnConnections` to `NetworkInfo`.
  - Ensure `interfaces` serialization matches JSON format.

### 4. Inventory Module
**Status**: Good Match (Swift is Superset)
- **Swift (`InventoryModels.swift`)**:
  - Includes all JSON keys (`assetTag`, `catalog`, `department`, `location`, `owner`, `purchaseDate`, `usage`, `warrantyExpiration`) plus more.
- **Action**:
  - Verify serialization excludes internal fields if strict schema is required, or confirm API accepts extra fields.

### 5. Security Module
**Status**: Significant Mismatch
- **Swift (`SecurityModels.swift`)**:
  - Missing: `firmwarePassword`, `ssh`, `tcc`.
  - Has extra: `fileVault`, `secureBoot`, `certificates`, etc.
- **JSON**:
  - `firmwarePassword`, `ssh`, `tcc`.
- **Action**:
  - Add `firmwarePassword`, `ssh`, `tcc` to `SecurityInfo`.
  - Check if `fileVault` and others should be mapped to different keys or if JSON is just a sample.

### 6. Installs Module
**Status**: Complete Mismatch
- **Swift (`InstallsModels.swift`)**:
  - Tracks Homebrew, MacPorts, Applications.
- **JSON**:
  - Tracks MDM/Munki/Cimian state: `bootstrapModeActive`, `cacheStatus`, `cimian`, `munki`, `softwareUpdate`.
- **Action**:
  - Redefine `InstallsData` to match JSON.
  - Implement logic to collect MDM/Munki/Cimian status.

### 7. Management Module
**Status**: Partial Match
- **Swift (`ManagementModels.swift`)**:
  - `mdmStatus`, `profiles`, `complianceStatus`.
- **JSON**:
  - `mdmEnrollment`, `compliancePolicies`, `deviceDetails`.
- **Action**:
  - Rename/Map `mdmStatus` to `mdmEnrollment`.
  - Rename/Map `complianceStatus` to `compliancePolicies`.
  - Add `deviceDetails`.

### 8. Profiles Module
**Status**: Partial Mismatch
- **Swift (`ProfilesModels.swift`)**:
  - `configurationProfiles`.
  - Missing: `groupPolicies`, `intunePolicies`, `jamfPolicies`, `systemExtensions`.
- **JSON**:
  - `groupPolicies`, `intunePolicies`, `jamfPolicies`, `systemExtensions`.
- **Action**:
  - Add missing fields to `ProfilesData`.

### 9. Applications Module
**Status**: Missing in Swift
- **Swift**: No `ApplicationsModels.swift`. `applications` is inside `InstallsData`.
- **JSON**: Top-level `applications` module.
- **Action**:
  - Create `ApplicationsModels.swift` and `ApplicationsModuleProcessor`.
  - Move application collection logic from `InstallsModuleProcessor` to `ApplicationsModuleProcessor`.

## Plan of Attack
1.  **Refactor Models**: Update Swift structs to match JSON schema.
2.  **Update Processors**: Modify `ModuleProcessor` classes to populate the new struct fields.
3.  **Verify**: Run client and compare output with `device_MJ0KP6ER.json`.

## MunkiReport Modules to Reference

When osquery doesn't provide enough data, reference these MunkiReport repos:

| Module | MunkiReport Repo | What It Provides |
|--------|-----------------|------------------|
| Security | `munkireport/security` | SIP, Gatekeeper, Firewall |
| FileVault | `munkireport/filevault_status` | Encryption status |
| MDM | `munkireport/mdm_status` | MDM enrollment details |
| Profiles | `munkireport/profile` | Configuration profiles |
| WiFi | `munkireport/wifi` | WiFi networks/status |
| Bluetooth | `munkireport/bluetooth` | Paired devices |
| Battery | `munkireport/power` | Battery health |
| Certificates | `munkireport/certificate` | System certs |
| Munki | `munkireport/munki` | Managed installs |
