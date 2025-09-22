#!/bin/bash

# System Profiler Wrapper Scripts for ReportMate macOS Client
# These scripts provide fallback data collection when osquery is unavailable

# Hardware Information Collection
collect_hardware_info() {
    echo "=== Hardware Information ==="
    
    # System overview
    system_profiler SPHardwareDataType 2>/dev/null | \
    grep -E "(Model Name|Model Identifier|Processor|Memory|Serial Number)" | \
    sed 's/^[ \t]*//' || echo "Hardware info unavailable"
    
    # CPU Information  
    echo -e "\n=== CPU Information ==="
    sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "CPU info unavailable"
    echo "CPU Cores: $(sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")"
    echo "Physical CPU Cores: $(sysctl -n hw.physicalcpu 2>/dev/null || echo "Unknown")"
    echo "Logical CPU Cores: $(sysctl -n hw.logicalcpu 2>/dev/null || echo "Unknown")"
    
    # Memory Information
    echo -e "\n=== Memory Information ==="
    echo "Physical Memory: $(($(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 / 1024)) GB"
    
    # Storage Information
    echo -e "\n=== Storage Information ==="
    df -h | head -1
    df -h | grep -E "^/dev/" | head -5 || echo "Storage info unavailable"
}

# System Information Collection
collect_system_info() {
    echo "=== System Information ==="
    
    # Operating System
    echo "OS Name: $(sw_vers -productName 2>/dev/null || echo "macOS")"
    echo "OS Version: $(sw_vers -productVersion 2>/dev/null || echo "Unknown")"
    echo "Build Version: $(sw_vers -buildVersion 2>/dev/null || echo "Unknown")"
    
    # System Details
    echo "Computer Name: $(scutil --get ComputerName 2>/dev/null || echo "Unknown")"
    echo "Host Name: $(scutil --get HostName 2>/dev/null || hostname 2>/dev/null || echo "Unknown")"
    echo "Local Host Name: $(scutil --get LocalHostName 2>/dev/null || echo "Unknown")"
    
    # Kernel Information
    echo -e "\n=== Kernel Information ==="
    echo "Kernel Version: $(uname -r 2>/dev/null || echo "Unknown")"
    echo "Architecture: $(uname -m 2>/dev/null || echo "Unknown")"
    
    # Uptime
    echo -e "\n=== System Uptime ==="
    uptime 2>/dev/null || echo "Uptime unavailable"
    
    # Boot time
    echo "Boot Time: $(sysctl -n kern.boottime 2>/dev/null | awk '{print $4}' | sed 's/,//' || echo "Unknown")"
}

# Network Information Collection
collect_network_info() {
    echo "=== Network Information ==="
    
    # Network Interfaces
    echo "=== Network Interfaces ==="
    ifconfig 2>/dev/null | grep -E "^[a-z]" | awk '{print $1}' | sed 's/:$//' || echo "Interface info unavailable"
    
    # Active Network Interfaces
    echo -e "\n=== Active Network Interfaces ==="
    for interface in $(ifconfig 2>/dev/null | grep -E "^[a-z]" | awk '{print $1}' | sed 's/:$//' | head -5); do
        echo "Interface: $interface"
        ifconfig "$interface" 2>/dev/null | grep -E "(inet |ether |status:)" | sed 's/^[ \t]*/  /' || true
        echo
    done
    
    # Default Route
    echo "=== Default Route ==="
    route get default 2>/dev/null | grep -E "(gateway|interface)" | sed 's/^[ \t]*//' || echo "Route info unavailable"
    
    # DNS Configuration
    echo -e "\n=== DNS Configuration ==="
    scutil --dns 2>/dev/null | grep "nameserver" | head -5 | sed 's/^[ \t]*//' || \
    cat /etc/resolv.conf 2>/dev/null | grep "nameserver" | head -5 || echo "DNS info unavailable"
    
    # Wi-Fi Status (if available)
    echo -e "\n=== Wi-Fi Status ==="
    if command -v /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport >/dev/null 2>&1; then
        /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null || echo "Wi-Fi info unavailable"
    else
        echo "Airport utility not available"
    fi
}

# Security Information Collection
collect_security_info() {
    echo "=== Security Information ==="
    
    # System Integrity Protection
    echo "=== System Integrity Protection ==="
    csrutil status 2>/dev/null || echo "SIP status unavailable"
    
    # Gatekeeper Status
    echo -e "\n=== Gatekeeper Status ==="
    spctl --status 2>/dev/null || echo "Gatekeeper status unavailable"
    
    # Firewall Status
    echo -e "\n=== Firewall Status ==="
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "Firewall status unavailable"
    
    # Security Configuration
    echo -e "\n=== Security Configuration ==="
    echo "FileVault Status:"
    fdesetup status 2>/dev/null || echo "  FileVault status unavailable"
    
    # Code Signing Status for System
    echo -e "\n=== System Code Signing ==="
    codesign -dv /System/Library/CoreServices/Finder.app 2>&1 | head -3 || echo "Code signing info unavailable"
}

# Application Information Collection
collect_application_info() {
    echo "=== Application Information ==="
    
    # Applications in /Applications
    echo "=== Applications ==="
    find /Applications -name "*.app" -maxdepth 1 2>/dev/null | head -20 | while read app; do
        echo "App: $(basename "$app")"
        if [ -f "$app/Contents/Info.plist" ]; then
            version=$(defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            identifier=$(defaults read "$app/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || echo "Unknown")
            echo "  Version: $version"
            echo "  Bundle ID: $identifier"
        fi
        echo
    done
    
    # Running Processes (top 10 by CPU)
    echo "=== Top Processes by CPU ==="
    ps aux 2>/dev/null | head -1
    ps aux 2>/dev/null | sort -rn -k3 | head -10 || echo "Process info unavailable"
    
    # Running Processes (top 10 by Memory)
    echo -e "\n=== Top Processes by Memory ==="
    ps aux 2>/dev/null | head -1
    ps aux 2>/dev/null | sort -rn -k4 | head -10 || echo "Process info unavailable"
}

# Management Information Collection
collect_management_info() {
    echo "=== Management Information ==="
    
    # MDM Status
    echo "=== MDM Status ==="
    profiles status -type enrollment 2>/dev/null || echo "MDM status unavailable"
    
    # Configuration Profiles
    echo -e "\n=== Configuration Profiles ==="
    profiles list 2>/dev/null | head -20 || echo "Profile info unavailable"
    
    # Remote Management
    echo -e "\n=== Remote Management ==="
    echo "ARD Status:"
    /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -query -agent 2>/dev/null || echo "  ARD status unavailable"
    
    # Screen Sharing
    echo -e "\n=== Screen Sharing ==="
    launchctl list | grep -i screen 2>/dev/null || echo "Screen sharing info unavailable"
    
    # SSH Status
    echo -e "\n=== SSH Status ==="
    systemsetup -getremotelogin 2>/dev/null || echo "SSH status unavailable"
}

# Inventory Information Collection
collect_inventory_info() {
    echo "=== Inventory Information ==="
    
    # Disk Usage
    echo "=== Disk Usage ==="
    df -h 2>/dev/null || echo "Disk usage unavailable"
    
    # Mount Points
    echo -e "\n=== Mount Points ==="
    mount 2>/dev/null | head -10 || echo "Mount info unavailable"
    
    # USB Devices
    echo -e "\n=== USB Devices ==="
    system_profiler SPUSBDataType 2>/dev/null | grep -E "(Product ID|Vendor ID|Serial Number|Location ID)" | head -20 || echo "USB info unavailable"
    
    # Network Devices
    echo -e "\n=== Network Devices ==="
    system_profiler SPNetworkDataType 2>/dev/null | grep -E "(Type|Hardware|BSD Device Name)" | head -15 || echo "Network device info unavailable"
    
    # System Extensions
    echo -e "\n=== System Extensions ==="
    systemextensionsctl list 2>/dev/null | head -20 || echo "System extensions info unavailable"
    
    # Kernel Extensions (deprecated but still present)
    echo -e "\n=== Kernel Extensions ==="
    kextstat 2>/dev/null | head -20 || echo "Kernel extensions info unavailable"
}

# Main execution based on module type
case "${1:-all}" in
    "hardware")
        collect_hardware_info
        ;;
    "system")
        collect_system_info
        ;;
    "network")
        collect_network_info
        ;;
    "security")
        collect_security_info
        ;;
    "applications")
        collect_application_info
        ;;
    "management")
        collect_management_info
        ;;
    "inventory")
        collect_inventory_info
        ;;
    "all")
        collect_hardware_info
        echo -e "\n\n"
        collect_system_info
        echo -e "\n\n"
        collect_network_info
        echo -e "\n\n"
        collect_security_info
        echo -e "\n\n"
        collect_application_info
        echo -e "\n\n"
        collect_management_info
        echo -e "\n\n"
        collect_inventory_info
        ;;
    *)
        echo "Usage: $0 [hardware|system|network|security|applications|management|inventory|all]"
        echo "Collects system information using native macOS tools as fallback for osquery"
        exit 1
        ;;
esac