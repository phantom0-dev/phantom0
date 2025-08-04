#!/bin/bash
# === Phantom-0 Uninstaller ===

set -euo pipefail

echo "🧼 Phantom-0 Uninstaller"
echo "This will remove all installed Phantom-0 components from your system."
read -rp "Are you sure you want to proceed? (y/n): " confirm
[[ "$confirm" != "y" ]] && echo "Aborted." && exit 0

# Define install paths
INSTALL_DIR="/usr/local/bin/phantom0"
SYSTEMD_SERVICE="/etc/systemd/system/phantom0.service"
MODULES_DIR="/usr/local/bin/phantom0/modules"
LOG_DIR="/home/$(id -nu 1000)/phantom0_logs"

# Remove systemd service
if [ -f "$SYSTEMD_SERVICE" ]; then
    echo "🧯 Disabling and removing systemd service..."
    sudo systemctl disable phantom0.service || true
    sudo systemctl stop phantom0.service || true
    sudo rm -f "$SYSTEMD_SERVICE"
    sudo systemctl daemon-reload
    echo "✅ Service removed"
else
    echo "ℹ️ No systemd service found"
fi

# Remove installed scripts
if [ -d "$INSTALL_DIR" ]; then
    echo "🧹 Removing installed scripts at $INSTALL_DIR"
    sudo rm -rf "$INSTALL_DIR"
else
    echo "ℹ️ No installed script directory found"
fi

# Remove modules (if separately placed)
if [ -d "$MODULES_DIR" ]; then
    echo "🧹 Removing modules at $MODULES_DIR"
    sudo rm -rf "$MODULES_DIR"
fi

# Optional: Remove log directory
if [ -d "$LOG_DIR" ]; then
    read -rp "Delete Phantom-0 logs at $LOG_DIR? (y/n): " del_logs
    [[ "$del_logs" == "y" ]] && sudo rm -rf "$LOG_DIR" && echo "✅ Logs deleted"
fi

echo "✅ Phantom-0 successfully uninstalled."
exit 0

