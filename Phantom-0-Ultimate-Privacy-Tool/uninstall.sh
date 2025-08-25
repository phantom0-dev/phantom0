#!/usr/bin/env bash
set -Eeuo pipefail
sudo rm -f /usr/local/bin/phantomctl
if command -v systemctl >/dev/null 2>&1; then
  sudo rm -f /etc/systemd/system/phantom0-startup.service
  sudo rm -f /etc/systemd/system/phantom0-shutdown.service
fi
echo "[+] Uninstalled phantomctl and removed unit files"
