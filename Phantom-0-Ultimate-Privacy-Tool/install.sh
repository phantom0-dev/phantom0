#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo install -m 0755 "$ROOT_DIR/phantomctl" /usr/local/bin/phantomctl
echo "[+] Installed phantomctl to /usr/local/bin"

# systemd units (disabled by default)
if command -v systemctl >/dev/null 2>&1; then
  sudo install -m 0644 "$ROOT_DIR/systemd/phantom0-startup.service" /etc/systemd/system/
  sudo install -m 0644 "$ROOT_DIR/systemd/phantom0-shutdown.service" /etc/systemd/system/
  echo "[+] Installed systemd unit files (disabled). Enable manually if desired."
fi
