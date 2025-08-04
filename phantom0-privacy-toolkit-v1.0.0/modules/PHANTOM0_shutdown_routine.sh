#!/bin/bash
umask 007
# === PHANTOM-0 - SHUTDOWN ===

REAL_USER=$(id -nu 1000)
REAL_HOME=$(eval echo "~$REAL_USER")
LOG_DIR="$REAL_HOME/phantom0_logs"
mkdir -p "$LOG_DIR"
sudo chown -R root:"$REAL_USER" "$LOG_DIR"
sudo chmod 750 "$LOG_DIR"

TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
LOGFILE="$LOG_DIR/cloak_shutdown_$TIMESTAMP.log"
exec > >(tee -a "$LOGFILE" | /usr/bin/systemd-cat -t phantom0-shutdown) 2>&1
echo "Script started at $TIMESTAMP"

# === 1. Command Log Cleaned ===
unset HISTFILE && echo "  ✅ HISTFILE unlinked"
rm -f /root/.bash_history /root/.zsh_history && echo "  ✅ Root session cleaned"
rm -f /home/*/.bash_history /home/*/.zsh_history && echo "  ✅ User session logs cleaned"

# === 2. System Log Maintenance ===
journalctl --rotate && echo "  ✅ Journal rotation successful."
journalctl --vacuum-time=1s && echo "  ✅ Log vacuum (1s) completed."
find /var/log/journal /run/log/journal -type f -name '*.journal' -not -newermt '1 minute ago' -delete && echo "  ✅ Legacy Journals Cleared."

# === 3. Secure Free Space Wipe (~5GB + TRIM) ===

# Run fstrim to signal SSD block discard (safe with LUKS)
if command -v fstrim >/dev/null 2>&1; then
  fstrim -v /
else
  echo "    ⚠ fstrim not found — skipping SSD block trim."
fi

# Detect real user and home directory
REAL_USER=$(id -nu 1000)
REAL_HOME=$(eval echo "~$REAL_USER")

# Fill 5GB of free space with zeroes to wipe recent traces
timeout 30s dd if=/dev/zero of="$REAL_HOME/.zero.fill" bs=1M count=5120 status=progress
  echo "    ✅ 5GB free space filled with zeroes."
else
  echo "    ⚠ Partial zero-fill (expected if disk filled early)."
fi

# Remove filler file
if rm -f "$REAL_HOME/.zero.fill"; then
  echo "    ✅ Temporary filler file removed."
else
  echo "    ⚠ Failed to remove filler file."
fi

echo "    ✅ Free space trace wipe complete."

# === 4. Clear Volatile Memory Buffers ===
sync && echo "  ✅ Filesystem sync completed"
swapoff -a && echo "  ✅ Swap disabled"
MEM_KILLER=$(mktemp /dev/shm/memwipe.XXXXXX)
dd if=/dev/zero of="$MEM_KILLER" bs=1M status=none || echo "  ⚠ Memory limit reached (expected)"
rm -f "$MEM_KILLER" && echo "  ✅ Temporary memory cleared"
echo "  ✅ Safe memory flush complete"

# === 5. Low-Noise DNS Cleanup ===
sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1 && echo "  ✅ ICMP echo ignore enabled"
command -v resolvectl && resolvectl flush-caches && echo "  ✅ DNS cache flushed (resolvectl)"
command -v systemd-resolve && systemd-resolve --flush-caches && echo "  ✅ DNS cache flushed (systemd-resolve)"
rm -f /run/systemd/resolve/* && echo "  ✅ DNS residue cleared"

# === 6. Session Cleanup ===
TRASH_PATHS=(
  "$REAL_HOME/.local/share/Trash/files"
  "$REAL_HOME/Desktop/Trash"
  "$REAL_HOME/.Trash"
  "$REAL_HOME/.cache/Trash"
)

for TRASH_DIR in "${TRASH_PATHS[@]}"; do
  if [ -d "$TRASH_DIR" ]; then
    find "$TRASH_DIR" -type f -exec shred -u -n 3 -z {} \; 2>/dev/null || true
    rm -rf "$TRASH_DIR"/* && echo "  ✅ Emptied $TRASH_DIR"
  fi
done

rm -f "$REAL_HOME/.local/share/Trash/info/"*
rm -rf "$REAL_HOME/.cache/"* \
       "$REAL_HOME/.thumbnails/"* \
       "$REAL_HOME/.recently-used.xbel" \
       "$REAL_HOME/.local/share/gvfs-metadata/"* \
       "$REAL_HOME/.local/share/recently-used.xbel" \
       "$REAL_HOME/.config/gtk-3.0/bookmarks" \
       "$REAL_HOME/.bash_history" \
       "$REAL_HOME/.zsh_history"

# === 7. Shutdown Enhancements ===
history -c
systemctl mask avahi-daemon.service cups.service bluetooth.service
echo "cd ~/Downloads" > "$REAL_HOME/.bash_history"
echo "firefox duckduckgo.com" >> "$REAL_HOME/.bash_history"
echo "kernel panic - not syncing: Fatal exception in interrupt" > /tmp/kernel_panic_fake.log
cp /tmp/kernel_panic_fake.log /var/log/syslog

# === 8. Backup Firefox Profile ===
PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"
BACKUP_DIR="$REAL_HOME/.firefox_profile_backups"
mkdir -p "$BACKUP_DIR"
cp "$PERSISTENT_PROFILE/places.sqlite" "$BACKUP_DIR/" || true
cp "$PERSISTENT_PROFILE/logins.json" "$BACKUP_DIR/" || true
cp "$PERSISTENT_PROFILE/key4.db" "$BACKUP_DIR/" || true
cp "$PERSISTENT_PROFILE/cert9.db" "$BACKUP_DIR/" || true
pkill -f firefox || true

exit 0
echo "✅ Phantom-0 shutdown complete."
