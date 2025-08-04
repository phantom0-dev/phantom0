#!/bin/bash
umask 007
# === PHANTOM-0 - STARTUP ===
sudo chown -R root:$REAL_USER $REAL_HOME/phantom0_logs
sudo chmod 750 $REAL_HOME/phantom0_logs

################################################################################

# === Root Privilege & Safe Execution Check ===
echo "Root Privilege & Safe Execution Check"

# Color helpers
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
RESET=$(tput sgr0)

# Check for root
if [[ "$EUID" -ne 0 ]]; then
echo -e "${RED} > ERROR: Script must be run as root (use: sudo ./phantom0_startup.sh or systemd)${RESET}"
exit 1
else
echo -e "${GREEN} > Root privilege confirmed${RESET}"
fi

# Optional: Check for systemd-safe flag if no DISPLAY present
if [[ "$1" != "--systemd-safe" && -z "$DISPLAY" ]]; then
echo -e "${RED} > ERROR: Missing --systemd-safe flag for systemd execution${RESET}"
exit 1
else
echo -e "${GREEN} > Execution flag valid or graphical session detected${RESET}"
fi

echo -e "${GREEN} > All privilege checks passed. Continuing script...${RESET}"

################################################################################

REAL_USER="$REAL_USER"
REAL_HOME="/home/$REAL_USER"
PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"
PROFILE_PATH="$PERSISTENT_PROFILE"

# === Log startup time directly to /var/log with root privileges ===
echo "Log startup time directly to /var/log with root privileges"
if sudo bash -c "echo \"[cloak] phantom0_startup.sh ran at $(date)\" >> /var/log/phantom0_startup.log"; then
echo " [✔] Startup time logged to /var/log/phantom0_startup.log"
else
echo " [✘] Failed to log startup time" >&2
fi

# === Setup Logging to User Log Directory ===
echo " Setup Logging to User Log Directory"
LOG_DIR="$REAL_HOME/phantom0_logs"

# Fallback if home isn't writable
if [ ! -w "$LOG_DIR" ]; then
LOG_DIR="/var/log/cloak_fallback"
echo " [⚠] $REAL_HOME not writable, using fallback: $LOG_DIR"
fi

mkdir -p "$LOG_DIR"
chmod 770 "$LOG_DIR"
chown root:root "$LOG_DIR"

# === Initialize Logfile With Timestamp ===
echo " Initialize Logfile With Timestamp"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
LOGFILE="$LOG_DIR/cloak_run_$TIMESTAMP.log"

# Redirect stdout/stderr to log file
exec > >(tee -a "$LOGFILE") 2> >(tee -a "$LOGFILE.err" >&2)
echo " [✔] Cloak script started at $(date)"

################################################################################

# === 1. Setup real user variables ===
echo "1. [+] Detecting real user with UID 1000..."

REAL_USER=$(id -nu 1000 2>/dev/null)
if [ -z "$REAL_USER" ]; then
echo " [!] Failed to find user with UID 1000 — exiting."
exit 1
else
echo " [✓] Real user detected: $REAL_USER"
fi

REAL_HOME=$(eval echo "~$REAL_USER")
if [ -d "$REAL_HOME" ]; then
echo " [✓] Home directory found: $REAL_HOME"
else
echo " [!] Could not verify home directory at $REAL_HOME"
exit 1
fi

################################################################################

# === 2. FORCE PERSISTENT PROFILE EARLY ===
echo "2. FORCE PERSISTENT PROFILE EARLY"
REAL_HOME="$REAL_HOME"
PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"
BACKUP_DIR="$REAL_HOME/.firefox_profile_backups"

# === 2.1 Ensure persistent profile folder exists or restore from backup ===
if [ ! -d "$PERSISTENT_PROFILE" ]; then
echo " ⚠ Persistent Firefox profile missing — recreating and restoring from backup..."
mkdir -p "$PERSISTENT_PROFILE"

# Restore critical data if backup exists
cp "$BACKUP_DIR"/places.sqlite "$PERSISTENT_PROFILE/" 2>/dev/null && echo " ✔ Bookmarks restored"
cp "$BACKUP_DIR"/logins.json "$PERSISTENT_PROFILE/" 2>/dev/null && echo " ✔ Logins restored"
cp "$BACKUP_DIR"/key4.db "$PERSISTENT_PROFILE/" 2>/dev/null && echo " ✔ Decryption key restored"
cp "$BACKUP_DIR"/cert9.db "$PERSISTENT_PROFILE/" 2>/dev/null && echo " ✔ Certificates restored"
fi

# === 2.2 Detect Firefox random profile and replace with link to persistent profile to persistent ===
RANDOM_PROFILE=$(find "$REAL_HOME/.mozilla/firefox" -maxdepth 1 -type d -name "*.default-release" -o -name "*.default" | head -n 1)

if [ -n "$RANDOM_PROFILE" ] && [ ! -L "$RANDOM_PROFILE" ]; then
echo " > Removing randomized Firefox profile: $RANDOM_PROFILE"
if rm -rf "$RANDOM_PROFILE" && ln -s "$PERSISTENT_PROFILE" "$RANDOM_PROFILE"; then
echo " ✅ Firefox now uses persistent profile (link to persistent profile successful)"
else
echo " ❌ Failed to link persistent Firefox profile"
fi
else
echo " > Firefox profile already linked or missing"
fi

sleep 2
echo " > Firefox Cleanup (preserve bookmarks & logins)..."

REAL_HOME=$(eval echo "~$REAL_USER")

################################################################################

# === 3.0 Ensure all Firefox processes are fully closed ===
echo "3.0 Firefox Cleanup (preserve bookmarks & logins)..."
echo " Killing any leftover Firefox processes..."
if pkill -u "$REAL_USER" -f "firefox" 2>/dev/null; then
echo " ✅ Firefox processes killed."
else
echo " ℹ No Firefox processes were running."
fi
sleep 3

# === 3.1 Wipe history from all Firefox profiles ===
echo " 3.1 Wipe Firefox history in ALL profiles..."
FIREFOX_DIR="$REAL_HOME/.mozilla/firefox"
for PROFILE in "$FIREFOX_DIR"/*.default*; do
if [ -f "$PROFILE/places.sqlite" ]; then
echo " > Wiping places.sqlite in: $PROFILE"
sqlite3 "$PROFILE/places.sqlite" "DELETE FROM moz_places;" 2>/dev/null
sqlite3 "$PROFILE/places.sqlite" "DELETE FROM moz_historyvisits;" 2>/dev/null
sqlite3 "$PROFILE/places.sqlite" "VACUUM;" 2>/dev/null
echo " ✅ History wiped for: $PROFILE"
else
echo " ⚠ No places.sqlite found in: $PROFILE"
fi
done

# === 3.1.1 Refresh Temporary Browser Data ===
echo " 3.1.1 Refreshing Temporary Browser Data..."
find "$REAL_HOME/.mozilla/firefox" -type f -name "cookies.sqlite" -exec rm -f {} \;
find "$REAL_HOME/.mozilla/firefox" -type f \( -name "webappsstore.sqlite" -o -name "storage.sqlite" -o -name "permissions.sqlite" \) -exec rm -f {} \;
echo " ✅ Refreshed Temorary Browser Data"

# === 3.1.2 Optional: Remove unused profiles (if not symlinked or persistent) ===
echo " 3.1.2 Removing unused Firefox profiles (non-symlinked)..."
for PROFILE in "$FIREFOX_DIR"/*.default*; do
if [ ! -L "$PROFILE" ] && [[ "$PROFILE" != *".firefox_persistent_profile" ]]; then
echo " 🧹 Removing unused profile: $PROFILE"
rm -rf "$PROFILE"
fi
done

# === 3.2 Pre-launch Firefox headless to initialize profile (only if not already running) ===
echo " 3.2 Pre-launch Firefox headless to initialize profile (only if not already running)"
if ! pgrep -u "$REAL_USER" -f "firefox" > /dev/null; then
echo " Firefox not running — launching headless to initialize profile..."
if sudo -u "$REAL_USER" DISPLAY=:0 XAUTHORITY="$REAL_HOME/.Xauthority" firefox --headless &>/dev/null & then
sleep 5
echo " ✅ Headless Firefox launched successfully."
else
echo " ❌ Failed to launch headless Firefox."
fi
else
echo " ⚠ Firefox already running — skipping headless launch."
fi

# === 3.3 Wait for headless Firefox to exit, with timeout ===
echo " 3.3 Wait for headless Firefox to exit, with timeout"
MAX_TRIES=5
TRY_COUNT=0
while pgrep -u "$REAL_USER" -f "firefox --headless" > /dev/null; do
if [ "$TRY_COUNT" -ge "$MAX_TRIES" ]; then
echo " ⚠ Firefox still locking DB after $MAX_TRIES attempts — force killing..."
pkill -u "$REAL_USER" -f "firefox --headless"
sleep 2
echo " ❌ Firefox forcibly terminated after timeout."
break
fi
echo " Waiting for Firefox to release database lock..."
sleep 2
((TRY_COUNT++))
done

if [ "$TRY_COUNT" -lt "$MAX_TRIES" ]; then
echo " ✅ Firefox headless session successfully ended after $TRY_COUNT attempt(s)."
fi

# === 3.4 Detect Firefox profile & link to persistent profile if profile exists ===
echo " 3.4 Detect Firefox profile & link to persistent profile if profile exists"

PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"
RANDOM_PROFILE=$(find "$REAL_HOME/.mozilla/firefox" -maxdepth 1 -type d \( -name "*.default-release" -o -name "*.default" \) | head -n 1)

if [ -n "$RANDOM_PROFILE" ] && [ ! -L "$RANDOM_PROFILE" ]; then
echo " > Removing Firefox's randomized profile: $RANDOM_PROFILE"
if rm -rf "$RANDOM_PROFILE"; then
echo " ✔️ Deleted randomized profile"
else
echo " ❌ Failed to delete randomized profile"
fi

echo " > Creating link to persistent profile to persistent profile"
if ln -s "$PERSISTENT_PROFILE" "$RANDOM_PROFILE"; then
echo " ✔️ link to persistent profile created: $RANDOM_PROFILE → $PERSISTENT_PROFILE"
echo " ✅ Firefox now uses persistent profile"
else
echo " ❌ Failed to create link to persistent profile"
fi
else
echo " > Profile already linked to persistent or not found"
fi

PROFILE_PATH="$PERSISTENT_PROFILE"
chown -R "$REAL_USER:$REAL_USER" "$PROFILE_PATH"
chmod -R u+rw "$PROFILE_PATH"

# === 3.5 Cleanup Diagnostic Logs and Temorary Files ===
echo " 3.5 Cleaning Diagnostic Logs and Temorary Files..."

{
rm -rfv "$PROFILE_PATH"/sessionstore*
"$PROFILE_PATH"/cookies.sqlite \
"$PROFILE_PATH"/formhistory.sqlite \
"$PROFILE_PATH"/telemetry.json \
"$PROFILE_PATH"/healthreport.sqlite \
"$PROFILE_PATH"/containers.json \
"$PROFILE_PATH"/addonStartup.json.lz4 \
"$PROFILE_PATH"/downloads.sqlite \
"$PROFILE_PATH"/extension-preferences.json \
&& rm -rfv "$PROFILE_PATH"/datareporting/ \
"$PROFILE_PATH"/crashes/ \
"$PROFILE_PATH"/startupCache/ \
"$PROFILE_PATH"/storage/
} # Remove sessionstore-logs directory if it exists
rm -rf "$PROFILE_PATH/sessionstore-logs" && echo " ✅ Firefox cleanup complete — personal data preserved." \
|| echo " ⚠️ Firefox cleanup encountered an issue — check path or permissions."

# === 3.5.1 Extra: Silent Refresh of Web Session Data ===
echo " 3.5.1 Silent Refresh of Web Session Data..."
find "$PROFILE_PATH" -type f \( -name "cookies.sqlite" -o -name "webappsstore.sqlite" -o -name "storage.sqlite" -o -name "permissions.sqlite" \) -exec rm -f {} \; 2>/dev/null

echo " ✅ Silent Refresh of Web Session Data Completed (if present)"

# === 3.6 Release Stale Temporary Resources ===
echo " 3.6 Releasing Stale Temporary Resources..."

cleanup_success=true

rm -f "$PROFILE_PATH"/places.sqlite-shm || cleanup_success=false
rm -f "$PROFILE_PATH"/places.sqlite-wal || cleanup_success=false
rm -f "$PROFILE_PATH"/parent.lock || cleanup_success=false
rm -f "$PROFILE_PATH"/.startup-incomplete || cleanup_success=false
rm -f "$PROFILE_PATH"/sessionCheckpoints.json || cleanup_success=false
rm -f "$PROFILE_PATH"/sessionstore.jsonlz4 || cleanup_success=false
rm -f "$PROFILE_PATH"/recovery.jsonlz4 || cleanup_success=false
rm -f "$PROFILE_PATH"/recovery.baklz4 || cleanup_success=false

if $cleanup_success; then
echo " [✓] Firefox session cleanup complete."
else
echo " [✗] One or more Firefox session files failed to delete (may not exist — safe to ignore)."
fi

# === 3.7 Final permissions + VACUUM cleanup ===
echo " 3.7 Final permissions + VACUUM cleanup"
chown "$REAL_USER:$REAL_USER" "$PROFILE_PATH"/places.sqlite && \
echo " ✅ Ownership set on places.sqlite" || \
echo " ❌ Failed to set ownership on places.sqlite"

chmod 600 "$PROFILE_PATH"/places.sqlite && \
echo " ✅ Permissions set to 600 on places.sqlite" || \
echo " ❌ Failed to set permissions on places.sqlite"

echo " Testing if places.sqlite is writable..."
if echo "VACUUM;" | sudo -u "$REAL_USER" sqlite3 "$PROFILE_PATH/places.sqlite"; then
echo " ✅ Bookmark database write test successful."
else
echo " ❌ Bookmark DB locked or corrupted!"
fi

# === 3.8 Final kill — make sure nothing Firefox remains ===
echo " 3.8 Cleaning up Firefox background processes..."
pkill -u "$REAL_USER" -f "firefox" 2>/dev/null
sleep 2
if pgrep -u "$REAL_USER" -f "firefox" > /dev/null; then
echo " ⚠ Firefox background process still running."
echo " ❌ Cleanup failed — Firefox is still active"
else
echo " ✔ Firefox background process terminated."
echo " ✅ Cleanup successful — no Firefox processes found"
fi


################################################################################

# === 4. Root Privilege & Safe Execution Check ===
echo "4. Root Privilege & Safe Execution Check"

# Color helpers
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
RESET=$(tput sgr0)

# Check for root
if [[ "$EUID" -ne 0 ]]; then
echo -e "${RED} > ERROR: Script must be run as root (use: sudo ./phantom0_startup.sh or systemd)${RESET}"
exit 1
else
echo -e "${GREEN} > Root privilege confirmed${RESET}"
fi

# Optional: Check for systemd-safe flag if no DISPLAY present
if [[ "$1" != "--systemd-safe" && -z "$DISPLAY" ]]; then
echo -e "${RED} > ERROR: Missing --systemd-safe flag for systemd execution${RESET}"
exit 1
else
echo -e "${GREEN} > Execution flag valid or graphical session detected${RESET}"
fi

echo -e "${GREEN} > All privilege checks passed. Continuing script...${RESET}"

################################################################################

# === 5. Session context check (GUI environment detection) ===
echo "5. Session context check (GUI environment detection)"
if [[ -z "$SUDO_USER" && -z "$XDG_RUNTIME_DIR" ]]; then
echo " > Systemd boot detected — no GUI session"
echo " ✅ GUI session detection: headless/systemd confirmed"
else
echo " > Manual or GUI-session cloak mode"
echo " ✅ GUI session detection: interactive or desktop session confirmed"
fi

################################################################################

# === 6. Detect and Set Display Authority (Only if GUI Exists) ===
echo "6. Detect and Set Display Authority (Only if GUI Exists)"
if [ -n "$DISPLAY" ] && [ -f "$XAUTHORITY" ]; then
echo " > GUI detected, DISPLAY=$DISPLAY, using existing XAUTHORITY"
echo " ✅ Display authority confirmed via environment variables"
elif [ -f "$NEO_HOME/.Xauthority" ]; then
export DISPLAY=:0
export XAUTHORITY=$NEO_HOME/.Xauthority
echo " > GUI likely available, XAUTHORITY set manually"
echo " ✅ Display authority set manually to :0 using .Xauthority"
else
echo " > No GUI session detected, skipping GUI-dependent steps"
echo " ⚠ GUI not detected — display authority not set"
fi

################################################################################

# === NETWORK INTERFACE (Update if needed) ===
NET_IFACE="wlo1" # Replace with your actual network interface (use `ip a` to check)

# === 7. Initialize Network Interfaces ===
echo "7. Initialize Network Interfaces..."
echo " > Waiting 5 seconds for network/Mullvad to initialize..."
sleep 5

# Check if the network interface is up
if ip link show "$NET_IFACE" | grep -q "state UP"; then
echo " ✅ Network interface '$NET_IFACE' is up and running."
else
echo " ⚠ Warning: Network interface '$NET_IFACE' is not up. Continuing anyway..."
fi

################################################################################

# === 8. Verify Display Environment Access ===
echo "8. Verify Display Environment Access..."
if [ -n "$(command -v xhost)" ]; then
# Attempt to detect GUI user (first one with X session)
GUI_USER=$(who | grep -m1 '(:' | awk '{print $1}')
GUI_HOME=$(eval echo "~$GUI_USER")
XAUTHORITY_PATH="$GUI_HOME/.Xauthority"

# Auto-detect DISPLAY if not set (fallback for systemd/root environments)
if [ -z "$DISPLAY" ]; then
DISPLAY=$(who | grep -m1 '(:' | awk -F'[()]' '{print $2}')
export DISPLAY=":$DISPLAY"
fi

export XAUTHORITY="$XAUTHORITY_PATH"

if [ -n "$GUI_USER" ] && [ -f "$XAUTHORITY" ]; then
echo " > GUI detected for user: $GUI_USER"
echo " > DISPLAY=$DISPLAY"
echo " > XAUTHORITY=$XAUTHORITY"

# Try to grant root access to user’s GUI session
if sudo -u "$REAL_USER" xhost +SI:localuser:root 2>/dev/null; then
echo " ✅ Root granted access to user X session"
else
echo " ❌ Failed to grant root access to X session"
fi

if xhost +SI:localuser:root >/dev/null 2>&1; then
echo " ✅ Root access to X session granted"
else
echo " ❌ Failed to grant root access to X session"
fi
else
echo " ⚠ GUI user or .Xauthority missing (GUI_USER=$GUI_USER, XAUTHORITY=$XAUTHORITY)"
fi
else
echo " > xhost command not found or no GUI"
fi

################################################################################

# === 9. Refresh System Identifier ===
echo "9. Reseting Host Descriptor..."

# Get current hostname (to clean up any old entry if needed)
CURRENT_HOSTNAME=$(hostname)
NEW_HOSTNAME=$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)

# Update /etc/hosts BEFORE applying hostname to avoid sudo errors
if grep -q "^127.0.1.1" /etc/hosts; then
if sed -i "s/^127.0.1.1.*/127.0.1.1 $NEW_HOSTNAME/" /etc/hosts; then
echo " ✅ /etc/hosts entry updated successfully"
else
echo " ❌ Failed to update /etc/hosts entry"
fi
else
if echo "127.0.1.1 $NEW_HOSTNAME" >> /etc/hosts; then
echo " ✅ /etc/hosts entry added successfully"
else
echo " ❌ Failed to add new /etc/hosts entry"
fi
fi

# Now apply the new hostname (no sudo needed inside root-run script)
if hostnamectl set-hostname "$NEW_HOSTNAME"; then
echo " ✅ Hostname changed to: $NEW_HOSTNAME"
else
echo " ❌ Failed to change hostname"
fi

################################################################################

# === 10. Refresh Network Interface Settings ===
echo "10. Refreshing Network Interface Settings..."

if sudo ip link set "$NET_IFACE" down; then
echo " ✅ Interface $NET_IFACE brought down."
else
echo " ❌ Failed to bring down interface $NET_IFACE."
fi

if sudo macchanger -r "$NET_IFACE"; then
echo " ✅ Adapter identity refreshed for $NET_IFACE."
else
echo " ❌ Unable to refresh adapter identity for $NET_IFACE."
fi

if sudo ip link set "$NET_IFACE" up; then
echo " ✅ Interface $NET_IFACE brought back up."
else
echo " ❌ Failed to bring up interface $NET_IFACE."
fi

echo " > Adapter identity refreshed and network interface reinitialized."

################################################################################

# === 11.0 Clear Redundant Session Data (Expanded and Safe) ===
echo "11.0 Clear Redundant Session Data..."

TRASH1="$REAL_HOME/.local/share/Trash/files"
TRASH2="$REAL_HOME/Desktop/Trash"

if [ -d "$TRASH1" ]; then
  echo " 🛡️  Shredding main trash contents..."
  find "$TRASH1" -type f -exec shred -u -n 3 -z {} \; 2>/dev/null || true
  if rm -rf "$TRASH1"/* 2>/dev/null; then
    echo " ✅ Main trash cleaned successfully"
  else
    echo " ❌ Failed to clean main trash"
  fi
else
  echo " ⚠ Main trash directory not found"
fi

# === 11.1 Clear Secure Trash Cleanup ===
echo " Clear Secure Trash Cleanup"
if rm -f "$REAL_HOME/.local/share/Trash/info/"* 2>/dev/null; then
  echo " ✅ Cleared Secure Trash Cleanup."
else
  echo " ⚠ Failed to clear Secure Trash Cleanup."
fi

if [ -d "$TRASH2" ]; then
  echo " 🛡️  Shredding desktop trash contents..."
  find "$TRASH2" -type f -exec shred -u -n 3 -z {} \; 2>/dev/null || true
  if rm -rf "$TRASH2"/* 2>/dev/null; then
    echo " ✅ Recycle bin cleared successfully"
  else
    echo " ❌ Failed to clear recycle bin"
  fi
else
  echo " ⚠ Recycle bin directory not found"
fi

echo " 11.2 Perform Routine Cache Maintenance"

cleanup_success=true

find "$REAL_HOME/.cache" -type f -exec rm -f {} \; 2>/dev/null || cleanup_success=false
find "$REAL_HOME/.thumbnails" -type f -exec rm -f {} \; 2>/dev/null || cleanup_success=false
rm -f "$REAL_HOME/.recently-used.xbel" 2>/dev/null || cleanup_success=false
rm -f "$REAL_HOME/.local/share/recently-used.xbel" 2>/dev/null || cleanup_success=false
rm -f "$REAL_HOME/.config/gtk-3.0/bookmarks" 2>/dev/null || cleanup_success=false
rm -f "$REAL_HOME/.bash_history" "$REAL_HOME/.zsh_history" 2>/dev/null || cleanup_success=false

# gvfs metadata cleanup — skip if inaccessible
if [ -d "$REAL_HOME/.local/share/gvfs-metadata" ]; then
  find "$REAL_HOME/.local/share/gvfs-metadata" -type f -exec rm -f {} \; 2>/dev/null || true
fi

if $cleanup_success; then
  echo " ✅ User workspace cleanup completed"
else
  echo " ⚠️ Some user workspace files may not have been removed (non-fatal)"
fi

################################################################################

# === 12. Preserve Essential GUI App Data (Whitelist) ===
echo "12. Whitelist essential GUI app data..."
mkdir -p "$REAL_HOME/.cloak_whitelist"

for dir in \
"$REAL_HOME/.config/libreoffice" \
"$REAL_HOME/.cache/libreoffice" \
"$REAL_HOME/.config/gtk-3.0" \
"$REAL_HOME/.cache/fontconfig"; do

if [ -d "$dir" ]; then
cp -a "$dir" "$REAL_HOME/.cloak_whitelist/" && \
echo " ✅ Preserved: $dir"
else
echo " ⚠ Skipped or missing: $dir"
fi
done

################################################################################

# === 13. Reset Temporary Session Files ===
echo "13. Reset Temporary Session Files..."

# shell history
if history -c && history -w; then
echo " ✅ Command log refreshed"
else
echo " ❌ Failed to refresh command log (continuing)"
fi

# unset HISTFILE
if unset HISTFILE 2>/dev/null; then
echo " ✅ HISTFILE unset"
else
echo " ⚠️ HISTFILE was not set or could not be unset (continuing)"
fi

# individual history / recent files
rm -f ~/.bash_history ~/.zsh_history ~/.local/share/recently-used.xbel && \
echo " ✅ Removed: ~/.bash_history ~/.zsh_history ~/.local/share/recently-used.xbel" || \
echo " ⚠️ Some history/recent files were missing or couldn't be removed (continuing)"

# browser caches
rm -rf ~/.cache/google-chrome ~/.cache/chromium ~/.cache/BraveSoftware && \
echo " ✅ Cleared browser caches" || \
echo " ⚠️ One or more browser cache dirs didn't exist or couldn't be removed (continuing)"

# browser configs
rm -rf ~/.config/BraveSoftware ~/.config/google-chrome ~/.config/chromium && \
echo " ✅ Wiped browser config directories" || \
echo " ⚠️ One or more browser config dirs didn't exist or couldn't be removed (continuing)"

echo " > Reset Temporary Session Files Complete"

################################################################################

# === 14. Restore Whitelisted GUI App Config ===
echo "14. Restoring GUI app config..."

WHITELIST_DIR="$HOME/.cloak_whitelist/libreoffice"

if [ -d "$WHITELIST_DIR" ]; then
mkdir -p ~/.config ~/.cache
cp -r "$WHITELIST_DIR" ~/.config/ 2>/dev/null
cp -r "$WHITELIST_DIR" ~/.cache/ 2>/dev/null
echo " ✅ Whitelisted GUI app config restored"
else
echo " ⚠ No GUI app config found in whitelist — skipping restore"
fi

rm -rf "$HOME/.cloak_whitelist"

################################################################################

# === 15. Reset X Display Auth Credentials ===
echo "15. Reset X Display Auth Credentials..."

REAL_USER="$REAL_USER"
REAL_HOME="/home/$REAL_USER"

if [ -f "$REAL_HOME/.Xauthority" ]; then
if cp /dev/null "$REAL_HOME/.Xauthority"; then
echo " ✅ Xauthority safely wiped at $REAL_HOME/.Xauthority"
else
echo " ❌ Failed to wipe $REAL_HOME/.Xauthority — check permissions"
fi
else
echo " ⚠ $REAL_HOME/.Xauthority not found — skipping"
fi

################################################################################

echo "16. Rotate System Maintenance Logs (Safe Mode)..."

# Rotate logs but avoid spamming truncate system-wide
LOG_DIRS=("/var/log" "/var/log/journal" "/run/log/journal")

for DIR in "${LOG_DIRS[@]}"; do
  if [ -d "$DIR" ]; then
    echo " ➤ Truncating logs in: $DIR"
    find "$DIR" -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null
  fi
done

# Let journald handle rotation without full vacuum stress
if journalctl --rotate; then
  echo " ✅ Journals rotated"
else
  echo " ⚠️ Journal rotation failed or was locked"
fi

# Instead of vacuuming all, delete oldest entries gently
if journalctl --vacuum-time=6h; then
  echo " ✅ Older journals removed (older than 6h)"
else
  echo " ⚠️ Journal vacuum skipped"
fi

################################################################################

# === 17. Perform System Log Maintenance ===
echo "17. Perform System Log Maintenance..."

if journalctl --rotate; then
echo " ✅ System logs cycled successfully"
else
echo " ❌ System logs cycle failed"
fi

if journalctl --vacuum-time=1s; then
echo " ✅ Log compression completed successfully"
else
echo " ❌ Log compression failed"
fi

if find /var/log/journal /run/log/journal -type f -name "*.journal" -not -newermt "1 minute ago" -delete 2>/dev/null; then
echo " ✅ Archived logs removed successfully"
else
echo " ⚠ Some log entries were locked or reserved"
fi

################################################################################

# === 18. Optimize Background Resource Usage ===
echo "18. Optimize Background Resource Usage..."
if killall geoclue geoclue-2.0 >/dev/null 2>&1; then
echo " ✅ Background services 'geoclue' and 'geoclue-2.0' terminated"
else
echo " ⚠ Some background services not running or already stopped (safe to ignore)"
fi

################################################################################

# === 19. Regenerate System Instance Identifiers ===
echo "19. Regenerate System Instance Identifiers..."

if sudo truncate -s 0 /etc/machine-id /var/lib/dbus/machine-id; then
echo " ✅ Cleared outdate system ID references."
else
echo " ❌ Failed to clear outdated system ID references."
fi

if sudo systemd-machine-id-setup; then
echo " ✅ Created fresh system ID."
else
echo " ❌ Failed to create fresh system ID."
fi

if sudo ln -sf /etc/machine-id /var/lib/dbus/machine-id; then
echo " ✅ Symlinked machine-id to D-Bus directory."
else
echo " ❌ Failed to link to persistent profile machine-id."
fi

echo " > System ID update completed"

################################################################################

# === 20. Reconnect Secure Network Service (via CLI readiness check) ===
echo "20. Reconnect Secure Network Service..."

# Ensure daemon is running
if sudo systemctl restart mullvad-daemon; then
echo " ✅ Mullvad daemon restarted successfully."
else
echo " ❌ Failed to restart Mullvad daemon — continuing anyway..."
fi

# Wait up to 30 seconds for Mullvad to respond
TIMEOUT=30
WAITED=0
CONNECTED=0

while [ $WAITED -lt $TIMEOUT ]; do
if mullvad status 2>&1 | grep -qE "Connected|Disconnected"; then
CONNECTED=1
break
fi
sleep 1
WAITED=$((WAITED + 1))
done

if [ "$CONNECTED" -eq 1 ]; then
echo " ✅ Daemon responsive after ${WAITED}s — attempting reconnect..."
if mullvad reconnect; then
echo " ✅ Mullvad reconnected successfully."
else
echo " ❌ Mullvad reconnect failed (daemon was responsive)."
fi
else
echo " ❌ Mullvad daemon unresponsive after ${TIMEOUT}s — skipping reconnect."
fi

################################################################################

# === 21. Apply Custom Network Access Policy (Integrity Monitoring Agent) ===
### You can also use Suricata as a more persistant IPS ###
echo "21. Apply Custom Network Access Policy..."

# Flush and set default policies
if sudo iptables -F && \
sudo iptables -P INPUT DROP && \
sudo iptables -P FORWARD DROP && \
sudo iptables -P OUTPUT ACCEPT; then
echo " ✅ Base firewall rules set (flush + default policies)"
else
echo " ❌ Failed to set base firewall rules" >&2
fi

# Allow local subnet access
if sudo iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT && \
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && \
sudo iptables -A INPUT -i lo -j ACCEPT; then
echo " ✅ Local + loopback access rules applied"
else
echo " ❌ Failed to apply local network rules" >&2
fi

# Drop pings, log others
if sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP && \
sudo iptables -A INPUT -j LOG --log-prefix "INTRUSION ATTEMPT: " --log-level 4; then
echo " ✅ ICMP blocked and logging enabled"
else
echo " ❌ Failed to apply ICMP block or logging rule" >&2
fi

echo " > Stealth firewall enabled. System protected from unauthorized remote access."

################################################################################

# === 22. Clear Volatile Memory Buffers ===
echo "22. Clear Volatile Memory Buffers..."

sync
swapoff -a 2>/dev/null

MEM_KILLER=$(mktemp /dev/shm/memwipe.XXXXXX)

# Fill memory with zeroes until full — ignores errors
if dd if=/dev/zero of="$MEM_KILLER" bs=1M status=none 2>/dev/null; then
echo " ✅ Cleared volatile memory buffers without interruption."
else
echo " ⚠ Memory buffer reached capcity -- operation concluded as expected."
fi

rm -f "$MEM_KILLER" && echo " Cleared temorary memory buffer." || echo " ⚠ Failed to clear temporary memory buffer."

echo " ✅ Alternate memory reset completed."

################################################################################

# === 23. Apply Kernel Security Mode ===
echo "23. Apply Kernel Security Mode..."

if sudo sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lockdown=confidentiality"/' /etc/default/grub; then
echo " ✅ GRUB kernel line updated successfully"
else
echo " ❌ Failed to update GRUB kernel line"
fi

if sudo update-grub; then
echo " ✅ GRUB successfully updated"
else
echo " ❌ Failed to update GRUB"
fi

################################################################################

# === 24. Restrict Non-Essential Kernel Drivers ===
echo "24. Restrict Non-Essential Kernel Drivers..."
sudo tee /etc/modprobe.d/blacklist-security.conf > /dev/null <<EOF
blacklist firewire-core
blacklist thunderbolt
blacklist usb-storage
blacklist sg
blacklist bpf
blacklist cuse
blacklist bluetooth
blacklist v4l2loopback
EOF

# === Feedback: Success/Failure Check ===
if [ -f /etc/modprobe.d/blacklist-security.conf ] && grep -q "blacklist firewire-core" /etc/modprobe.d/blacklist-security.conf; then
echo " ✅ Kernel driver restrictions applied successfully."
else
echo " ❌ Failed to apply kernel driver restrictions."
fi

################################################################################

# === 25. Clean up residual user data ===
echo "25. Clearing visual and usage cache..."

CLEAN_PATHS=(
"$REAL_HOME/.cache/"*
"$REAL_HOME/.thumbnails/"*
"$REAL_HOME/.recently-used.xbel"
"$REAL_HOME/.local/share/gvfs-metadata/"*
"$REAL_HOME/.local/share/recently-used.xbel"
"$REAL_HOME/.config/gtk-3.0/bookmarks"
"$REAL_HOME/.bash_history"
"$REAL_HOME/.zsh_history"
)

for TARGET in "${CLEAN_PATHS[@]}"; do
rm -rf $TARGET 2>/dev/null
if [ $? -eq 0 ]; then
echo " ✅ Removed: $TARGET"
else
echo " ⚠ Could not remove: $TARGET (may not exist)"
fi
done

echo " ✅ User environment cleanup completed successfully."

################################################################################

# === 26. Enable Real-Time System Integrity Watcher ===
echo "26. Enable Real-Time System Integrity Watcher..."

INTRUSION_MONITOR="/usr/local/bin/live_intrusion_monitor.sh"

if sudo tee "$INTRUSION_MONITOR" > /dev/null <<'EOF'
#!/bin/bash
CLOAK_SCRIPT="$NEO_HOME/phantom0_startup.sh"
LOG_FILE="/var/log/monitor_kills.log"

while true; do
SUSPICIOUS_PROCESSES=$(pgrep -f 'keylogger|snoop|record|screencap|tcpdump|nmap|telnet|bash -i|sh -i|zsh -i|python -c import pty')
if [ ! -z "$SUSPICIOUS_PROCESSES" ]; then
echo "[$(date)] Intrusion Detected! Killing PIDs: $SUSPICIOUS_PROCESSES" >> "$LOG_FILE"
kill -9 $SUSPICIOUS_PROCESSES

if command -v zenity &>/dev/null; then
DISPLAY=:0 zenity --warning --text="? Presence Detected: Intrusion stopped and system re-cloaked." --title="Cloak Alert"
elif command -v notify-send &>/dev/null; then
DISPLAY=:0 notify-send "? Presence Detected" "Intrusion stopped. Project Blackhole Sun initiated"
fi

bash "$CLOAK_SCRIPT" &
fi
sleep 5
done
EOF
then
echo " ✅ Integrity Monitoring Agent script created at: $INTRUSION_MONITOR"
else
echo " ❌ Failed to write Integrity Monitoring Agent script to: $INTRUSION_MONITOR"
fi

if sudo chmod +x "$INTRUSION_MONITOR"; then
echo " ✅ Made $INTRUSION_MONITOR executable"
else
echo " ❌ Failed to make $INTRUSION_MONITOR executable"
fi

################################################################################

# === 27. Optimize Remote Access Security ===
echo "27. Optimize Remote Access Security..."

sudo systemctl mask systemd-resolved.service 2>/dev/null \
&& echo " ✅ systemd-resolved masked" \
|| echo " ⚠️ Failed to mask systemd-resolved (may already be masked)"

if [ -f /etc/systemd/resolved.conf ]; then
sudo sed -i '/^#MulticastDNS=/c\MulticastDNS=no' /etc/systemd/resolved.conf \
&& echo " ✅ MulticastDNS disabled" \
|| echo " ⚠️ Failed to disable MulticastDNS"

sudo sed -i '/^#LLMNR=/c\LLMNR=no' /etc/systemd/resolved.conf \
&& echo " ✅ LLMNR disabled" \
|| echo " ⚠️ Failed to disable LLMNR"
else
echo " > resolved.conf not found -- skipping MulticastDNS and LLMNR settings"
fi

sudo sed -i '/^net.ipv4.icmp_echo_ignore_all/d' /etc/sysctl.conf

echo " net.ipv4.icmp_echo_ignore_all = 1" | sudo tee -a /etc/sysctl.conf >/dev/null \
&& echo " ✅ IPv4 ICMP echo ignore set in sysctl.conf" \
|| echo " ⚠️ Failed to write IPv4 ICMP echo ignore to sysctl.conf"

sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1 \
&& echo " ✅ Runtime IPv4 ICMP echo ignore applied" \
|| echo " ⚠️ Failed to apply runtime IPv4 ICMP echo ignore"

if [ -f /proc/sys/net/ipv6/icmp_echo_ignore_all ]; then
sudo sed -i '/^net.ipv6.icmp_echo_ignore_all/d' /etc/sysctl.conf

echo " net.ipv6.icmp_echo_ignore_all = 1" | sudo tee -a /etc/sysctl.conf >/dev/null \
&& echo " ✅ IPv6 ICMP echo ignore set in sysctl.conf" \
|| echo " ⚠️ Failed to write IPv6 ICMP echo ignore to sysctl.conf"

sudo sysctl -w net.ipv6.icmp_echo_ignore_all=1 \
&& echo " ✅ Runtime IPv6 ICMP echo ignore applied" \
|| echo " ⚠️ Failed to apply runtime IPv6 ICMP echo ignore"
else
echo " > IPv6 not enabled -- skipping ICMP6 echo ignore config"
fi

if sudo systemctl is-enabled ssh >/dev/null 2>&1; then
sudo systemctl disable --now ssh \
&& echo " ✅ SSH disabled" \
|| echo " ⚠️ Failed to disable SSH"
else
echo " > SSH not enabled -- safe"
fi

sudo iptables -F && echo " ✅ iptables flushed" || echo " ⚠️ Failed to flush iptables"
sudo iptables -P INPUT DROP && echo " ✅ Default INPUT policy set to DROP" || echo " ⚠️ Failed to set INPUT policy"
sudo iptables -P FORWARD DROP && echo " ✅ Default FORWARD policy set to DROP" || echo " ⚠️ Failed to set FORWARD policy"
sudo iptables -P OUTPUT ACCEPT && echo " ✅ Default OUTPUT policy set to ACCEPT" || echo " ⚠️ Failed to set OUTPUT policy"

sudo iptables -A INPUT -i lo -j ACCEPT && echo " ✅ Loopback input accepted" || echo " ⚠️ Failed to accept loopback input"
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
&& echo " ✅ Established/related input accepted" \
|| echo " ⚠️ Failed to allow established/related input"

echo " ✅ WiFi & remote access hardened"

################################################################################

# === 28.0 Private Browser Session Cleanup ===
echo "28.0 Private Browser Session Cleanup"
REAL_USER=$(id -nu 1000)
REAL_HOME=$(eval echo "~$REAL_USER")
TOR_HOME="$REAL_HOME/.local/share/torbrowser"

# --- 28.1 Pre-launch Tor to ensure profile/state exist ---
echo " 28.1 > Pre-launching Tor as $REAL_USER to ensure profile/state exist..."
sudo -u "$REAL_USER" DISPLAY=:0 XAUTHORITY="$REAL_HOME/.Xauthority" torbrowser-launcher --detach 2>/dev/null &
sleep 5
pkill -u "$REAL_USER" -f torbrowser-launcher 2>/dev/null
sleep 1

# --- 28.2 Reset Tor Browser User Data ---
echo " 28.2 Reset Tor Browser User Data"
TOR_PROFILE=$(find "$TOR_HOME" -type d -name "profile.default" 2>/dev/null | head -n 1)
if [ -n "$TOR_PROFILE" ] && [ -d "$TOR_PROFILE" ]; then
echo " ✅ Tor profile found at: $TOR_PROFILE"
rm -rf "$TOR_PROFILE/minidumps" \
"$TOR_PROFILE/sessionstore-backups" \
"$TOR_PROFILE/healthreport.sqlite" \
"$TOR_PROFILE/Telemetry.json" \
"$TOR_PROFILE/storage" \
"$TOR_PROFILE/save-session.json" \
"$TOR_PROFILE/.parentlock" && echo " Folder-specific data cleaned." || echo " ⚠ Failed to remove some directories."

rm -f "$TOR_PROFILE/formhistory.sqlite" \
"$TOR_PROFILE/webappsstore.sqlite" \
"$TOR_PROFILE/content-prefs.sqlite" \
"$TOR_PROFILE/siteSecurityServiceState.txt" \
"$TOR_PROFILE/permissions.sqlite" \
"$TOR_PROFILE/containers.json" \
"$TOR_PROFILE/search.json.mozlz4" \
"$TOR_PROFILE/xulstore.json" \
"$TOR_PROFILE/addonStartup.json.lz4" \
"$TOR_PROFILE/times.json" \
"$TOR_PROFILE/startupCache*" \
"$TOR_PROFILE/"*.bak 2>/dev/null && echo " Individual file data cleaned." || echo " ⚠ Some files could not be deleted."

echo " ✅ Tor configuration data refreshed."
# Wipe cache-based profile (startup thumbnails, safebrowsing, etc)
rm -rf "$TOR_HOME/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser/Caches/profile.default"
else
echo " ⚠ No Tor browser profile found. Skipping profile wipe..."
fi

# === 28.3. Reset Tor Network Configuration ===
echo " 28.3 Reset Tor Network Configuration"
TOR_STATE_DIRS=(
"$TOR_HOME/tbb/x86_64/tor-browser/Data/Tor"
"$TOR_HOME/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Tor"
"$TOR_HOME/tbb/x86_64/tor-browser/Browser/TorBrowser/Tor"
)

FOUND_TOR_STATE=false

for TOR_STATE in "${TOR_STATE_DIRS[@]}"; do
if [ -d "$TOR_STATE" ]; then
echo " Tor state directory found: $TOR_STATE"
rm -f "$TOR_STATE"/state \
"$TOR_STATE"/cached-* \
"$TOR_STATE"/*.log \
"$TOR_STATE"/geoip* \
"$TOR_STATE"/lock \
"$TOR_STATE"/*.auth_private && echo " ✅ Tor network data reset." || echo " ⚠ Certain Tor data files were in use and skipped."

rm -rf "$TOR_STATE/onion-services" "$TOR_STATE/hidden_services" 2>/dev/null && echo " ✅ Obsolete service paths purged." || echo " ⚠ Some obsolete service paths may not have existed."

echo " ✅ Reset Tor network configuration successfully."
FOUND_TOR_STATE=true
fi
done

if [ "$FOUND_TOR_STATE" = false ]; then
echo " ⚠ No Tor state directory found in known locations."
fi

# 28.4 Remove cleanup lock if it exists
echo " 28.4 Remove cleanup lock if it exists"
rm -f /tmp/firefox_cleanup.lock && echo " Removed cleanup lock." || echo " ⚠ No cleanup lock found or could not remove it."

################################################################################

# === 29. Clean up archived system logs ===
echo "29. Clean up archived system logs..."
journalctl --rotate && echo " ✅ System logs archived successfully" || echo " ❌ Failed to archive system logs"

journalctl --vacuum-time=1s && echo " ✅ Compressed system logs (older than 1 second)" || echo " ❌ Failed to compress system logs"

if find /var/log/journal /run/log/journal -type f -name "*.journal" -not -newermt "1 minute ago" -delete 2>/dev/null; then
echo " ✅ Archived log files removed"
else
echo " ⚠ Some archived log files may be protected or in use"
fi

################################################################################

# === 30. Low-Noise DNS Cleanup ===
echo "30. Entering low-noise networking mode..."

if sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1; then
echo " ✅ ICMP echo ignore enabled"
else
echo " ❌ Failed to set ICMP echo ignore"
fi

# Attempt DNS cache flush only if tool exists
if command -v resolvectl >/dev/null 2>&1; then
if resolvectl flush-caches >/dev/null 2>&1; then
echo " ✅ DNS cache flushed with resolvectl"
else
echo " ❌ Failed to flush DNS with resolvectl"
fi
elif command -v systemd-resolve >/dev/null 2>&1; then
if systemd-resolve --flush-caches >/dev/null 2>&1; then
echo " ✅ DNS cache flushed with systemd-resolve"
else
echo " ❌ Failed to flush DNS with systemd-resolve"
fi
else
echo " ⚠ No DNS flush tool found (resolvectl/systemd-resolve missing)"
fi

if rm -f /run/systemd/resolve/* 2>/dev/null; then
echo " ✅ DNS state files purged"
else
echo " ⚠ Could not purge DNS state files (may not exist)"
fi

echo " ✅ Low-noise exit complete."

exec > /dev/null 2>&1

################################################################################

# === Restore GUI App Data from Whitelist ===
echo "Restoring whitelisted GUI app data..."
for folder in "$REAL_HOME/.cloak_whitelist/"*; do
TARGET="$REAL_HOME/.${folder##*/}"
cp -a "$folder" "$TARGET" && \
echo " ✅ Restored: $TARGET"
done

################################################################################

pkill -u "$REAL_USER" -f "firefox"
pkill -u "$REAL_USER" -f tor

################################################################################

exit 0
