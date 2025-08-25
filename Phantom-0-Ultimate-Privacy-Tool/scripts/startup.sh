#!/usr/bin/env bash

################################################################################
# === Phantom-0 - Startup: Digital Hygiene & Security Process ===
################################################################################




################################################################################
# Replace these placeholders OR source an external config before running.
################################################################################
: "${REAL_USER:=your_user_here}"
: "${REAL_HOME:=/your_path_here}"
: "${PRIMARY_IFACE:=your_primary_iface_here}"      # e.g., wlp3s0, eth0, enp0s3
: "${VPN_IFACE:=your_vpn_iface_here}"              # e.g., wg0, tun0
: "${ALLOWED_LAN_CIDRS:=192.168.0.0/16,10.0.0.0/8}"
: "${LOG_DIR:=/your_ram_log_dir_here}"             # e.g., /run/phantom0/logs
: "${LEGACY_DIR:=/your_legacy_dir_here}"           # if the script refers to an old fixed path

################################################################################
# --- Runtime measurement + local timezone autodetect ---
################################################################################

# 0) Optional override from env/config (set PH0_TZ="Region/City" to force)
if [[ -n "${PH0_TZ:-}" ]]; then
  DETECTED_TZ="$PH0_TZ"
else
  DETECTED_TZ=""
  # 1) systemd-based distros
  if command -v timedatectl >/dev/null 2>&1; then
    tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
    [[ -n "$tz" && "$tz" != "n/a" ]] && DETECTED_TZ="$tz"
  fi
  # 2) /etc/localtime symlink → /usr/share/zoneinfo/Region/City
  if [[ -z "$DETECTED_TZ" && -L /etc/localtime ]]; then
    target=$(readlink -f /etc/localtime 2>/dev/null || true)
    if [[ "$target" == *"/zoneinfo/"* ]]; then
      DETECTED_TZ="${target##*/zoneinfo/}"
    fi
  fi
  # 3) Debian/Ubuntu style
  if [[ -z "$DETECTED_TZ" && -r /etc/timezone ]]; then
    tz=$(tr -d ' \t\r' </etc/timezone)
    [[ -n "$tz" ]] && DETECTED_TZ="$tz"
  fi
  # 4) RHEL/CentOS style
  if [[ -z "$DETECTED_TZ" && -r /etc/sysconfig/clock ]]; then
    tz=$(awk -F= '/^ZONE=/{gsub(/"/,"",$2); print $2}' /etc/sysconfig/clock)
    [[ -n "$tz" ]] && DETECTED_TZ="$tz"
  fi
  # 5) Final fallback
  : "${DETECTED_TZ:=UTC}"
fi

# Export TZ for this script’s process only (handles DST automatically)
export TZ="$DETECTED_TZ"

# Freeze local timezone “tokens” at script start (robust even if zoneinfo changes later)
START_TZ_NAME="$TZ"                   # e.g., America/Chicago
START_TZ_ABBR="$(date '+%Z')"         # e.g., CDT
START_TZ_OFFS="$(date '+%z')"         # e.g., -0500
START_ISO_OFFS="$(date '+%:z')"       # e.g., -05:00

# Record script start time in seconds
START_TIME="$(date +%s)"

# Header log entry
echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] >>> Script $(basename "$0") started (tz=${START_TZ_NAME}, offs=${START_ISO_OFFS})"

# Add this line at the start of your script to detect systemd execution
IS_SYSTEMD=$(pidof systemd > /dev/null && echo "1" || echo "0")

umask 007

# Minimize systemd correlation noise from child processes
export SYSTEMD_LOG_LEVEL=0

# Right after the shebang in ${REAL_HOME}/phantom0-startup.sh
PHANTOM0_VERSION="2025-08-15-23:18:banner1"
echo "[PHANTOM0-STARTUP] Running ${REAL_HOME}/phantom0-startup.sh version=$PHANTOM0_VERSION ts=$(date -Is)"

################################################################################
# Status helpers (lightweight)
################################################################################
STEP_TITLE=""
STEP_START=0
_green() { tput setaf 2 2>/dev/null; }
_red() { tput setaf 1 2>/dev/null; }
_reset() { tput sgr0 2>/dev/null; }

step() {
STEP_TITLE="$1"
STEP_START=$(date +%s)
echo "$STEP_TITLE"
}

_done() {
local rc="$1"; shift
local msg="$*"
local dur=$(( $(date +%s) - STEP_START ))
if [ "$rc" -eq 0 ]; then
echo " $(_green)✅$(_reset) ${msg} (${dur}s)"
else
echo " $(_red)❌$(_reset) ${msg} (rc=${rc}, ${dur}s)"
fi
}

# run "label" cmd...
# Replace your current run() with this
run() {
local label="$1"; shift
local tmp rc start end
tmp="$(mktemp)"
start=$(date +%s)
"$@" >"$tmp" 2>&1; rc=$?
end=$(date +%s)
local dur=$(( end - start ))
if [ $rc -eq 0 ]; then
echo " ✅ ${label} (${dur}s)"
else
echo " ❌ ${label} (rc=${rc}, ${dur}s)"
sed -e 's/^/ · /' <"$tmp" | head -n 8
fi
rm -f "$tmp"
return $rc
}
warn() {
echo " ⚠ $1"
[ -n "$2" ] && echo " · $2"
}

################################################################################
# Background service initialization (guarded)
################################################################################
if [[ "$1" == "--systemd-safe" && -z "${SERVICE_EXEC_ONCE:-}" ]]; then
export SERVICE_EXEC_ONCE=1
exec -a "system-privacy-service" /bin/bash "$0" --already-execed "${@:2}"
fi
# Ignore internal marker on second entry
if [[ "$1" == "--already-execed" ]]; then shift; fi

# Ensure logs dir exists before chown
install -d -m 0750 -o root -g ${REAL_USER} ${REAL_HOME}/phantom0_logs 2>/dev/null
run "Initialize log directory ownership" sudo chown -R root:${REAL_USER} ${REAL_HOME}/phantom0_logs
run "Set log directory permissions" sudo chmod 750 ${REAL_HOME}/phantom0_logs


###############################################################################
# Digital Footprint Reduction Toolkit (HDD vs SSD, CoW detection, strict/normal routing)
###############################################################################

# 0 = light-touch (truncate/rm + trim); 1 = strict (prefer secure methods where meaningful)
: "${SANITIZE_STRICT:=0}"

# FS & device helpers
fs_type_of() { stat -f -c %T "$1" 2>/dev/null || echo unknown; } # ext2/ext3,xfs,btrfs,zfs,overlay,tmpfs,...
is_cow_or_tmpfs() { case "$(fs_type_of "$1")" in btrfs|zfs|overlay|tmpfs) return 0 ;; * ) return 1 ;; esac; }

# --- Circuit breakers: refuse dangerous targets ---
# NOTE: $REAL_HOME *root* is intentionally NOT allowed here (only subpaths).
_confirm_safe_dir() {
case "$1" in
"$REAL_HOME"/*|"$REAL_HOME/.cache"|"$REAL_HOME/.cache"/*|"/tmp"/*|"/var/tmp"/*|"/dev/shm"/*)
return 0 ;;
*)
echo " ! REFUSING unsafe path: $1" >&2; return 1 ;;
esac
}

# Allow the home root specifically for free-space/TRIM; otherwise enforce normal safety.
_confirm_free_space_target() {
case "$1" in
"$REAL_HOME"|"$REAL_HOME"/*) return 0 ;;
*) _confirm_safe_dir "$1" ;;
esac
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# True (exit 0) if the underlying block device for PATH is rotational (HDD).
# Follows dm-crypt/LVM "slaves" down to the real device (e.g., nvme0n1, sda).
is_rotational() {
local path="$1" dev base sysb rc=1
dev="$(df -P "$path" | awk 'NR==2{print $1}')" || return 1
dev="${dev#/dev/}" # e.g., mapper/luks-..., nvme0n1p3
base="${dev%%[0-9]*}" # strip partition number

# If this is a device-mapper node (dm-crypt/LVM), walk its slaves
if [ -d "/sys/block/$base/slaves" ] && ls /sys/block/"$base"/slaves/* >/dev/null 2>&1; then
rc=1
for s in /sys/block/"$base"/slaves/*; do
sysb="$(basename "$s")" # e.g., nvme0n1
if [ -r "/sys/block/$sysb/queue/rotational" ] && grep -q '^1$' "/sys/block/$sysb/queue/rotational"; then
rc=0; break
else
rc=1
fi
done
return "$rc"
fi

# Direct block device case
if [ -r "/sys/block/$base/queue/rotational" ]; then
grep -q '^1$' "/sys/block/$base/queue/rotational"
else
return 1
fi
}

# Single-file sanitization
sanitize_file() {
local f="$1"
[ -e "$f" ] || return 0
has_cmd chattr && chattr -i "$f" 2>/dev/null || true

if [ "$SANITIZE_STRICT" -eq 1 ] && has_cmd shred && is_rotational "$f" && ! is_cow_or_tmpfs "$f"; then
sudo -u "$REAL_USER" shred -n 3 -z -u -- "$f" 2>/dev/null || shred -n 3 -z -u -- "$f"
else
if has_cmd truncate; then
sudo -u "$REAL_USER" truncate -s 0 -- "$f" 2>/dev/null || truncate -s 0 -- "$f"
else
sudo -u "$REAL_USER" bash -c ': > "$1"' _ "$f" 2>/dev/null || : > "$f"
fi
fi
}

# Directory tree sanitization (ephemeral data only) — $REAL_HOME root is not allowed here
sanitize_tree() {
local d="$1"
[ -d "$d" ] || return 0
_confirm_safe_dir "$d" || return 1
if [ "$SANITIZE_STRICT" -eq 1 ] && has_cmd shred && is_rotational "$d" && ! is_cow_or_tmpfs "$d"; then
find "$d" -type f -exec shred -n 3 -z -u -- {} + 2>/dev/null || true
find "$d" -depth -type d -empty -exec rmdir -- {} + 2>/dev/null || true
else
rm -rf --one-file-system "$d"/* "$d"/.[!.]* "$d"/..?* 2>/dev/null || true
find "$d" -type d -empty -delete 2>/dev/null || true
fi
}

# Free-space sanitization (calls fstrim on SSD/NVMe; random+zero on HDD in strict mode)
# Uses the special confirmer to allow $REAL_HOME root specifically for TRIM.
sanitize_free_space() {
local path="$1" mnt rand zero
_confirm_free_space_target "$path" || return 1
mnt="$(df -P "$path" | awk 'NR==2{print $6}')" || return 0
if is_rotational "$path" && ! is_cow_or_tmpfs "$path" && [ "$SANITIZE_STRICT" -eq 1 ]; then
rand="$mnt/.wipe.rand.$$"; zero="$mnt/.wipe.zero.$$"
dd if=/dev/urandom of="$rand" bs=16M status=none || true; sync; rm -f "$rand"
dd if=/dev/zero of="$zero" bs=16M status=none || true; sync; rm -f "$zero"
else
has_cmd fstrim && fstrim -v "$mnt" >/dev/null 2>&1 || true
fi
}

################################################################################
# 1. Privilege Verification and System Safety Checks
################################################################################
step "1. Verifying System Permissions and Execution Context..."

# Root verification
if [[ "$EUID" -ne 0 ]]; then
echo " $(_red)> ERROR:$(_reset) Elevated privileges required"
exit 1
else
echo " $(_green)> Privilege level confirmed$(_reset)"
fi

# Correct initialization check for systemd and non-interactive environment
if [[ "$1" != "--systemd-safe" && -z "$DISPLAY" && -z "$SSH_CONNECTION" && "$(tty)" != "/dev/tty1" && ! -t 0 && ! $IS_SYSTEMD ]]; then
echo " $(_red)> ERROR:$(_reset) Incorrect initialization method"
echo " $(_yellow)> Debug info: \$(tty) = $(tty), \$DISPLAY = $DISPLAY, \$SSH_CONNECTION = $SSH_CONNECTION, \$1 = $1, ! -t 0 = $([[ ! -t 0 ]])" # Debugging line
exit 1
else
echo " $(_green)> Execution environment validated$(_reset)"
fi
_done 0 "Environment checks passed"

################################################################################
# 2. Logging System Initialization
################################################################################
step "2. Initializing Diagnostic Logging System..."
REAL_USER=${REAL_USER}
REAL_HOME="/home/$REAL_USER"
LOG_DIR="$REAL_HOME/phantom0_logs"

# Fallback if not writable
if [ ! -w "$LOG_DIR" ]; then
LOG_DIR="/var/log/phantom0"
echo " [] Using secure logging location: $LOG_DIR"
fi

run "Ensure logging directory exists" mkdir -p "$LOG_DIR"
run "Harden logging directory perms" chmod 770 "$LOG_DIR"
run "Set logging directory owner" chown root:root "$LOG_DIR"

# Logfile creation with line-buffered tee for live console visibility
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
LOGFILE="$LOG_DIR/phantom0-startup_$TIMESTAMP.log"
exec > >(stdbuf -oL -eL tee -a "$LOGFILE") 2> >(stdbuf -oL -eL tee -a "$LOG_DIR/phantom0-startup_$TIMESTAMP.err" >&2)

echo " [] Service initialized at $(date)"

run "Write startup breadcrumb to syslog" sudo bash -c "logger -t phantom0-startup \"Started at $(date)\"; echo \"[phantom0-startup] Started at $(date)\" >> /var/log/phantom0-startup.log"

################################################################################
# 3. System Dependency Verification
################################################################################
step "3. Verifying System Components..."
if ! command -v tpm2_clear >/dev/null; then
run "Install tpm2-tools" env DEBIAN_FRONTEND=noninteractive apt-get -yq install tpm2-tools
else
echo " [] tpm2-tools present"
fi
_done 0 "Dependency check complete"

################################################################################
# 4. User Environment Configuration
################################################################################
step "4. Configuring User Environment..."

# Prefer UID 1000 (primary desktop user). Fallback to invoking user.
if id -nu 1000 >/dev/null 2>&1; then
REAL_USER="$(id -nu 1000)"
else
REAL_USER="${SUDO_USER:-${LOGNAME:-$(logname 2>/dev/null || true)}}"
fi

# Hard failure if we still don't have a user
if [ -z "${REAL_USER:-}" ]; then
_done 1 "User identification failed (no REAL_USER)"; exit 1
fi

# Resolve home via passwd; fallback to ~REAL_USER
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[ -z "$REAL_HOME" ] && REAL_HOME="$(eval echo "~$REAL_USER")"

# Verify home exists and is a directory
if [ ! -d "$REAL_HOME" ]; then
_done 1 "Home directory verification failed for $REAL_USER ($REAL_HOME)"; exit 1
fi

# Export so subshells (bash -lc / runuser) can see them
export REAL_USER REAL_HOME

echo " [] User environment: $REAL_USER ($REAL_HOME)"
_done 0 "User environment configured"

################################################################################
# 5. Persistent Profile Management
################################################################################
step "5. Managing Application Profiles..."
PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"
BACKUP_DIR="$REAL_HOME/.firefox_profile_backups"

if [ ! -d "$PERSISTENT_PROFILE" ]; then
run "Create persistent profile dir" mkdir -p "$PERSISTENT_PROFILE"
run "Restore bookmarks" cp -f "$BACKUP_DIR/places.sqlite" "$PERSISTENT_PROFILE/" 2>/dev/null
run "Restore logins" cp -f "$BACKUP_DIR/logins.json" "$PERSISTENT_PROFILE/" 2>/dev/null
run "Restore key DB" cp -f "$BACKUP_DIR/key4.db" "$PERSISTENT_PROFILE/" 2>/dev/null
run "Restore cert DB" cp -f "$BACKUP_DIR/cert9.db" "$PERSISTENT_PROFILE/" 2>/dev/null
fi

RANDOM_PROFILE=$(find "$REAL_HOME/.mozilla/firefox" -maxdepth 1 -type d \( -name "*.default-release" -o -name "*.default" \) | head -n 1)
if [ -n "$RANDOM_PROFILE" ] && [ ! -L "$RANDOM_PROFILE" ]; then
run "Link Firefox profile -> persistent" bash -c "rm -rf \"$RANDOM_PROFILE\" && ln -s \"$PERSISTENT_PROFILE\" \"$RANDOM_PROFILE\""
fi

# Clear immutability flags if present, then chown
run "Remove immutable flags (if any)" chattr -i -a "$PERSISTENT_PROFILE"/{places.sqlite,logins.json,key4.db,cert9.db} 2>/dev/null
run "Ensure profile ownership" chown -R "$REAL_USER:$REAL_USER" "$PERSISTENT_PROFILE"
_done 0 "Firefox persistent profile ready"

################################################################################
# 6. Browser Session Management
################################################################################
step "6. Managing Browser Sessions..."

# --- Safety: ensure persistent profile exists ---
if [ -z "${PERSISTENT_PROFILE:-}" ]; then
PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"
fi
[ -d "$PERSISTENT_PROFILE" ] || mkdir -p "$PERSISTENT_PROFILE"
chown -R "$REAL_USER:$REAL_USER" "$PERSISTENT_PROFILE"

echo " 6.1 Terminating existing browser processes..."
run "Terminate firefox (soft)" bash -lc '
if pkill -u "$REAL_USER" -x firefox 2>/dev/null; then
echo " ✓ firefox terminated (soft)"; exit 0
else
if pgrep -u "$REAL_USER" -x firefox >/dev/null; then
echo " ✗ firefox still running after soft attempt"; exit 1
else
echo " ✓ firefox not running (nothing to terminate, soft)"; exit 0
fi
fi
'
sleep 1
run "Terminate firefox (hard)" bash -lc '
if pkill -9 -u "$REAL_USER" -x firefox 2>/dev/null; then
echo " ✓ firefox terminated (hard)"; exit 0
else
if pgrep -u "$REAL_USER" -x firefox >/dev/null; then
echo " ✗ firefox still running after hard attempt"; exit 1
else
echo " ✓ firefox not running (nothing to terminate, hard)"; exit 0
fi
fi
'

echo " 6.2 Clearing browsing artifacts..."
run "Clear Firefox history and form data, but keep bookmarks and saved logins" bash -lc '
prof_root="'"$REAL_HOME"'/.mozilla/firefox"
profs=( "$prof_root"/*.default* "$prof_root"/*.default-release )
if [ ${#profs[@]} -eq 0 ]; then
echo " ! no Firefox profiles found; skipping"; exit 0
fi
okc=0; warnc=0
for p in "${profs[@]}"; do
db="$p/places.sqlite"
[ -f "$db" ] || { echo " ! no places.sqlite in $p; skipping"; continue; }
if sqlite3 "$db" <<'SQL' >/dev/null 2>&1
.timeout 3000
PRAGMA journal_mode=WAL;
PRAGMA wal_checkpoint=FULL;
BEGIN;
DELETE FROM moz_historyvisits;
DELETE FROM moz_inputhistory;
DELETE FROM moz_places
WHERE id NOT IN (SELECT fk FROM moz_bookmarks)
AND visit_count = 0;
COMMIT;
VACUUM;
SQL
then
echo " ✓ history purge ($p)"; okc=$((okc+1))
else
echo " ! history purge warning (locked?) -> $p"; warnc=$((warnc+1))
fi
done
echo " -> profiles processed: $okc ok, $warnc warnings"
exit 0
'

# Purge Firefox form & search history (typed URLs, search box autocomplete)
run "6.2.1 Clear Firefox form & search history" bash -lc '
DB="'"$PERSISTENT_PROFILE"'/formhistory.sqlite"
if [ -f "$DB" ]; then
if sqlite3 "$DB" <<SQL
DELETE FROM moz_formhistory;
VACUUM;
SQL
then
echo " ✓ formhistory.sqlite cleared"
else
echo " ! failed to clear formhistory.sqlite"
fi
else
echo " ! formhistory.sqlite not found"
fi
'

echo " 6.3 Refreshing temporary data stores..."
run "Delete cookie/storage DBs" bash -lc '
find "'"$REAL_HOME/.mozilla/firefox"'" -type f \
\( -name cookies.sqlite -o -name webappsstore.sqlite -o -name storage.sqlite -o -name permissions.sqlite \) -delete
'

echo " 6.4 Removing unused profiles..."
bash -lc '
shopt -s nullglob
for PROFILE in "'"$REAL_HOME"'/.mozilla/firefox"/*.default*; do
if [ -n "$PROFILE" ] && [ ! -L "$PROFILE" ] && [[ "$PROFILE" != *".firefox_persistent_profile" ]]; then
run "Remove $PROFILE" rm -rf "$PROFILE"
fi
done
'

echo " 6.5 Initializing browser profiles..."
# Pre-clean locks right before launch (prevents stuck DB/lock states)
run "Pre-clean Firefox locks" bash -lc '
rm -f "'"$PERSISTENT_PROFILE"'"/places.sqlite-{shm,wal} \
"'"$PERSISTENT_PROFILE"'"/{parent.lock,.startup-incomplete,sessionCheckpoints.json,sessionstore.jsonlz4,recovery.jsonlz4,recovery.baklz4} 2>/dev/null || true
'

# Optional Minimal-Footprint Mode (preserve bookmarks/logins) — enable per-run
: "${ENABLE_FIREFOX_MINIMAL_FOOTPRINT_PRESERVE:=0}"
if [ "${ENABLE_FIREFOX_MINIMAL_FOOTPRINT_PRESERVE}" -eq 1 ]; then
if mount | grep -q "on /dev/shm "; then
RUNTIME_PROFILE="/dev/shm/firefox_runtime_$REAL_USER"
else
RUNTIME_PROFILE="$REAL_HOME/.cache/firefox_runtime_$REAL_USER"
fi
export RUNTIME_PROFILE

echo " 6.5a Preparing cleanup of runtime profile (preserve bookmarks/logins)..."
run "Prepare runtime profile dir" bash -lc '
rm -rf --one-file-system "'"$RUNTIME_PROFILE"'" 2>/dev/null || true
mkdir -p "'"$RUNTIME_PROFILE"'"
chown -R "$REAL_USER:$REAL_USER" "'"$RUNTIME_PROFILE"'"
'
run "Sync whitelist -> runtime" bash -lc '
src="'"$PERSISTENT_PROFILE"'" ; dst="'"$RUNTIME_PROFILE"'"
[ -d "$src" ] || { echo " ✗ persistent profile missing: $src"; exit 1; }
for f in places.sqlite logins.json key4.db cert9.db; do
[ -f "$src/$f" ] && install -m 600 -o "$REAL_USER" -g "$REAL_USER" "$src/$f" "$dst/$f" || true
done
echo " ✓ whitelist staged into runtime"
'
export FIREFOX_PROFILE_OVERRIDE="$RUNTIME_PROFILE"
fi

################################################################################
# 7. Session Context Detection
################################################################################
step "7. Detecting Session Context..."
if [[ -z "$SUDO_USER" && -z "$XDG_RUNTIME_DIR" ]]; then
echo " > System service environment detected"
else
echo " > Interactive session detected"
fi
_done 0 "Session context noted"

################################################################################
# 7.1 Auto-detect and mount USB devices (safe; supports plain & LUKS-on-USB)
################################################################################
step "7.1 Auto-detect and mount USB devices..."

auto_mount_usb() {
echo " 7.1 Checking for USB devices..."

# Ensure usb-storage is present; don’t fail if not
modprobe usb-storage >/dev/null 2>&1 || true

# Wait for device events to settle
udevadm settle || true

# Only consider true USB transports; avoids internal NVMe/SATA (protects system LUKS)
dev=$(lsblk -dpno NAME,TRAN | awk '$2=="usb" {print $1}' | head -n1)
if [ -z "$dev" ]; then
echo " ! No USB device detected"
return 0
fi
echo " ✓ Found USB disk: $dev"

# Choose first partition on that USB disk
part=$(lsblk -dpno NAME "$dev" | awk 'NR==2{print $1}')
if [ -z "$part" ]; then
echo " ! No partition found on $dev"; return 0
fi
echo " ✓ Found partition: $part"

mount_point="$REAL_HOME/usb"
mkdir -p "$mount_point"
chown "$REAL_USER:$REAL_USER" "$mount_point" 2>/dev/null || true

# If partition is LUKS-container-on-USB, **do NOT** invent a random key.
# We either prompt (via udisksctl) or skip if non-interactive.
if cryptsetup isLuks "$part" >/dev/null 2>&1; then
echo " • Detected LUKS on USB partition"
if command -v udisksctl >/dev/null 2>&1; then
# Unlock will prompt (GUI/TTY). This NEVER touches your system LUKS root.
if udisksctl unlock -b "$part"; then
# Find mapper name created by udisks
mapper=$(lsblk -dpno NAME,TYPE | awk '/mapper/ {print $1}' | tail -n1)
if [ -n "$mapper" ]; then
if udisksctl mount -b "$mapper" >/dev/null 2>&1; then
# Determine actual path udisks used
mp=$(lsblk -no MOUNTPOINT "$mapper" | head -n1)
echo " ✓ LUKS USB mounted at: ${mp:-$mount_point}"
else
echo " ! udisksctl failed to mount mapper"
fi
else
echo " ! Could not determine mapper device"
fi
else
echo " ! LUKS unlock cancelled/failed (skipping mount)"
fi
else
echo " ! udisksctl not found; cannot safely prompt for LUKS passphrase"
echo " (Install udisks2 or mount manually for encrypted USBs)"
fi
else
# Plain (non-encrypted) USB partition. Mount with user ownership.
if mount -o uid=1000,gid=1000,umask=0022 "$part" "$mount_point"; then
echo " ✓ Mounted $part at $mount_point"
else
echo " ✗ Failed to mount $part"
fi
fi
}

auto_mount_usb
_done 0 "USB auto-detection and mount complete"

################################################################################
# 8. Display Authority Configuration
################################################################################
step "8. Configuring Display Authority..."
if [ -n "$DISPLAY" ] && [ -f "$XAUTHORITY" ]; then
echo " > Existing display configuration detected"
elif [ -f "$REAL_HOME/.Xauthority" ]; then
export DISPLAY=:0
export XAUTHORITY="$REAL_HOME/.Xauthority"
echo " > Manual display configuration applied"
else
echo " > No display configuration required"
fi
_done 0 "Display authority handled"

################################################################################
# 9. Network Interface Initialization
################################################################################
step "9. Initializing Network Systems..."
NET_IFACE="${PRIMARY_IFACE}"
sleep 2
if ip link show "$NET_IFACE" | grep -q "state UP"; then
echo " Network interface active"
else
warn "Network interface status uncertain" "Interface: $NET_IFACE"
fi
_done 0 "Network init step done"

################################################################################
# 10. Display Access Verification
################################################################################
step "10. Verifying Display Access..."
GUI_USER=$(who | grep -m1 '(:' | awk '{print $1}')
GUI_HOME=$(eval echo "~$GUI_USER")
XAUTHORITY_PATH="$GUI_HOME/.Xauthority"
if [ -z "$DISPLAY" ]; then
DISPLAY=$(who | grep -m1 '(:' | awk -F'[()]' '{print $2}')
export DISPLAY=":$DISPLAY"
fi
export XAUTHORITY="$XAUTHORITY_PATH"
if [ -n "$GUI_USER" ] && [ -f "$XAUTHORITY" ]; then
run "Authorize root to X" sudo -u "$REAL_USER" xhost +SI:localuser:root
fi
_done 0 "Display access verified"

################################################################################
# 11. Host Identification Management
################################################################################
step "11. Managing System Identification..."
CURRENT_HOSTNAME=$(hostname)
NEW_HOSTNAME=$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)
if grep -q "^127.0.1.1" /etc/hosts; then
run "Update /etc/hosts entry" sed -i "s/^127.0.1.1.*/127.0.1.1 $NEW_HOSTNAME/" /etc/hosts
else
run "Append /etc/hosts entry" bash -c "echo '127.0.1.1 $NEW_HOSTNAME' >> /etc/hosts"
fi
run "Apply hostname" hostnamectl set-hostname "$NEW_HOSTNAME"
echo " System identification updated"
_done 0 "Hostname refreshed"

################################################################################
# 12. Network Identity Refresh
################################################################################
step "12. Refreshing Network Identity..."
run "Bring interface down" ip link set "$NET_IFACE" down
run "Refreshing MAC" macchanger -r "$NET_IFACE"
run "Bring interface up" ip link set "$NET_IFACE" up
echo " Network interface reconfigured"
_done 0 "Network identity refreshed"

################################################################################
# 13. System Hygiene & Workspace Tidying
################################################################################
step "13. Performing System Cleanup..."

echo " 13.1 Recycling bin housekeeping..."
run "Empty $REAL_HOME/.local/share/Trash/files" bash -lc '
dir="'"$REAL_HOME"'/.local/share/Trash/files"
[ -d "$dir" ] || exit 0
rm -rf --one-file-system "$dir"/* 2>/dev/null || true
echo " ✓ bin emptied"
'

echo " 13.2 Refreshing recent activity & caches..."

# 13.2.1 Light-touch refresh of “recent items” (keeps files; trims contents)
run "Recent items housekeeping" bash -lc '
shopt -s nullglob
files=(
"'"$REAL_HOME"'/.bash_history"
"'"$REAL_HOME"'/.zsh_history"
"'"$REAL_HOME"'/.lesshst"
"'"$REAL_HOME"'/.local/share/recently-used.xbel"
)
okc=0; warnc=0
for f in "${files[@]}"; do
[ -e "$f" ] || continue
if sanitize_file "$f"; then
echo " ✓ refreshed: $f"; okc=$((okc+1))
else
echo " ! could not refresh: $f"; warnc=$((warnc+1))
fi
done
echo " -> recent items: $okc ok, $warnc notes"
exit 0
'

# 13.2.2 Browser history hygiene (preserves bookmarks/logins)
run "Browser history hygiene (Firefox)" bash -lc '
shopt -s nullglob
prof_root="'"$REAL_HOME"'/.mozilla/firefox"
profs=( "$prof_root"/*.default* "$prof_root"/*.default-release )
[ ${#profs[@]} -eq 0 ] && { echo " ! no profiles found; skipping"; exit 0; }

for p in "${profs[@]}"; do
db="$p/places.sqlite"
[ -f "$db" ] || { echo " ! no places.sqlite in $p; skipping"; continue; }
sqlite3 "$db" <<'SQL' >/dev/null 2>&1 || true
.timeout 3000
PRAGMA journal_mode=WAL;
PRAGMA wal_checkpoint=FULL;
BEGIN;
-- remove visit/input history, keep bookmarks/passwords intact
DELETE FROM moz_historyvisits;
DELETE FROM moz_inputhistory;
-- prune unbookmarked, unvisited URLs; bookmarks remain
DELETE FROM moz_places
WHERE id NOT IN (SELECT fk FROM moz_bookmarks)
AND visit_count = 0;
COMMIT;
VACUUM;
SQL
echo " ✓ history refreshed ($p)"
done
exit 0
'

# 13.2.3 Cache refresh (avoids profile databases; focuses on ephemeral data)
run "Cache refresh" bash -lc '
shopt -s nullglob
targets=(
"'"$REAL_HOME"'/.cache"
"'"$REAL_HOME"'/.cache/mozilla"
/var/tmp
/tmp
/dev/shm
)
# include snap app caches if present
for snapc in "'"$REAL_HOME"'/snap/"*"/common/.cache"; do
[ -d "$snapc" ] && targets+=( "$snapc" )
done

for t in "${targets[@]}"; do
[ -d "$t" ] || continue
sanitize_tree "$t"
done

echo " ✓ caches refreshed"
exit 0
'

echo " 13.3 Refreshing temporary data stores..."
run "Temp space reset" bash -lc '
for d in /tmp /var/tmp /dev/shm; do
[ -d "$d" ] && sanitize_tree "$d"
done
echo " ✓ temporary spaces reset"
exit 0
'

# SSD: fstrim; HDD strict: random+zero free space (best-effort)
sanitize_free_space "$REAL_HOME"

_done 0 "System hygiene completed"

################################################################################
# 14. Application Configuration Preservation
################################################################################
step "14. Preserving Critical Application Data..."
mkdir -p "$REAL_HOME/.privacy_whitelist"
for dir in "$REAL_HOME/.config/libreoffice" "$REAL_HOME/.cache/libreoffice" "$REAL_HOME/.config/gtk-3.0" "$REAL_HOME/.cache/fontconfig"; do
[ -d "$dir" ] && run "Whitelist $(basename "$dir")" cp -a "$dir" "$REAL_HOME/.privacy_whitelist/"
done
_done 0 "App config preserved"

################################################################################
# 15. Session History Management
################################################################################
step "15. Managing Session History..."
run "Clear shell history" bash -c 'history -c; history -w; unset HISTFILE; rm -f ~/.bash_history ~/.zsh_history ~/.local/share/recently-used.xbel'
run "Clear Chromium/Brave/Chrome caches" rm -rf ~/.cache/{google-chrome,chromium,BraveSoftware} ~/.config/{BraveSoftware,google-chrome,chromium}
_done 0 "Session history cleared"

################################################################################
# 16. Application Configuration Restoration
################################################################################
step "16. Restoring Application Configurations..."
WHITELIST_DIR="$REAL_HOME/.privacy_whitelist/libreoffice"
if [ -d "$WHITELIST_DIR" ]; then
run "Recreate config/cache dirs" bash -c 'mkdir -p ~/.config ~/.cache'
run "Restore LibreOffice config" cp -r "$WHITELIST_DIR" ~/.config/
run "Restore LibreOffice cache" cp -r "$WHITELIST_DIR" ~/.cache/
fi
run "Drop whitelist staging" rm -rf "$HOME/.privacy_whitelist"
_done 0 "App configuration restoration done"

################################################################################
# 17. Display Credential Management
################################################################################
step "17. Managing Display Credentials..."
[ -f "$REAL_HOME/.Xauthority" ] && run "Blank Xauthority" cp /dev/null "$REAL_HOME/.Xauthority"
_done 0 "Display credentials reset"

################################################################################
# 18. Maintaining System Logs
################################################################################
echo " 18. Maintaining System Logs..."

# Defer journald maintenance when running under systemd unless explicitly overridden.
if [ -n "${INVOCATION_ID:-}" ] && [ "${DEFER_JOURNAL_ROTATE:-1}" -eq 1 ]; then
echo " - Detected systemd unit context (INVOCATION_ID present)."
echo " - Deferring journald maintenance to preserve live unit logs."
echo " - To force run under systemd, set: DEFER_JOURNAL_ROTATE=0"
_done 0 "Logs maintained (deferred under systemd)"
else
overall_ok=1

run "Rotate journals" journalctl --rotate
r1=$?
if [ $r1 -eq 0 ]; then
echo " ✓ Rotated journals"
else
echo " ✗ Failed Rotate journals (rc=$r1)"
overall_ok=0
fi

run "Vacuum journals to 1s" journalctl --vacuum-time=1s
r2=$?
if [ $r2 -eq 0 ]; then
echo " ✓ Vacuumed journals to 1s"
else
echo " ✗ Failed to Vacuum journals to 1s (rc=$r2)"
overall_ok=0
fi

run "Purge old journal files" bash -lc 'find /var/log/journal -type f -name "*.journal~" -delete 2>/dev/null || true'
r3=$?
if [ $r3 -eq 0 ]; then
echo " ✓ Purged old journal files (*.journal~)"
else
echo " ✗ Failed to Purge old journal files (rc=$r3)"
overall_ok=0
fi

if [ $overall_ok -eq 1 ]; then
_done 0 "Logs successfully maintained"
else
_done 1 "Logs maintenance completed with errors"
fi
fi

################################################################################
# 19. Background Service Management
################################################################################
step "19. Optimizing Background Services..."
run "Kill geoclue services" bash -c 'killall geoclue geoclue-2.0 2>/dev/null || true'
_done 0 "Background services optimized"

################################################################################
# 20. System Identification Regeneration
################################################################################
step "20. Refreshing System Identifiers..."
run "Refreshing machine-id files" truncate -s 0 /etc/machine-id /var/lib/dbus/machine-id
run "Optimize machine-id" systemd-machine-id-setup
run "Link dbus machine-id" ln -sf /etc/machine-id /var/lib/dbus/machine-id
_done 0 "System identifiers refreshed"

################################################################################
# 21. Hardware Security Module Maintenance
################################################################################
step "21. Maintaining Hardware Security Modules..."
if ! grep -q "tpm" /etc/crypttab; then
run "tpm2_clear" tpm2_clear
else
echo " [] TPM in use by crypttab; skipping clear"
fi
_done 0 "HSM maintenance complete"

################################################################################
# 22. Secure Network Services
################################################################################
step "22. Secure Network Services..."

# --- WireGuard (${VPN_IFACE}): prefer systemd unit; fallback to wg-quick up; verify status ---
run "Start WireGuard ${VPN_IFACE} (if present)" bash -lc '
# Already up?
if ip link show ${VPN_IFACE} >/dev/null 2>&1 || wg show ${VPN_IFACE} >/dev/null 2>&1; then
echo " ✓ ${VPN_IFACE} already up"
exit 0
fi

# Require either systemd unit or wg-quick + config file
WG_CONF=/etc/wireguard/${VPN_IFACE}.conf
HAVE_WGQ=$(command -v wg-quick >/dev/null 2>&1 && echo yes || echo no)
HAVE_UNIT=$(systemctl list-unit-files 2>/dev/null | awk "(\$1==\"wg-quick@${VPN_IFACE}.service\"){print \$1}" | head -n1)

if [ -n "$HAVE_UNIT" ]; then
# Use systemd-managed interface if unit exists
if systemctl start wg-quick@${VPN_IFACE} 2>/dev/null; then
sleep 0.5
if wg show ${VPN_IFACE} >/dev/null 2>&1; then
echo " ✓ wg-quick@${VPN_IFACE} started via systemd"
exit 0
else
echo " ! wg-quick@${VPN_IFACE} start returned ok but ${VPN_IFACE} not visible"
fi
else
echo " ! systemd start wg-quick@${VPN_IFACE} failed; will try wg-quick directly (if available)"
fi
fi

if [ "$HAVE_WGQ" = "yes" ] && [ -f "$WG_CONF" ]; then
if wg-quick up ${VPN_IFACE} >/dev/null 2>&1; then
echo " ✓ ${VPN_IFACE} up (wg-quick)"
exit 0
else
echo " ✗ wg-quick up ${VPN_IFACE} failed"
exit 1
fi
fi

echo " ! WireGuard not started: missing unit and/or wg-quick or $WG_CONF"
exit 0
'

# --- obfs4proxy: only start if a service exists (and not already active) ---
run "Start obfs4 transport (if present)" bash -lc '
# Many setups run obfs4 via Tor; only start a dedicated unit if it exists.
if ! command -v systemctl >/dev/null 2>&1; then
echo " ! systemd not present (skipping obfs4)"
exit 0
fi

# Find a plausible obfs4 service name
UNIT=""
for cand in obfs4proxy.service obfs4.service; do
if systemctl list-unit-files 2>/dev/null | awk "{print \$1}" | grep -qx "$cand"; then
UNIT="$cand"; break
fi
done

if [ -z "$UNIT" ]; then
echo " ! no obfs4 service unit installed (skipping)"
exit 0
fi

if systemctl is-active --quiet "$UNIT"; then
echo " ✓ $UNIT already active"
exit 0
fi

if systemctl start "$UNIT" 2>/dev/null; then
if systemctl is-active --quiet "$UNIT"; then
echo " ✓ $UNIT started"
else
echo " ! $UNIT start issued but not active"
fi
else
echo " ! failed to start $UNIT"
fi
'

_done 0 "Secure network services configured"

################################################################################
# 23. Network Security Policies
################################################################################
step "23. Applying Network Security Policies..."
run "Refreshed iptables" iptables -F
run "Set default policies" bash -c 'iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT'
run "Allow loopback" iptables -A INPUT -i lo -j ACCEPT
run "Allow established" iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
run "Allow LAN ${ALLOWED_LAN_CIDRS}" iptables -A INPUT -s ${ALLOWED_LAN_CIDRS} -j ACCEPT
run "Drop ICMP echo" iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
run "Log blocked" iptables -A INPUT -j LOG --log-prefix "NETWORK_BLOCKED: " --log-level 4
_done 0 "Successfully applied network policies"

################################################################################
# 24. Network Traffic Optimization
################################################################################
step "24. Optimizing Network Traffic..."
command -v tc >/dev/null || run "Install iproute2" env DEBIAN_FRONTEND=noninteractive apt-get -yq install iproute2
# Use replace (not add) to avoid "Exclusivity flag on"
run "Apply qdisc (netem delay)" bash -c 'tc qdisc replace dev '"$NET_IFACE"' root netem delay 100ms 50ms 25%'
_done 0 "Network traffic shaping updated"

################################################################################
# 25. Memory management
################################################################################

# Allocate and release a temporary buffer in volatile space to sanitize remnants.
TMP_ALLOC="/dev/shm/cache.$RANDOM$RANDOM.bin"
export TMP_ALLOC

run "Memory management" bash -lc '
errfile=$(mktemp)
# Fill a temporary buffer in volatile memory; "No space left on device" is expected and OK.
if dd if=/dev/zero of="$TMP_ALLOC" bs=16M status=none 2>"$errfile"; then
rm -f "$errfile"
exit 0
else
if grep -q "No space left on device" "$errfile"; then
rm -f "$errfile"
exit 0
else
cat "$errfile" >&2
rm -f "$errfile"
exit 1
fi
fi
'

run "Release temporary buffer" bash -lc 'rm -f "$TMP_ALLOC" || true'

################################################################################
# 26. Kernel Security Configuration
################################################################################
step "26. Configuring Kernel Security..."
run "Inject GRUB lockdown param" sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lockdown=confidentiality"/' /etc/default/grub
run "Update GRUB" update-grub
_done 0 "Kernel boot parameters updated"

################################################################################
# 27. Hardware/Kernel Controls — Safe eBPF hardening (no blacklist)
################################################################################
step "27. Hardware/Kernel Controls..."

run "Harden eBPF for unprivileged users" bash -lc '
cat >/etc/sysctl.d/99-phantom0-bpf.conf <<EOF
kernel.unprivileged_bpf_disabled = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
sysctl --system >/dev/null 2>&1 || true
echo " ✓ eBPF hardened (unprivileged disabled)"
'
_done 0 "Kernel controls applied"

################################################################################
# 28. Finalize User Environment
################################################################################
echo " 28. Finalizing User Environment..."
run "Finalize user cache refresh" bash -lc '
root="'"$REAL_HOME"'/.cache"
[ -d "$root" ] || { echo " ! no user cache dir; skipping"; exit 0; }

# Temporarily preserve special mounts
for skip in gvfs doc; do
[ -e "$root/$skip" ] && mv "$root/$skip" "$root/$skip.__keep__" 2>/dev/null || true
done

sanitize_tree "$root"

# Restore placeholders
for keep in "$root"/gvfs.__keep__ "$root"/doc.__keep__; do
[ -e "$keep" ] && mv "$keep" "${keep%.__keep__}" 2>/dev/null || true
done

echo " ✓ user cache finalized"
exit 0
'
_done 0 "User environment finalized"

################################################################################
# 29. Real-time System Monitoring
################################################################################
step "29. Initializing System Monitoring..."
INTRUSION_MONITOR="/usr/local/bin/system_monitor.sh"
INTRUSION_NOTIFY="/usr/local/bin/intrusion_notify.sh"
SERVICE_PATH="/etc/systemd/system/system_monitor.service"

# Make paths visible to inner bash -lc calls
export INTRUSION_MONITOR INTRUSION_NOTIFY SERVICE_PATH

# Ensure target dirs exist (no-ops if present)
install -d -m 755 /usr/local/bin || true
install -d -m 755 /etc/systemd/system || true
install -d -m 755 /var/log || true
install -d -m 755 /run || true

# -----------------------------
# 29.1 Install notifier helper
# -----------------------------
run "Install intrusion_notify.sh" bash -lc '
base64 -d > "$INTRUSION_NOTIFY" << "B64"
IyEvdXNyL2Jpbi9lbnYgYmFzaAptc2c9IiQxIgoKaWYgY29tbWFuZCAtdiB3YWxsID4vZGV2L251
bGwgdHtsaW5lCiAgZWNobyAiJHttc2d9IiB8IHdhbGwKICBleGl0IDA KZmkKbG9nZ2VyIC10IHN5
c3RlbV9tb25pdG9yICIkbXNnIiB8fCB0cnVlCmV4aXQgMAo=
B64
chmod 0755 "$INTRUSION_NOTIFY"
[ -s "$INTRUSION_NOTIFY" ] || { echo "Notify script write failed"; exit 1; }
'

# -----------------------------
# 29.2 Install monitor script
# -----------------------------
run "Install system_monitor.sh" bash -lc '
base64 -d > "$INTRUSION_MONITOR" << "B64"
IyEvdXNyL2Jpbi9lbnYgYmFzaApzZXQgLXVvIHBpcGVmYWlsCkxPR19GSUxFPSIvdmFyL2xvZy9z
eXN0ZW1fbW9uaXRvci5sb2ciCkxPQ0tfRklMRT0iL3J1bi9zeXN0ZW1fbW9uaXRvci5sb2NrIgoK
ZXhlYyA5PiIkTE9DS19GSUxFIiB8fCBleGl0IDAKZmxvY2sgLW4gOSB8fCBleGl0IDAKCm1rZGly
IC1wIC92YXIvbG9nID4vZGV2bnVsbCB8fCB0cnVlCnRvdWNoICIkTE9HX0ZJTEUiID4vZGV2bnVs
bCB8fCB0cnVlCmNobW9kIDYwMCAiJExPR19GSUxFIiA+L2RldnVsbCB8fCB0cnVlCmlvbmljZSAt
YzMgLXAgJCQgPi9kZXYvbnVsbCB8fCB0cnVlCnJlbmljZSArMTAgJCQgPi9kZXYvbnVsbCAyPiYx
IHwgdHJ1ZQoKUEFUVEVSTj0ia2V5bG9nZ2VyfHNub29wfHNjcmVlbmNhcHx0Y3BkdW1wfHRzaGFy
a3xubWFwfHRlbG5ldHx5YXNocnVufG1vZGJ1c3xpZWM2MTg1MHxkbnB8cGxjIgpCQVNFX0lHTk9S
RV9SRT0ic3lzdGVtX21vbml0b3JcLnNofGludHJ1c2lvbl9ub3RpZnlcLnNofGpvdXJuYWwoZHxj
dGwpfHN5c3RlbWR8c3NoZHxwZ3JlcHxwa2lsbHxncmVwfGF3a3xzZWQiCgpsb2dfZXZ0KCkgeyBw
cmludGYgIlslKCUlRiAlVCldICVzXG4iIC0xICIkKiIgPj4gIiRMT0dfRklMRSIgfHwgdHJ1ZSAg
fQoKdGVybWluYXRlX3BpZHMoKSB7IGxvY2FsIHBpZHM9KCIkQCIpOyBraWxsIC1URU1NICIke3Bp
ZHNbQF19IiAyPi9kZXZ1bGwgfHwgdHJ1ZTsgc2xlZXAgMTsgZm9yIHBpZCBpbiAiJHtwaWRzW0Bd
fSI7IGRvIGlmIGtpbGwgLTAgIiRwaWQiIDI+L2RldnVsbDsgdGhlbiBraWxsIC1LSUxMICIkcGlk
IiAyPi9kZXZ1bGwgfHwgdHJ1ZTsgZG9uZTsgfQoKd2hpbGUgdHJ1ZTsgZG8gCiAgbWFwZmlsZSAt
dCBoaXRzIDw8KHBncmVwIC1mYSAtLSAiJFBBVFRFUk4iIDI+L2RldnVsbCB8fCB0cnVlKQogICgp
ICYmIGJhZF9saW5lcz0oKQogIGZvciBsaW5lIGluICIkKHhzaXRzW0BdfSI7IGRvCiAgICBbWyAi
JGxpbmUiIH5lICRCQVNFX0lHTk9SRV9SRSBdXSAmJiBjb250aW51ZQogICAgaWYgW1sgIiRsaW5l
IiB+ZSAvYmluLyhiYXNofHNofHpzaCkgXV07IHRoZW4KICAgICAgWyAiJGxpbmUiICE9ICoqIiAt
aSIqIF0gfHwgY29udGludWUKICAgIGZpCiAgICBiYWRfbGluZXMoKSIkbGluZSIpCiAgZG9uZQog
IGlmICgoICR7I2JhZF9saW5lc1tAXX0gPiAwICkpOyB0aGVuCiAgICBtYXBmaWxlIC10IHBpZHMg
PDwoIHByaW50ZiAiJXMiICIiIHwgYXdrICd7cHJpbnQgJDF9JyApCiAgICBsb2dfZXZ0ICJTZWN1
cml0eSBFdmVudCBkZXRlY3RlZDo iCiAgICBwcmludGYgIiVzXG4iICIkYmFkX2xpbmVzQCIgPj4g
IiRMT0dfRklMRSIKICAgIHRlcm1pbmF0ZV9waWRzICIkcGlkc0AiCiAgICAvdXNyL2xvY2FsL2Jp
bi9pbnRydXNpb25fbm90aWZ5LnNoICJTZWN1cml0eSBldmVudCBkZXRlY3RlZC4gU3VzcGljaW91
cyBwcm9jZXNzZXMvZXMgdGVybWluYXRlZC4iID4vZGV2L251bGwgMj4mMSB8fCB0cnVlCiAgZmkK
ICBzbGVlcCA1CmRvbmUKB64=
B64
chmod 0755 "$INTRUSION_MONITOR"
bash -n "$INTRUSION_MONITOR"
[ -s "$INTRUSION_MONITOR" ] || { echo "Monitor script write failed"; exit 1; }
'

# -----------------------------
# 29.3 Install systemd service
# -----------------------------
run "Install system_monitor.service" bash -lc '
cat > "$SERVICE_PATH" << "EOF"
[Unit]
Description=Phantom-0 Real-time System Monitor
After=network.target syslog.target
ConditionPathExists=/usr/local/bin/system_monitor.sh

[Service]
Type=simple
ExecStart=/usr/local/bin/system_monitor.sh
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now system_monitor.service
systemctl status --no-pager --lines=20 system_monitor.service || true
'

_done 0 "System monitor prepared and service active"

################################################################################
# 30. Remote Access Security
################################################################################
step "30. Enhancing Remote Access Security..."
run "Mask systemd-resolved" systemctl mask systemd-resolved.service
if [ -f /etc/systemd/resolved.conf ]; then
run "Disable MulticastDNS" sed -i '/^#\?MulticastDNS=/c\MulticastDNS=no' /etc/systemd/resolved.conf
run "Disable LLMNR" sed -i '/^#\?LLMNR=/c\LLMNR=no' /etc/systemd/resolved.conf
fi
run "Apply IPv4 echo ignore" bash -c 'sed -i "/^net.ipv4.icmp_echo_ignore_all/d" /etc/sysctl.conf; echo "net.ipv4.icmp_echo_ignore_all = 1" | tee -a /etc/sysctl.conf >/dev/null; sysctl -w net.ipv4.icmp_echo_ignore_all=1'
if [ -f /proc/sys/net/ipv6/icmp_echo_ignore_all ]; then
run "Apply IPv6 echo ignore" bash -c 'sed -i "/^net.ipv6.icmp_echo_ignore_all/d" /etc/sysctl.conf; echo "net.ipv6.icmp_echo_ignore_all = 1" | tee -a /etc/sysctl.conf >/dev/null; sysctl -w net.ipv6.icmp_echo_ignore_all=1'
fi
if systemctl is-enabled ssh >/dev/null 2>&1; then
run "Disable SSH service" systemctl disable --now ssh
fi
# Re-assert minimal INPUT rules (idempotent)
run "Re-apply minimal INPUT rules" bash -c 'iptables -F; iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT; iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
_done 0 "Remote access hardening complete"

################################################################################
# 31. Tor Browser Maintenance
################################################################################
step "31. Maintaining Privacy Browsers..."
TOR_HOME="$REAL_HOME/.local/share/torbrowser"

# Prelaunch torbrowser (short timeout, no detach/kill loop)
if command -v torbrowser-launcher >/dev/null 2>&1; then
if [ -f "$REAL_HOME/.Xauthority" ]; then
run "Prelaunch torbrowser (4s cap)" bash -lc '
timeout 4s runuser -u "$REAL_USER" -- env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$REAL_HOME/.Xauthority" \
torbrowser-launcher --settings >/dev/null 2>&1 || true
'
else
warn "Skipping Tor prelaunch" "no Xauthority/DISPLAY; optional step"
fi
else
warn "Tor Browser Launcher not found" "Skipping optional prelaunch"
fi

# Tor profile maintenance
TOR_PROFILE=$(find "$TOR_HOME" -type d -name "profile.default" 2>/dev/null | head -n 1)
if [ -n "$TOR_PROFILE" ]; then
for DIR in "$TOR_PROFILE/minidumps" "$TOR_PROFILE/sessionstore-backups" "$TOR_PROFILE/storage"; do
[ -d "$DIR" ] && run "Refresh Tor dir $(basename "$DIR")" \
bash -c 'find "'"$DIR"'" -type f -exec shred -n 3 -u -z {} \;'
done
for FILE in "$TOR_PROFILE/healthreport.sqlite" "$TOR_PROFILE/Telemetry.json" "$TOR_PROFILE/save-session.json" \
"$TOR_PROFILE/.parentlock" "$TOR_PROFILE/formhistory.sqlite" "$TOR_PROFILE/webappsstore.sqlite" \
"$TOR_PROFILE/content-prefs.sqlite" "$TOR_PROFILE/siteSecurityServiceState.txt" "$TOR_PROFILE/permissions.sqlite" \
"$TOR_PROFILE/containers.json" "$TOR_PROFILE/search.json.mozlz4" "$TOR_PROFILE/xulstore.json" \
"$TOR_PROFILE/addonStartup.json.lz4" "$TOR_PROFILE/times.json"; do
[ -f "$FILE" ] && run "Shred $(basename "$FILE")" shred -n 3 -u -z "$FILE"
done
run "Refreshed Tor cache/bak" \
bash -c 'find "'"$TOR_PROFILE"'" -type f \( -name "startupCache*" -o -name "*.bak" \) -exec shred -n 3 -u -z {} \;'
fi

# Tor network state
TOR_STATE_DIRS=(
"$TOR_HOME/tbb/x86_64/tor-browser/Data/Tor"
"$TOR_HOME/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Tor"
"$TOR_HOME/tbb/x86_64/tor-browser/Browser/TorBrowser/Tor"
)
for TOR_STATE in "${TOR_STATE_DIRS[@]}"; do
if [ -d "$TOR_STATE" ]; then
run "Refresh Tor state in $(basename "$TOR_STATE")" \
bash -c 'find "'"$TOR_STATE"'" -type f \( -name state -o -name "cached-*" -o -name "*.log" -o -name "geoip*" -o -name lock -o -name "*.auth_private" \) -exec shred -n 3 -u -z {} \;'
for DIR in "$TOR_STATE/onion-services" "$TOR_STATE/hidden_services"; do
[ -d "$DIR" ] && run "Refresh hidden services $(basename "$DIR")" \
bash -c 'find "'"$DIR"'" -type f -exec shred -n 3 -u -z {} \;'
done
fi
done

run "Clear firefox cleanup lock" rm -f /tmp/firefox_cleanup.lock
_done 0 "Tor/Firefox privacy maintenance complete"

################################################################################
# 32. Performing Log Maintenance
################################################################################
echo " 32. Performing Log Maintenance..."

# Defer under systemd unless explicitly overridden, to preserve this unit's logs.
if [ -n "${INVOCATION_ID:-}" ] && [ "${DEFER_JOURNAL_ROTATE:-1}" -eq 1 ]; then
echo " - Detected systemd unit context (INVOCATION_ID present)."
echo " - Deferring journald maintenance to preserve live unit logs."
echo " - To force run under systemd, set: DEFER_JOURNAL_ROTATE=0"
_done 0 "Log maintenance pass complete (deferred under systemd)"
else
overall_ok=1

run "Rotate journals" journalctl --rotate
r1=$?
if [ $r1 -eq 0 ]; then
echo " ✓ Rotate journals"
else
echo " ✗ Rotate journals (rc=$r1)"
overall_ok=0
fi

run "Vacuum journals to 1s" journalctl --vacuum-time=1s
r2=$?
if [ $r2 -eq 0 ]; then
echo " ✓ Vacuum journals to 1s"
else
echo " ✗ Vacuum journals to 1s (rc=$r2)"
overall_ok=0
fi

run "Refreshed old journal files" bash -lc 'find /var/log/journal -type f -name "*.journal~" -delete 2>/dev/null || true'
r3=$?
if [ $r3 -eq 0 ]; then
echo " ✓ Refreshed old journal files (*.journal~)"
else
echo " ✗ Failed to refresh old journal files (rc=$r3)"
overall_ok=0
fi

if [ $overall_ok -eq 1 ]; then
_done 0 "Log maintenance pass complete"
else
_done 1 "Log maintenance completed with errors"
fi
fi

################################################################################
# 33. Filesystem Hygiene and Maintenance
################################################################################
step "33. Performing Filesystem Hygiene and Maintenance..."
# Apply timestamp obfuscation (optional, disabled by default)
if [[ "${ENABLE_TOUCH_SCOPED:-0}" == "1" ]]; then
run "Perform timestamp alignment to sensitive files (HOME, <=50MB, 60s cap)" bash -c 'timeout 60s nice -n 19 ionice -c3 find "'"$REAL_HOME"'" -xdev -type f -size -50M -exec touch -d "2020-01-01" {} \;'
else
echo " [] Timestamp alignment disabled (ENABLE_TOUCH_SCOPED=1 to enable)"
fi

ROOT_DEV="$(findmnt -no SOURCE /)"
ROOT_FS="$(findmnt -no FSTYPE /)"
if [[ "$ROOT_FS" == "ext4" && "${ENABLE_JOURNAL_REFRESH:-0}" == "1" ]]; then
echo " ⚠ Skipping journal refresh for mounted $ROOT_DEV (for offline use only)"
echo " · For offline use: run 'debugfs -w \"$ROOT_DEV\" -R 'journal_refresh' from live media"
fi

if [[ "${ENABLE_EMULATED_HWCLK:-0}" == "1" ]]; then
run "Set system hardware clock for privacy hygiene" timeout 2s hwclock --set --date "2023-01-01 00:00:00"
else
echo " [] Disabled software-emulated hardware clock for accurate timekeeping (ENABLE_EMULATED_HWCLK=1 to enable)"
fi
_done 0 "Filesystem hygiene and maintenance complete"

################################################################################
# 34. Network Privacy Enhancements
################################################################################
step "34. Enhancing Network Privacy..."
run "Ignore IPv4 echo" sysctl -w net.ipv4.icmp_echo_ignore_all=1
if command -v resolvectl >/dev/null 2>&1; then
run "Refresh systemd-resolved caches" resolvectl flush-caches
elif command -v systemd-resolve >/dev/null 2>&1; then
run "Refresh resolver caches" systemd-resolve --flush-caches
fi
run "Refresh resolve runtime" bash -c 'rm -f /run/systemd/resolve/*'
_done 0 "Network privacy updated"

################################################################################
# 35. Storage System Maintenance
################################################################################
step "35. Maintaining Storage Systems..."
run "Optimized mounted filesystems" fstrim -av

# NVMe / mapper-safe discard path
ROOT_SRC="$(findmnt -no SOURCE /)"
PKNAME="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null || true)"
if [ -n "$PKNAME" ] && [ -e "/sys/block/$PKNAME/queue/discard_granularity" ]; then
run "Set discard granularity" bash -c 'echo 1 > "/sys/block/'"$PKNAME"'/queue/discard_granularity"'
else
echo " [] No /sys/block/*/discard_granularity for $ROOT_SRC; skipping"
fi
_done 0 "Storage maintenance complete"

################################################################################
# 36. Final Application Restoration
################################################################################
step "36. Restoring Application States..."
if [ -d "$REAL_HOME/.privacy_whitelist" ]; then
for folder in "$REAL_HOME/.privacy_whitelist/"*; do
[ -e "$folder" ] || continue
TARGET="$REAL_HOME/.${folder##*/}"
run "Restore $(basename "$folder")" cp -a "$folder" "$TARGET"
done
else
echo " [] No whitelist staging to restore"
fi
_done 0 "Application state restoration done"

################################################################################
# 37. Service Finalization
################################################################################
step "37. Finalizing Service Operations..."
run "Ensure firefox down (soft)" bash -c 'pkill -u "$REAL_USER" -f "firefox" 2>/dev/null || true'
run "Ensure Tor down" pkill -u "$REAL_USER" -f tor
echo " [] Privacy maintenance completed at $(date)"
_done 0 "All operations finalized"

# --- Encrypt run log (OpenSSL AES-256-CBC + PBKDF2) ---
# Assumes: $RUNLOG points to the plaintext log path for this run
# Stores encrypted log alongside it as "$RUNLOG.enc"
if [ -n "${RUNLOG:-}" ] && [ -f "$RUNLOG" ]; then
KEYFILE="/root/.phantom0/log.key"
if [ -r "$KEYFILE" ]; then
ENCFILE="${RUNLOG}.enc" # rename for clarity
if openssl enc -aes-256-cbc -pbkdf2 -salt \
-in "$RUNLOG" -out "$ENCFILE"; then
printf "[log] encrypted -> %s\n" "$ENCFILE" | tee -a "$RUNLOG"
sync
else
printf "[log] WARNING: encryption failed; leaving plaintext: %s\n" "$RUNLOG" | tee -a "$RUNLOG"
fi
else
echo "[log] WARNING: key file missing/unreadable: $KEYFILE (plaintext kept)"
fi
fi

exit 0
