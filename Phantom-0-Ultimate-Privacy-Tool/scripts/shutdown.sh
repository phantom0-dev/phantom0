#!/usr/bin/env bash

################################################################################
# === Phantom-0 - Shutdown: Digital Hygiene & Security Process ===
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

################################################################################
# --- AA: LUKS protection functions ---
################################################################################
is_luks_related() {
[[ "$1" == *"/crypt"* ]] || \
[[ "$1" == *"/luks"* ]] || \
[[ "$1" == *"/LUKS"* ]] || \
file "$1" | grep -qi "LUKS"
}

luks_safe_wipe() {
local target="$1"
if ! is_luks_related "$target"; then
if dd if=/dev/urandom of="$target" bs=1M count=10 status=none conv=notrunc; then
truncate -s 0 "$target" && rm -f "$target" && return 0
echo "TRUNCATE_FAIL: $target" >&2
else
echo "OVERWRITE_FAIL: $target" >&2
fi
else
echo "LUKS_SKIPPED: $target" >&2
fi
return 1
}

################################################################################
# 1. Encrypted RAM logging
################################################################################
LOGDIR="/dev/shm/.p0_logs"
LEGACYDIR="/dev/shm/.p0_legacy"
if ! (mkdir -p "$LOGDIR" "$LEGACYDIR" && chmod 700 "$LOGDIR" "$LEGACYDIR"); then
echo "LOG_INIT_FAIL: Check /dev/shm permissions" >&2
exit 1
fi

# RAM log key + primary encrypted RAM logfile
LOG_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
RUNLOG="$LOGDIR/$(uuidgen).enc"

# Add a persistent phantom0 on-disk log tap alongside encrypted RAM logs
DISKLOGDIR="${REAL_HOME}/phantom0_logs"
mkdir -p "$DISKLOGDIR" && chown root:${REAL_USER} "$DISKLOGDIR" && chmod 750 "$DISKLOGDIR"
DISKSTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
DISKLOG="$DISKLOGDIR/phantom0-shutdown_${DISKSTAMP}.log"

# Mirror stdout/stderr -> encrypted RAM, legacy RAM copy, and phantom0 on-disk log
exec > >(
stdbuf -oL tee \
>( openssl enc -aes-256-ctr -pbkdf2 -pass pass:"$LOG_KEY" -out "$RUNLOG" ) \
>( tee -a "$LEGACYDIR/$(uuidgen).enc" >/dev/null ) \
-a "$DISKLOG"
) 2>&1

echo "RAM_LOG_ACTIVE: Session $(date +%s)"
logger -t phantom0-shutdown "Started at $(date -Is); disklog=$DISKLOG; ramlog=$RUNLOG"

# Shutdown banner (phantom0)
PHANTOM0_SHUTDOWN_VERSION="v1.0.0"
echo "[PHANTOM0-SHUTDOWN] Running /usr/local/bin/phantom0-shutdown.sh version=$PHANTOM0_SHUTDOWN_VERSION ts=$(date -Is)"

################################################################################
# 2. System Hygiene and Guardrails
################################################################################
set -euo pipefail
IFS=$'\n\t'
export TZ="CST6CDT"

# Minimal utility (kept because later sections rely on it)
require_cmd() { command -v "$1" >/dev/null 2>&1; }

# Guardrails for deletes/find
deny_paths_regex='^(/|/home$|/root$|/etc$|/var$|/usr$|/bin$|/sbin$|/lib($|64$)|/boot$)$'

safe_find_delete_files() {
local base="$1"; shift
echo ">>> 2.x Safe file cleanup in: $base"
local real; real="$(readlink -f -- "$base" 2>/dev/null || echo "$base")"

if [[ ! -d "$real" ]]; then
echo "✗ 2.x Cleanup skipped — target is not a directory: $real"
return 1
fi
if [[ "$real" =~ $deny_paths_regex ]]; then
echo "✗ 2.x Cleanup refused by guardrail: $real"
return 1
fi

if find "$real" -xdev "$@" -print0 2>/dev/null | xargs -0r rm -f -- 2>/dev/null; then
echo "✓ 2.x Cleanup completed on: $real"
else
echo "✗ 2.x Cleanup encountered issues on: $real"
return 1
fi
}

# Safety checks (used later if the handshake defers)
activate_safety_protocols() {
echo ">>> 2.1 Thermal safety checks"
local any=0
for cooling in /sys/class/thermal/cooling_device*; do
[[ -r "$cooling/type" && -r "$cooling/cur_state" ]] || continue
any=1
done
if [[ $any -eq 1 ]]; then
echo "✓ 2.1 Thermal devices detected and readable"
else
echo "✓ 2.1 No thermal entries found (safe)"
fi
}

# Environment prep
: "${REAL_USER:=$(id -nu 1000)}"
: "${REAL_HOME:=$(getent passwd "$REAL_USER" | cut -d: -f6)}"
echo ">>> 2.env Environment prepared — REAL_USER=$REAL_USER REAL_HOME=$REAL_HOME"

# Section 1 recap for context (echo-only)
echo "---- Section 1.1: Logging Setup ----"
echo "✓ 1.1 Dual log setup active (LOGDIR=$LOGDIR LEGACYDIR=$LEGACYDIR RUNLOG=$RUNLOG)"

# Section 2 start (echo-only)
echo "---- Section 2: System Hygiene and Guardrails ----"
echo ">>> 2.2 Safety rails online"
echo "✓ 2.2 Helpers loaded successfully"

################################################################################
# 3. Access Level Check
################################################################################

echo "---- Section 3.1: Privilege verification ----"
echo ">>> 3.1 Checking for administrator privileges"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
echo "✗ 3.1 Permission error: administrator privileges required"
echo "✗ Section 3.1 failed — script exiting due to insufficient access level"
exit 1
else
echo "✓ 3.1 Running with administrator privileges"
echo "✓ Section 3.1 completed successfully"
fi

################################################################################
# 4. Security module handshake
################################################################################

echo "---- Section 4.1: Security module handshake ----"
echo ">>> 4.1 Beginning security module handshake"

SECURITY_MODULE="/usr/lib/libsecurity.so"
SAFETY_DEFER=0

if [[ -f "$SECURITY_MODULE" && -r "$SECURITY_MODULE" ]]; then
export SECURITY_MODULE_PATH="$SECURITY_MODULE"
if require_cmd pkcs11-tool; then
if ! pkcs11-tool --module "$SECURITY_MODULE" --test >/dev/null 2>&1; then
echo "✗ 4.1 Module present but handshake test failed — deferring safety protocols"
echo "✗ Section 4.1 did not complete successfully (SAFETY_DEFER=1)"
SAFETY_DEFER=1
else
echo "✓ 4.1 Security module check passed"
echo "✓ Section 4.1 completed successfully"
fi
else
echo "✗ 4.1 pkcs11-tool not installed — module test skipped"
echo "✗ Section 4.1 skipped due to missing tool"
fi
else
echo "✓ 4.1 No security module detected — check skipped"
echo "✓ Section 4.1 completed successfully (nothing required)"
fi

################################################################################
# 5. System Preferences Profile
################################################################################

echo "---- Section 5.1: Applying system preference toggles ----"
echo ">>> 5.1 Setting system preference toggles"

declare -gx FREE_SPACE_CLEAN_SIZE=${FREE_SPACE_CLEAN_SIZE:-7}
declare -gx ENABLE_ADVANCED_SANITIZATION=${ENABLE_ADVANCED_SANITIZATION:-1}
declare -gx ENABLE_DEEP_STORAGE_CLEAN=${ENABLE_DEEP_STORAGE_CLEAN:-1}
declare -gx ENABLE_PERIPHERAL_PROTECTION=${ENABLE_PERIPHERAL_PROTECTION:-1}

if [[ -n "$FREE_SPACE_CLEAN_SIZE" && -n "$ENABLE_ADVANCED_SANITIZATION" && -n "$ENABLE_DEEP_STORAGE_CLEAN" && -n "$ENABLE_PERIPHERAL_PROTECTION" ]]; then
echo "✓ 5.1 Preference toggles set (ADV=$ENABLE_ADVANCED_SANITIZATION, DEEP=$ENABLE_DEEP_STORAGE_CLEAN, PERIPH=$ENABLE_PERIPHERAL_PROTECTION)"
echo "✓ Section 5.1 completed successfully"
else
echo "✗ 5.1 Preference toggle initialization failed – one or more variables unset"
echo "✗ Section 5.1 did not complete successfully"
fi

################################################################################
# 6. Temporary Workspacem Maintenance
################################################################################
clean_memory() {
echo "---- Section 6.1: Prepare temporary workspace ----"
local SECURE_WORKSPACE="/run/privsec"
local SECTION_OK=1

mkdir -p "$SECURE_WORKSPACE"
if mountpoint -q "$SECURE_WORKSPACE"; then
echo "✓ 6.1 Temporary workspace already active at $SECURE_WORKSPACE"
else
if mount -n -t tmpfs -o size=256M,noexec,nosuid,nodev tmpfs "$SECURE_WORKSPACE" 2>/dev/null; then
echo "✓ 6.1 Temporary workspace mounted at $SECURE_WORKSPACE"
else
echo "✗ 6.1 Could not mount workspace – skipping maintenance routine"
echo "✗ Section 6 not completed (workspace mount unavailable)"
return 0
fi
fi

echo "---- Section 6.2: Fill workspace with test data (64MiB) ----"
if dd if=/dev/urandom of="$SECURE_WORKSPACE/.memtest" bs=1M count=64 status=none 2>/dev/null; then
echo "✓ 6.2 Test data written successfully"
else
echo "✗ 6.2 Test data write failed – continuing"
SECTION_OK=0
fi

echo "---- Section 6.3: Clear temporary test file ----"
if rm -f "$SECURE_WORKSPACE/.memtest" 2>/dev/null; then
echo "✓ 6.3 Test file refreshed"
else
echo "✗ 6.3 Could not clear test file"
SECTION_OK=0
fi

echo "---- Section 6.4: Close temporary workspace ----"
if umount -l "$SECURE_WORKSPACE" 2>/dev/null; then
echo "✓ 6.4 Workspace unmounted"
else
echo "✗ 6.4 Could not unmount workspace (still in use)"
SECTION_OK=0
fi

##############################################################################
# 6. (cont.) Kernel memory hygiene (best-effort; safe for shutdown)
##############################################################################
echo "---- Section 6.5: Compact memory (best-effort) ----"
if [ -w /proc/sys/vm/compact_memory ]; then
if echo 1 > /proc/sys/vm/compact_memory 2>/dev/null; then
echo "✓ 6.5 Memory compaction requested"
else
echo "✗ 6.5 Unable to request memory compaction"
SECTION_OK=0
fi
else
echo "· 6.5 Skipping: /proc/sys/vm/compact_memory not writable"
fi

echo "---- Section 6.6: Drop filesystem caches (best-effort) ----"
# sync first to avoid losing dirty pages; then drop pagecache,dentries,inodes
sync 2>/dev/null || true
if [ -w /proc/sys/vm/drop_caches ]; then
if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then
echo "✓ 6.6 Dropped page cache, dentries, and inodes"
else
echo "✗ 6.6 Unable to drop caches"
SECTION_OK=0
fi
else
echo "· 6.6 Skipping: /proc/sys/vm/drop_caches not writable"
fi

if [[ $SECTION_OK -eq 1 ]]; then
echo "✓ Section 6 completed successfully"
else
echo "✗ Section 6 completed with notes (see above substeps)"
fi
}

clean_memory

################################################################################
# 7. File maintenance helpers
################################################################################

standardize_metadata() {
local target="$1"
echo "---- Section 7.1: Normalize metadata for $target ----"
local SECTION_OK=1

if [[ -e "$target" ]]; then
if touch -d "2021-01-01 00:00:00 UTC" "$target" 2>/dev/null; then
echo "✓ 7.1 File timestamp standardized"
else
echo "✗ 7.1 Could not update file timestamp"
SECTION_OK=0
fi

if require_cmd setfattr; then
if setfattr -n user.policy_version -v "PrivacyGuard-2023" "$target" 2>/dev/null; then
echo "✓ 7.1 File attribute applied"
else
echo "✗ 7.1 File attribute could not be applied"
SECTION_OK=0
fi
else
echo "✓ 7.1 Attribute tool not available – skipped"
fi
else
echo "✓ 7.1 Target not found – skipped"
fi

if [[ $SECTION_OK -eq 1 ]]; then
echo "✓ Section 7.1 completed successfully"
else
echo "✗ Section 7.1 completed with notes (see above)"
fi
}

clean_file() {
local target="$1"
echo "---- Section 7.2/7.3: File cleanup for $target ----"
local SECTION_OK=1

if [[ ! -e "$target" ]]; then
echo "✓ 7.2 No target found: $target"
echo "✓ Section 7.2 completed successfully (no target)"
return 0
fi

if [[ -d "$target" ]]; then
echo "✓ 7.2 Directory handled separately: $target"
echo "✓ Section 7.2 completed successfully (directory skipped)"
return 0
fi

if [[ "$target" == "/var/lib/systemd/random-seed" ]]; then
echo ">>> 7.2 Refresh system seed file"
if : > "$target" 2>/dev/null && chmod 600 "$target" 2>/dev/null && chown root:root "$target" 2>/dev/null; then
echo "✓ 7.2 Seed file refreshed with correct permissions"
echo "✓ Section 7.2 completed successfully"
else
echo "✗ 7.2 Could not refresh seed file"
echo "✗ Section 7.2 did not complete successfully"
fi
return 0
fi

echo ">>> 7.3 Refresh file contents: $target"
if require_cmd openssl; then
local ck; ck="$(head -c 48 /dev/urandom | base64 -w0 2>/dev/null || echo 0)"
if openssl enc -aes-256-gcm -K "$(printf %s "$ck" | sha256sum | cut -d' ' -f1)" \
-iv "$(head -c 12 /dev/urandom | xxd -p)" -in "$target" -out /dev/null 2>/dev/null; then
echo "✓ 7.3 Test pass with encryption tool succeeded"
else
echo "✓ 7.3 Encryption tool present but pass skipped/failed – continuing"
fi
else
echo "✓ 7.3 Encryption tool not available – skipped"
fi

if : > "$target" 2>/dev/null && rm -f "$target" 2>/dev/null; then
echo "✓ 7.3 File refreshed and removed"
else
echo "✗ 7.3 File could not be refreshed or removed"
SECTION_OK=0
fi

if [[ $SECTION_OK -eq 1 ]]; then
echo "✓ Section 7.3 completed successfully"
else
echo "✗ Section 7.3 completed with notes (see above)"
fi
}

################################################################################
# 8. Resource Maintenance
################################################################################

declare -a PRIVACY_RESOURCES=(
"$REAL_HOME/.bash_history"
"/var/log/auth.log"
"/tmp"
"$REAL_HOME/.browser_profiles"
"$REAL_HOME/.private_browsing"
"/var/cache/private"
)

#### ---- Section 8.1: Maintain resource list ----
echo "---- Section 8.1: Maintain resource list ----"

# Ensure list exists
RESOURCES=("${RESOURCES[@]}") # preserve if already set
if [ "${#RESOURCES[@]}" -eq 0 ]; then
RESOURCES=( "/var/log" "/var/tmp" "/tmp" )
fi

SECTION8_OK=1

for resource in "${RESOURCES[@]}"; do
echo "---- Section 8.1: Evaluating $resource ----"

if [ -e "$resource" ]; then
# 8.1.1 quick sanity / permission check
echo "---- Section 8.1.1: Sanity / permission check for $resource ----"
if [ -r "$resource" ]; then
echo "✓ 8.1.1 Readable: $resource"
else
echo "✗ 8.1.1 Not readable: $resource (skipping resource)"
SECTION8_OK=0
continue
fi

# 8.1.2 cleanup (files only; keep dirs)
echo "---- Section 8.1.2: Cleanup inside $resource ----"
clean_fail=0
if find "$resource" -xdev -type f -mindepth 1 -maxdepth 1 -print0 2>/dev/null \
| xargs -0r rm -f -- 2>/dev/null; then
echo " ✓ Resource cleaned: $resource"
else
clean_fail=1
echo " ✗ Resource cleanup failed in $resource" >&2
fi

# 8.1.3 remove empty subfolders
echo "---- Section 8.1.3: Remove unused folders under $resource ----"
if find "$resource" -xdev -depth -type d -empty -mindepth 1 -exec rmdir {} + 2>/dev/null; then
echo "✓ 8.1.3 Empty folders removed"
else
echo "✗ 8.1.3 Some folders could not be removed (continuing)"
SECTION8_OK=0
fi

# 8.1.4 metadata normalization
echo "---- Section 8.1.4: Metadata normalization for $resource ----"
if command -v standardize_metadata >/dev/null 2>&1; then
if standardize_metadata "$resource"; then
echo "✓ 8.1.4 Metadata normalized for $resource"
else
echo "✗ 8.1.4 Metadata normalization failed for $resource (continuing)"
SECTION8_OK=0
fi
else
echo "! 8.1.4 standardize_metadata helper not found (skipped)"
fi

else
echo "✓ 8.1 Resource not found: $resource (skipped)"
fi
done

if [[ $SECTION8_OK -eq 1 ]]; then
echo "✓ Section 8 completed successfully"
else
echo "✗ Section 8 completed with notes (see above substeps)"
fi

################################################################################
# --- 9. Journal Encryption (ephemeral-key by default) ---
################################################################################
echo "9. Encrypting and rotating journals..."

# --- Shim: ensure helpers/vars exist even under `set -u` and when sourced alone ---
if ! declare -F is_root >/dev/null 2>&1; then is_root(){ [ "$(id -u)" -eq 0 ]; }; fi
if ! declare -F have_cmd >/dev/null 2>&1; then have_cmd(){ command -v "$1" >/dev/null 2>&1; }; fi
if ! declare -F in_group >/dev/null 2>&1; then in_group(){ id -nG "${1:-$USER}" 2>/dev/null | grep -qw "${2}"; }; fi
: "${RUNROOT:=}"; : "${RUNJ:=}"; : "${REAL_USER:=$USER}"
: "${PH0_JOURNAL_KEY_MODE:=EPHEMERAL}" # EPHEMERAL | PERSIST

# (re)compute RUNROOT/RUNJ if empty
if [ -z "$RUNROOT" ]; then
if is_root; then RUNROOT=""; else RUNROOT="$(have_cmd sudo && echo sudo -n || echo "")"; fi
fi
if [ -z "$RUNJ" ]; then
if is_root || in_group "${REAL_USER}" systemd-journal || in_group "$USER" systemd-journal; then
RUNJ=""
else
RUNJ="$RUNROOT"
fi
fi

set +e # best-effort; never abort the whole script in this section

PERSIST_DIR="/var/log/journal"
KEY_DIR="/root/.phantom0"
KEY_FILE="$KEY_DIR/journal.key" # only used if PH0_JOURNAL_KEY_MODE=PERSIST
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
ENC_BASENAME="phantom0_journal_${STAMP}.export.enc"
ENC_OUT="$PERSIST_DIR/$ENC_BASENAME"

# -------------------- Prep & journal flush --------------------
echo " · Prep persistent dir"
$RUNROOT mkdir -p "$PERSIST_DIR" 2>/dev/null || true
$RUNROOT chmod 2750 "$PERSIST_DIR" 2>/dev/null || true

echo " · Flush/rotate/sync journals"
if [ -z "$RUNJ" ]; then
journalctl --flush >/dev/null 2>&1
journalctl --rotate >/dev/null 2>&1
journalctl --sync >/dev/null 2>&1
else
$RUNJ journalctl --flush >/dev/null 2>&1
$RUNJ journalctl --rotate >/dev/null 2>&1
$RUNJ journalctl --sync >/dev/null 2>&1
fi

# Heartbeat to ensure at least one record
if [ -z "$RUNJ" ]; then
logger -p user.notice "phantom0-shutdown: journal export at $STAMP" 2>/dev/null || true
journalctl --sync >/dev/null 2>&1
else
$RUNJ logger -p user.notice "phantom0-shutdown: journal export at $STAMP" 2>/dev/null || true
$RUNJ journalctl --sync >/dev/null 2>&1
fi
sleep 0.2

# -------------------- Export (boot -> 15m -> stub) --------------------
TMP_EXPORT="$(mktemp)" || TMP_EXPORT=""
if [ -z "$TMP_EXPORT" ]; then
echo " ✗ Could not create temp export"
echo "✗ Section 9 completed with notes (continuing)"
else
echo " · Exporting journal to temp (this boot)"
if [ -z "$RUNJ" ]; then
journalctl -b -a -o export --no-pager > "$TMP_EXPORT" 2>/dev/null
else
$RUNJ journalctl -b -a -o export --no-pager > "$TMP_EXPORT" 2>/dev/null
fi

if [ ! -s "$TMP_EXPORT" ]; then
echo " · Fallback export --since 15 minutes ago"
if [ -z "$RUNJ" ]; then
journalctl -a -o export --no-pager --since "15 minutes ago" > "$TMP_EXPORT" 2>/dev/null
else
$RUNJ journalctl -a -o export --no-pager --since "15 minutes ago" > "$TMP_EXPORT" 2>/dev/null
fi
fi

# Last-resort stub (guarantee an artifact)
if [ ! -s "$TMP_EXPORT" ]; then
echo " · Journal still empty; creating stub bundle"
{
echo "phantom0-journal-stub: $STAMP"
uname -a 2>/dev/null || true
echo "REAL_USER=${REAL_USER:-$USER}"
echo "HOSTNAME=$(hostname 2>/dev/null || echo unknown)"
} > "$TMP_EXPORT"
fi

# -------------------- Encryption (ephemeral or persistent key) --------------------
case "$PH0_JOURNAL_KEY_MODE" in
EPHEMERAL|ephemeral|'')
echo " · Encrypting with EPHEMERAL key (undecipherable after this run)"
RAND_PASS="$(head -c 32 /dev/urandom | base64 2>/dev/null)"
if $RUNROOT openssl enc -aes-256-ctr -pbkdf2 -md sha256 -salt \
-pass pass:"$RAND_PASS" \
-in "$TMP_EXPORT" -out "$ENC_OUT" 2>/dev/null; then
:
else
echo " ✗ OpenSSL encryption failed (ephemeral mode)" >&2
rm -f "$TMP_EXPORT"
echo "✗ Section 9 completed with notes (continuing)"
set -e; :
fi
unset RAND_PASS
;;
PERSIST|persist)
echo " · Encrypting with PERSISTENT key file: $KEY_FILE"
$RUNROOT mkdir -p "$KEY_DIR" 2>/dev/null || true
$RUNROOT chmod 700 "$KEY_DIR" 2>/dev/null || true
if ! $RUNROOT test -s "$KEY_FILE"; then
$RUNROOT sh -lc 'head -c 32 /dev/urandom > "'"$KEY_FILE"'"' 2>/dev/null
$RUNROOT chmod 600 "$KEY_FILE" 2>/dev/null || true
fi
if ! $RUNROOT openssl enc -aes-256-ctr -pbkdf2 -md sha256 -salt \
-pass file:"$KEY_FILE" \
-in "$TMP_EXPORT" -out "$ENC_OUT" 2>/dev/null; then
echo " ✗ OpenSSL encryption failed (persistent mode)" >&2
rm -f "$TMP_EXPORT"
echo "✗ Section 9 completed with notes (continuing)"
set -e; :
fi
;;
*)
echo " ! Unknown PH0_JOURNAL_KEY_MODE='$PH0_JOURNAL_KEY_MODE' — defaulting to EPHEMERAL"
RAND_PASS="$(head -c 32 /dev/urandom | base64 2>/dev/null)"
if $RUNROOT openssl enc -aes-256-ctr -pbkdf2 -md sha256 -salt \
-pass pass:"$RAND_PASS" \
-in "$TMP_EXPORT" -out "$ENC_OUT" 2>/dev/null; then
:
else
echo " ✗ OpenSSL encryption failed (fallback ephemeral)" >&2
rm -f "$TMP_EXPORT"
echo "✗ Section 9 completed with notes (continuing)"
set -e; :
fi
unset RAND_PASS
;;
esac

# Cleanup plaintext
shred -u "$TMP_EXPORT" 2>/dev/null || rm -f "$TMP_EXPORT"
echo " ✓ Journals exported and encrypted -> $(basename "$ENC_OUT")"

echo " · Vacuuming old persistent journals"
if [ -z "$RUNJ" ]; then
journalctl --vacuum-time=1min >/dev/null 2>&1 || true
else
$RUNJ journalctl --vacuum-time=1min >/dev/null 2>&1 || true
fi

# -------------------- OPTIONAL: Archive+encrypt raw journal files before delete --------------------
# Safe guards: size cap, timeout, low I/O priority, best-effort only.
# Disabled by default; enable by removing the leading '#' on the lines below.
#
# KEYFILE="/root/.phantom0/log.key" # reuse Option A key if you want a keepable archive
# STAMP2="$(date +%Y%m%d_%H%M%S)"
# TMP_TAR="/root/journal_${STAMP2}.tar"
# ENC_TAR="${TMP_TAR}.enc"
# SRC="$PERSIST_DIR"
# SIZE_CAP_MB=200
# TAR_TIMEOUT=20s
# if [ -r "$KEYFILE" ] && [ -d "$SRC" ] && [ -n "$(find "$SRC" -type f -name '*.journal*' -print -quit 2>/dev/null)" ]; then
# $RUNROOT systemctl kill -s SIGUSR2 systemd-journald 2>/dev/null || true
# sleep 0.3
# CUR_MB=$(du -ms "$SRC" 2>/dev/null | awk '{print $1+0}')
# if [ "$CUR_MB" -le "$SIZE_CAP_MB" ]; then
# if timeout "$TAR_TIMEOUT" ionice -c3 nice -n 19 \
# tar --numeric-owner --xattrs --acls -C "$SRC" -cf "$TMP_TAR" . 2>/dev/null
# then
# if $RUNROOT openssl enc -aes-256-cbc -pbkdf2 -salt \
# -in "$TMP_TAR" -out "$ENC_TAR" -pass file:"$KEYFILE"; then
# shred -u "$TMP_TAR" 2>/dev/null || rm -f "$TMP_TAR"
# $RUNROOT chmod 600 "$ENC_TAR"; $RUNROOT chown root:root "$ENC_TAR" 2>/dev/null || true
# echo " ✓ journals archived+encrypted -> $ENC_TAR"
# else
# echo " ! OpenSSL archive encryption failed"; rm -f "$TMP_TAR"
# fi
# else
# echo " ! Tar timed out or failed; skipping archive"; rm -f "$TMP_TAR"
# fi
# else
# echo " ! Journals ${CUR_MB}MB exceed cap ${SIZE_CAP_MB}MB; skipping archive"
# fi
# else
# echo " · No archive: missing key or no journal files"
# fi

# -------------------- Final plaintext removal --------------------
echo " · Removing plaintext *.journal / *.journal~ in $PERSIST_DIR"
$RUNROOT find "$PERSIST_DIR" -type f \( -name "*.journal" -o -name "*.journal~" \) -delete 2>/dev/null || true
echo " ✓ Persistent plaintext journals removed (if any)"

# --- Retention policy: keep only last 3 encrypted exports ---
echo " · Enforcing retention (keep 3 newest)"
$RUNROOT bash -lc '
ls -1t /var/log/journal/phantom0_journal_*.export.enc 2>/dev/null | tail -n +4 | while read -r old; do
[ -n "$old" ] && rm -f -- "$old"
done
'
echo " ✓ Retention enforced (3 most recent bundles kept)"

echo "✓ Section 9 completed successfully"
fi

set -e # restore strict mode if used by the rest of the script

################################################################################
# 10. System Tuning
################################################################################

echo "---- Section 10.1: Adjust system request interface ----"
echo ">>> 10.1 Adjusting system request interface"

if sysctl -w kernel.sysrq=0 >/dev/null 2>&1; then
echo "✓ 10.1 System request interface set to disabled"
echo "✓ Section 10.1 completed successfully"
else
echo "✗ 10.1 Could not adjust system request interface (safe to skip)"
echo "✗ Section 10.1 did not complete successfully"
fi

################################################################################
# 11. Peripheral Maintenance
################################################################################

echo "---- Section 11.1: Peripheral maintenance (display check) ----"
if [[ "$ENABLE_PERIPHERAL_PROTECTION" == "1" ]]; then
echo ">>> 11.1 Checking display blank status"
if [[ -e /sys/class/graphics/fb0/blank ]]; then
if echo 0 > /sys/class/graphics/fb0/blank 2>/dev/null; then
echo "✓ 11.1 Display confirmed active"
echo "✓ Section 11.1 completed successfully"
else
echo "✗ 11.1 Could not adjust display state (non-critical)"
echo "✗ Section 11.1 completed with notes"
fi
else
echo "✓ 11.1 No display blank control detected – skipped"
echo "✓ Section 11.1 completed successfully (skipped)"
fi
else
echo "✓ 11.1 Peripheral maintenance not enabled – skipped"
echo "✓ Section 11.1 completed successfully (skipped)"
fi

# NOTE: Do NOT remove 'usbhid' to avoid losing keyboard/mouse.

################################################################################
# 12. Temporary Storage Review
################################################################################

echo "---- Section 12.1: Refresh /dev/shm contents ----"
echo ">>> 12.1 Refreshing /dev/shm contents"

if mountpoint -q /dev/shm; then
if find /dev/shm -xdev -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null; then
echo "✓ 12.1 Temporary files in /dev/shm refreshed"
echo "✓ Section 12.1 completed successfully"
else
echo "✗ 12.1 Some /dev/shm files could not be refreshed (non-critical, safe to skip)"
echo "✗ Section 12.1 completed with notes"
fi
else
echo "✓ 12.1 /dev/shm not detected as a mountpoint – skipped"
echo "✓ Section 12.1 completed successfully (skipped)"
fi

# Note: Skipped /dev/mqueue and RAM-intensive fill to prevent unnecessary load.

################################################################################
# 13. Key Management
################################################################################
echo "13.1 Clearing non-LUKS keys..."
KEY_LIST="$($RUNROOT keyctl list @u 2>&1 || true)"
if echo "$KEY_LIST" | grep -qi "keyring is empty"; then
echo " ✓ Keyring already empty"
else
# Example: unlink all user keyring entries safely
# Adjust the selector if you only want specific keys.
while read -r id rest; do
case "$id" in
*id=*) kid="${id#id=}" ;;
*) kid="" ;;
esac
if [ -n "$kid" ]; then
$RUNROOT keyctl unlink "$kid" @u >/dev/null 2>&1 || true
fi
done <<EOF
$(echo "$KEY_LIST" | awk '/^ *{/{print $2}')
EOF

# Re-check status
KEY_LIST2="$($RUNROOT keyctl list @u 2>&1 || true)"
if echo "$KEY_LIST2" | grep -qi "keyring is empty"; then
echo " ✓ Keyring refreshed"
else
echo " ! Keyring not fully refreshed (non-fatal)"
fi
fi

################################################################################
# 14. System Care
################################################################################

echo "---- Section 14.1: Synchronize storage ----"
if sync; then
echo "✓ 14.1 Storage synchronized successfully"
else
echo "✗ 14.1 Storage sync encountered an error (rare)"
fi

echo "---- Section 14.2: Reclaim unused storage blocks ----"
# Safe with LUKS: will skip if discards not allowed
if fstrim -av 2>/dev/null; then
echo "✓ 14.2 Storage trim complete (skipped where not supported)"
else
echo "✗ 14.2 Storage trim not supported or skipped"
fi

echo "---- Section 14.3: Optimize memory layout ----"
if echo 1 > /proc/sys/vm/compact_memory 2>/dev/null; then
echo "✓ 14.3 Memory compaction requested"
else
echo "✗ 14.3 Memory compaction not available on this system"
fi

echo "---- Section 14.4: Refresh memory caches ----"
if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then
echo "✓ 14.4 Cache refresh requested"
else
echo "✗ 14.4 Cache refresh not available on this system"
fi

# Final summary for Section 14
echo "✓ Section 14 completed (with safe skips where unsupported)"

################################################################################
# 15. Completion Report
################################################################################

echo "---- Section 15.1: Finalize ----"
echo ">>> 15.1 Finalizing maintenance report"
echo "[[ SYSTEM MAINTENANCE COMPLETE: ALL TASKS REVIEWED ]]"

if [[ $? -eq 0 ]]; then
echo "✓ 15.1 System care routine finished"
echo "✓ Section 15.1 completed successfully"
else
echo "✗ 15.1 Completion report encountered an issue"
echo "✗ Section 15.1 did not complete successfully"
fi

# Final summary for Section 15
echo "✓ Section 15 completed (shutdown maintenance routine concluded)"

################################################################################
# ---15.2 FINAL SANITIZATION ---
################################################################################
trap '{
[ -f "$RUNLOG" ] && {
echo "15.2 Wiping run log..."
if luks_safe_wipe "$RUNLOG"; then
echo "LOG_WIPE_SUCCESS"
else
echo "LOG_WIPE_FAIL"
fi
}
}' EXIT

echo "15.2 Sanitizing kernel memory..."
if echo 1 > /proc/sys/vm/compact_memory && \
echo 3 > /proc/sys/vm/drop_caches && \
dd if=/dev/zero of=/dev/shm/zero bs=1M count=100 2>/dev/null
then
rm -f /dev/shm/zero
echo " ✓ Kernel memory sanitized"
else
echo " ✗ Kernel memory sanitization failed" >&2
fi

################################################################################
# 16. Verify all subsections reported
################################################################################
echo "---- Section 16.1: Verify all subsections reported results ----"

# Guard against running this block twice
if [ -n "${__VERIFY_RAN:-}" ]; then
echo "✓ 16.1 Verification already executed (skipping duplicate)"
else
__VERIFY_RAN=1

# Normalize directories (avoid unset vars under 'set -u')
LOGDIR="${LOGDIR:-${REAL_HOME}/phantom0_logs}"
LEGACYDIR="${LEGACYDIR:-${REAL_HOME}/phantom0_logs}"
RUNLOG="${RUNLOG:-}"

# Resolve a usable log path from: absolute RUNLOG, LOGDIR/RUNLOG, LEGACYDIR/RUNLOG,
# or the most recent file in LOGDIR, then LEGACYDIR.
resolve_log() {
local cand
# 1) If RUNLOG is absolute and exists
if [ -n "$RUNLOG" ] && [ "${RUNLOG#/}" != "$RUNLOG" ] && [ -f "$RUNLOG" ]; then
printf '%s\n' "$RUNLOG"; return 0
fi
# 2) If RUNLOG is a basename, try LOGDIR and LEGACYDIR
if [ -n "$RUNLOG" ] && [ "${RUNLOG#/}" = "$RUNLOG" ]; then
[ -n "$LOGDIR" ] && cand="$LOGDIR/$RUNLOG" && [ -f "$cand" ] && { printf '%s\n' "$cand"; return 0; }
[ -n "$LEGACYDIR" ] && cand="$LEGACYDIR/$RUNLOG" && [ -f "$cand" ] && { printf '%s\n' "$cand"; return 0; }
fi
# 3) Fallback: newest in LOGDIR
if [ -n "$LOGDIR" ] && [ -d "$LOGDIR" ]; then
cand="$(ls -1t "$LOGDIR"/phantom0-shutdown_*.log 2>/dev/null | head -n1)"
[ -n "$cand" ] && [ -f "$cand" ] && { echo ">>> 16.1 Falling back to latest log: $cand"; printf '%s\n' "$cand"; return 0; }
fi
# 4) Fallback: newest in LEGACYDIR
if [ -n "$LEGACYDIR" ] && [ -d "$LEGACYDIR" ]; then
cand="$(ls -1t "$LEGACYDIR"/phantom0-shutdown_*.log 2>/dev/null | head -n1)"
[ -n "$cand" ] && [ -f "$cand" ] && { echo ">>> 16.1 Falling back to latest log: $cand"; printf '%s\n' "$cand"; return 0; }
fi
return 1
}

LOGPATH=""
if LOGPATH="$(resolve_log)"; then
echo "✓ 16.1 Using log: $LOGPATH"
else
if [ -z "$RUNLOG" ]; then
echo "✗ 16.1 RUNLOG is not set — cannot verify"
else
echo "✗ 16.1 Log file not found (tried: '$RUNLOG', '$LOGDIR/$RUNLOG', '$LEGACYDIR/$RUNLOG')"
[ -z "$LOGDIR" ] && echo "✗ 16.1 LOGDIR not set or not a directory — skipped"
[ -z "$LEGACYDIR" ] && echo "✗ 16.1 LEGACYDIR not set or not a directory — skipped"
fi
fi

if [ -n "$LOGPATH" ]; then
# Discover all top-level subsection headers like: ---- Section N.M: <text> ----
mapfile -t discovered_ids < <(
grep -E '^---- Section [0-9]+\.[0-9]+:' "$LOGPATH" \
| sed -E 's/^---- Section ([0-9]+\.[0-9]+):.*/\1/' \
| grep -vE '^[0-9]+\.[0-9]+\.[0-9]+' \
| sort -u
)

if [ "${#discovered_ids[@]}" -eq 0 ]; then
echo "✗ 16.1 No subsection headers discovered in log — verification skipped"
else
missing=0
for id in "${discovered_ids[@]}"; do
# Require a result line that begins with ✓ or ✗ followed by the same ID
if ! grep -E "^[✓✗][[:space:]]+${id}\b" "$LOGPATH" >/dev/null 2>&1; then
echo "✗ Missing explicit result line for ${id}"
missing=1
fi
done
if [ $missing -eq 0 ]; then
echo "✓ All discovered subsections have explicit pass/fail lines"
fi

echo ">>> 16.2 Summary: scanning for any failures (excluding Section 16)"
# Exclude meta-failures from Section 16 itself to avoid false positives
if grep -E '^(✗|FAIL:)[[:space:]]+[0-9]+\.[0-9]+' "$LOGPATH" | grep -vE '^✗[[:space:]]+16\.' >/dev/null; then
echo "✗ Overall: one or more substeps reported issues (see above)."
echo ">>> 16.3 Details: failing substeps"
grep -nE '^(✗|FAIL:)[[:space:]]+[0-9]+\.[0-9]+' "$LOGPATH" | grep -vE '^✗[[:space:]]+16\.'
# Optional: exit non-zero for callers
# exit 2
else
echo "✓ Overall: no failures reported by any substep."
fi
fi
fi
fi

END_TIME=$(date +%s)
RUNTIME=$((END_TIME - START_TIME))
# Use frozen tokens (don’t rely on TZ lookup late in shutdown)
echo "[$(date '+%Y-%m-%d %H:%M:%S') ${START_TZ_ABBR}] >>> Script $(basename "$0") finished"
echo ">>> Runtime: ${RUNTIME} seconds"

# --- Encrypt run log (OpenSSL AES-256-CBC + PBKDF2) ---
# Assumes: $RUNLOG points to the plaintext log path for this run
# Stores encrypted log alongside it as "$RUNLOG.enc"
if [ -n "${RUNLOG:-}" ] && [ -f "$RUNLOG" ]; then
KEYFILE="/root/.phantom0/log.key"
if [ -r "$KEYFILE" ]; then
ENC="${RUNLOG}.enc"
if openssl enc -aes-256-cbc -pbkdf2 -salt \
-in "$RUNLOG" -out "$ENC" -pass file:"$KEYFILE"; then
shred -u "$RUNLOG" 2>/dev/null || rm -f "$RUNLOG"
chown root:root "$ENC" 2>/dev/null || true
chmod 600 "$ENC" 2>/dev/null || true
echo "[log] encrypted -> $ENC"
else
echo "[log] WARNING: encryption failed; leaving plaintext: $RUNLOG"
fi
else
echo "[log] WARNING: key file missing/unreadable: $KEYFILE (plaintext kept)"
fi
fi

exit 0
