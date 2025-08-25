#!/usr/bin/env bash
PH0_ORIG_BASENAME=phantom0-shutdown.sh
#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Common helpers
source "$ROOT_DIR/modules/common/utils.sh"
source "$ROOT_DIR/modules/common/distro.sh"

# ---------- Auto-detect environment (no hardcoded user/paths) ----------
load_config "$ROOT_DIR/config/phantom0.conf" || true
detect_distro

# User/home detection (prefer UID 1000, else SUDO_USER, else current user)
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  REAL_USER="${REAL_USER:-$SUDO_USER}"
else
  REAL_USER="${REAL_USER:-$(awk -F: '$3==1000{print $1;exit}' /etc/passwd || id -un)}"
fi
REAL_HOME="${REAL_HOME:-$(getent passwd "$REAL_USER" | cut -d: -f6)}"

# Network interface autodetect (default route; first wg/tun/tap/mullvad/vpn as VPN)
PRIMARY_IFACE="${PRIMARY_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
VPN_IFACE="${VPN_IFACE:-$(ip -o link show | awk -F': ' '$2 ~ /^(wg|tun|tap|mullvad|vpn)/ {print $2; exit}')}"
export REAL_USER REAL_HOME PRIMARY_IFACE VPN_IFACE DISTRO_FAMILY

# Logging to RAM by default (avoid real paths leakage)
: "${LOG_DIR:=/run/phantom0/logs}"
: "${RAM_AUDIT_DIR:=/run/phantom0}"
export LOG_DIR RAM_AUDIT_DIR

# ---------- Compatibility shim for hardcoded legacy paths ----------
# If the original scripts reference a legacy user path like /home/neo, we emulate it
# in a private mount namespace so the host FS is untouched.
LEGACY_HOME="/home/neo"

# Only create the shim if the legacy path is different from REAL_HOME or missing
need_ns_shim=0
if [[ "$LEGACY_HOME" != "$REAL_HOME" ]]; then
  need_ns_shim=1
elif [[ ! -d "$LEGACY_HOME" ]]; then
  need_ns_shim=1
fi

ORIG="$ROOT_DIR/scripts/original/${PH0_ORIG_BASENAME}"
if [[ ! -f "$ORIG" ]]; then
  echo "[wrapper] Original script missing at $ORIG" >&2
  exit 3
fi

run_in_namespace() {
  # Create a private mount namespace and bind-map legacy path to real home
  # Requires util-linux unshare & mount.
  # Note: We avoid altering the host /home; mapping is local to this process.
  if ! command -v unshare >/dev/null 2>&1; then
    echo "[shim] 'unshare' not available; running without legacy path mapping." >&2
    exec bash "$ORIG" "$@"
  fi

  unshare -m bash -c '
    set -Eeuo pipefail
    LEGACY_HOME="'"$LEGACY_HOME"'"
    REAL_HOME="'"$REAL_HOME"'"
    if [[ ! -d "$LEGACY_HOME" ]]; then
      mkdir -p "$LEGACY_HOME"
    fi
    mount --bind "$REAL_HOME" "$LEGACY_HOME"
    # Ensure HOME env points to REAL_HOME for tools that use it
    export HOME="'"$REAL_HOME"'"
    exec bash "'"$ORIG"'" "$@"
  ' bash "$@"
}

# ---------- Execute the original script unchanged ----------
if (( need_ns_shim )); then
  run_in_namespace "$@"
else
  # No shim needed; just run it with autodetected env
  exec bash "$ORIG" "$@"
fi
