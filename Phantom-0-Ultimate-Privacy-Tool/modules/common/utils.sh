#!/usr/bin/env bash
# shellcheck disable=SC2034
set -Eeuo pipefail

PH0_ROOT_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

load_config() {
  local cfg="${1:-$PH0_ROOT_DEFAULT/config/phantom0.conf}"
  if [[ -f "$cfg" ]]; then
    # shellcheck disable=SC1090
    source "$cfg"
  else
    echo "[!] No config found at $cfg; using defaults" >&2
  fi
  : "${DRY_RUN:=1}"
  : "${LOG_DIR:=/run/phantom0/logs}"
  : "${RAM_AUDIT_DIR:=/run/phantom0}"
}

log_ts() { date +"%Y-%m-%d %H:%M:%S %Z"; }
log_info() { echo "[INFO] $(log_ts) $*"; }
log_warn() { echo "[WARN] $(log_ts) $*" >&2; }
log_err()  { echo "[ERR ] $(log_ts) $*" >&2; }

ram_log_path() { echo "${RAM_AUDIT_DIR:-/run/phantom0}/audit.log"; }
ram_log_note() {
  local p; p="$(ram_log_path)"
  mkdir -p "$(dirname "$p")"
  printf "%s %s\n" "$(log_ts)" "$*" >> "$p"
}
