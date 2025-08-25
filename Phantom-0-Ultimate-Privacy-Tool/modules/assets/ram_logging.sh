#!/usr/bin/env bash
set -Eeuo pipefail

ram_log_init() {
  local base="${LOG_DIR:-/run/phantom0/logs}"
  # tmpfs-only path; no disk writes
  mkdir -p "$base"
  ram_log_note "ram_logging.init path=$base"
}
