#!/usr/bin/env bash
set -Eeuo pipefail

proc_hide_flow() {
  if [[ "${1:-}" == "--demo" ]]; then
    echo "[demo] proc_hide_flow (placeholder)"
    return 0
  fi
  echo "[guard] /proc hiding flow disabled in public skeleton"
  return 2
}
