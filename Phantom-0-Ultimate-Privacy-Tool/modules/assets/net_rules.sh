#!/usr/bin/env bash
set -Eeuo pipefail

net_rules_obfuscate() {
  if [[ "${1:-}" == "--demo" ]]; then
    echo "[demo] net_rules_obfuscate (placeholder)"
    return 0
  fi
  echo "[guard] network rule obfuscation disabled in public skeleton"
  return 2
}
