#!/usr/bin/env bash
set -Eeuo pipefail

journal_encrypt_flow() {
  if [[ "${1:-}" == "--demo" ]]; then
    echo "[demo] journal_encrypt_flow (placeholder)"
    return 0
  fi
  echo "[guard] journal encryption flow disabled in public skeleton"
  return 2
}
