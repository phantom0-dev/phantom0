#!/usr/bin/env bash
set -Eeuo pipefail

ethics_gate() {
  # Expect AGREE_TO_ETHICS=1 in config
  if [[ "${AGREE_TO_ETHICS:-0}" != "1" ]]; then
    echo "[ETHICS] Consent not granted. Set AGREE_TO_ETHICS=1 in config/phantom0.conf" >&2
    exit 2
  fi
}
