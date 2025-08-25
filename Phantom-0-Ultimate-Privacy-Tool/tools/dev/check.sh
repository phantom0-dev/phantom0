#!/usr/bin/env bash
set -Eeuo pipefail
echo "[*] Running basic checks..."
command -v bash >/dev/null || { echo "bash not found"; exit 1; }
echo "[*] OK: shell present"
# Optional: shellcheck, shfmt, bats if available
if command -v shellcheck >/dev/null 2>&1; then shellcheck -x phantomctl scripts/*.sh modules/**/*.sh; fi
if command -v shfmt >/dev/null 2>&1; then shfmt -d . || true; fi
if command -v bats >/dev/null 2>&1; then bats tests || true; fi
echo "[*] Done"
