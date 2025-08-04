#!/bin/bash
# === phantom0.sh ===
# Main CLI launcher for the Phantom-0 Privacy Toolkit

set -euo pipefail
IFS=$'\n\t'

# --- CONFIG ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
LOG_DIR="$HOME/.phantom0_logs"

# Ensure required directories exist
mkdir -p "$LOG_DIR"
if [ ! -d "$MODULES_DIR" ]; then
  echo "[!] Modules directory missing: $MODULES_DIR"
  exit 1
fi

# --- Banner ---
cat <<'EOF'
===============================================
    PHANTOM-0: BUILT FOR PRIVACY.
     DESIGNED FOR FREEDOM.
===============================================

Usage: phantom0 [run|verify|list|help] [module]

EOF

# --- Functions ---

run_module() {
  local module="$1"
  local path="$MODULES_DIR/${module}_routine.sh"

  if [ ! -f "$path" ]; then
    echo "[!] Module not found: '$module'"
    list_modules
    exit 1
  fi

  echo "[+] Executing module: $module"

  local log_file="$LOG_DIR/PHANTOM0_${module}_$(date +%F_%H-%M-%S).log"

  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    sudo bash "$path" 2>&1 | tee "$log_file"
  else
    bash "$path" 2>&1 | tee "$log_file"
  fi

  echo "[✓] Module '$module' finished. Log saved to: $log_file"
}

list_modules() {
  echo "Available modules:"
  local found=0
  for f in "$MODULES_DIR"/*_routine.sh; do
    [ -e "$f" ] || continue
    found=1
    name=$(basename "$f" | sed 's/_routine.sh//')
    echo " - $name"
  done
  [[ "$found" -eq 0 ]] && echo " (No modules found)"
}

verify_system() {
  local verify_script="$SCRIPT_DIR/verify.sh"
  if [ -f "$verify_script" ]; then
    echo "[+] Running system verification..."
    bash "$verify_script"
  else
    echo "[!] Verification tool not found: $verify_script"
    exit 1
  fi
}

show_help() {
  cat <<EOF
Commands:
  run [module]    Run a specific module (e.g., startup, shutdown)
  verify          Run system verification (checks cloak effectiveness)
  list            List all available modules
  help            Show this help message
EOF
}

# --- Command Parser ---
CMD="${1:-help}"
MODULE="${2:-}"

case "$CMD" in
  run)
    if [ -z "$MODULE" ]; then
      echo "[!] No module specified."
      list_modules
      exit 1
    fi
    run_module "$MODULE"
    ;;
  verify)
    verify_system
    ;;
  list)
    list_modules
    ;;
  help|*)
    show_help
    ;;
esac

exit 0
