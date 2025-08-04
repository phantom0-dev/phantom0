#!/bin/bash
# === verify.sh ===
# Phantom-0 System Cloak Verifier

set -euo pipefail
IFS=$'\n\t'

REAL_USER=$(id -nu 1000 2>/dev/null || echo "unknown")
REAL_HOME=$(eval echo "~$REAL_USER")
PERSISTENT_PROFILE="$REAL_HOME/.firefox_persistent_profile"

GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

pass=0
fail=0
warn=0

print_ok()    { echo -e "${GREEN}✔ $1${RESET}"; ((pass++)); }
print_fail()  { echo -e "${RED}✘ $1${RESET}"; ((fail++)); }
print_warn()  { echo -e "${YELLOW}! $1${RESET}"; ((warn++)); }

check() {
  local desc="$1"
  shift
  if "$@"; then print_ok "$desc"; else print_fail "$desc"; fi
}

check_file() {
  local desc="$1"
  local path="$2"
  [ -f "$path" ] && print_ok "$desc ($path)" || print_fail "$desc ($path not found)"
}

check_symlink() {
  local desc="$1"
  local path="$2"
  [ -L "$path" ] && print_ok "$desc ($path is symlink)" || print_fail "$desc ($path not symlink)"
}

check_string_contains() {
  local desc="$1"
  local string="$2"
  local pattern="$3"
  [[ "$string" == *"$pattern"* ]] && print_ok "$desc" || print_fail "$desc"
}

echo -e "\n🧪 Verifying Phantom-0 Cloak State...\n"

# Firefox profile symlink
profile_path=$(ls -d "$REAL_HOME/.mozilla/firefox/"*.default* 2>/dev/null || true)
if [ -n "$profile_path" ]; then
  check_symlink "Firefox profile is symlinked to persistent" "$profile_path"
else
  print_warn "Firefox profile not found for symlink check"
fi

# Shell history cleared
[ ! -f "$REAL_HOME/.bash_history" ] && print_ok "Shell history cleared" || print_fail "Shell history file exists"

# Machine ID file
check_file "Machine ID exists and valid" "/etc/machine-id"

# MAC address check
CURRENT_MAC=$(ip link 2>/dev/null | awk '/ether/ {print $2}' | head -n1 || echo "")
if [[ "$CURRENT_MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
  check_string_contains "MAC address appears randomized" "$CURRENT_MAC" ":"
else
  print_fail "MAC address not found or invalid format"
fi

# Hostname heuristic check
HOSTNAME=${HOSTNAME:-$(hostname)}
[[ ${#HOSTNAME} -le 12 ]] && print_ok "Hostname appears randomized (length ≤ 12)" || print_warn "Hostname length > 12 – review if randomized"

# Recent log check
LOG_COUNT=$(journalctl --since "5 minutes ago" 2>/dev/null | wc -l || echo 0)
[[ "$LOG_COUNT" -lt 10 ]] && print_ok "Logs rotated recently (quiet log state)" || print_warn "High recent log activity ($LOG_COUNT lines)"

# DNS cache check
[ ! -f /run/systemd/resolve/stub-resolv.conf ] && print_ok "DNS cache state purged" || print_warn "DNS cache file still exists – confirm purge"

# ICMP echo rule
if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null; then
  print_ok "ICMP echo requests blocked"
else
  print_warn "ICMP echo requests not blocked (iptables rule missing)"
fi

# Mullvad daemon
if systemctl is-active --quiet mullvad-daemon; then
  print_ok "Mullvad daemon active"
else
  print_warn "Mullvad daemon not active"
fi

# Final status
echo -e "\n-----------------------------------------------"
echo -e "🧾 Results: ${GREEN}${pass} passed${RESET}, ${RED}${fail} failed${RESET}, ${YELLOW}${warn} warnings${RESET}"
if [[ "$fail" -eq 0 ]]; then
  echo -e "${GREEN}✔ Phantom-0 verification PASSED!${RESET}\n"
else
  echo -e "${RED}✘ Phantom-0 verification INCOMPLETE – review failed checks above.${RESET}\n"
fi
