#!/usr/bin/env bash
set -Eeuo pipefail
VERSION_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.version"
init() { [[ -f "$VERSION_FILE" ]] || echo "0.1.0" > "$VERSION_FILE"; }
print() { init; cat "$VERSION_FILE"; }
bump() {
  init
  v="$(cat "$VERSION_FILE")"
  IFS='.' read -r a b c <<<"$v"
  c=$((c+1))
  echo "${a}.${b}.${c}" > "$VERSION_FILE"
  echo "New version: $(cat "$VERSION_FILE")"
}
case "${1:-print}" in
  print) print ;;
  bump)  bump  ;;
esac
