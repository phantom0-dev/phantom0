#!/usr/bin/env bash
set -Eeuo pipefail

detect_distro() {
  DISTRO_FAMILY="unknown"
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID_LIKE:-$ID}" in
      *debian*|*ubuntu*|debian) DISTRO_FAMILY="debian" ;;
      *arch*|arch)              DISTRO_FAMILY="arch"   ;;
      *rhel*|*fedora*|*centos*|rhel) DISTRO_FAMILY="rhel" ;;
      *) DISTRO_FAMILY="$ID" ;;
    esac
  fi
  export DISTRO_FAMILY
}
