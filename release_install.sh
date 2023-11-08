#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

usage () {
  echo "Usage: $(basename "$0") [-v|--verbose] [--dry-run] [PREFIX]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      usage
      exit 0
      ;;
    --verbose|-v)
      set -x
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [ "$EUID" -ne 0 ]
then
  echo "This script needs to install global udev rules, so please run as root."
  exit 1
fi

set -e

PREFIX=${1:-/usr/local}

sed -e "s|/usr/local|$PREFIX|" "$SCRIPT_DIR"/99-hid-bpf.rules > "$SCRIPT_DIR"/etc/udev/rules.d/99-hid-bpf.rules

if [[ -z "$DRY_RUN" ]];
then
  install -D -t "$PREFIX"/bin/ "$SCRIPT_DIR"/bin/udev-hid-bpf
  install -D -t /lib/firmware/hid/bpf "$SCRIPT_DIR"/lib/firmware/hid/bpf/*.bpf.o
  install -D -m 644 -t /etc/udev/rules.d "$SCRIPT_DIR"/etc/udev/rules.d/99-hid-bpf.rules
  install -D -m 644 -t /etc/udev/hwdb.d "$SCRIPT_DIR"/etc/udev/hwdb.d/99-hid-bpf.hwdb
  udevadm control --reload
  systemd-hwdb update
fi
