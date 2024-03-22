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
    --*)
      usage
      exit 1
      ;;
    *)
      break;
      ;;
  esac
done

if [ $# -gt 1 ]; then
  usage
  exit 1
fi

if [ "$EUID" -ne 0 ]
then
  echo "This script needs to update global udev rules, so please run as root."
  exit 1
fi

set -e

PREFIX=${1:-/usr/local}

if [[ -z "$DRY_RUN" ]];
then
  rm -f "$PREFIX"/bin/udev-hid-bpf
  BPF=$(ls "$SCRIPT_DIR"/lib/firmware/hid/bpf/*.bpf.o)
  INSTALLED_BPF=${BPF//$SCRIPT_DIR/}
  rm -f $INSTALLED_BPF
  rm -f /etc/udev/rules.d/99-hid-bpf.rules
  rm -f /etc/udev/hwdb.d/99-hid-bpf.hwdb
  udevadm control --reload
  systemd-hwdb update
fi
