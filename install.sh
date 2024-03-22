#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

usage () {
  echo "Usage: $(basename "$0") [-v|--verbose] [--dry-run] [--udevdir /etc/] [PREFIX]"
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
      DRY_RUN="echo"
      shift
      ;;
    --udevdir)
      UDEVDIR=$2
      shift 2
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

set -e

CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}

PREFIX=${1:-/usr/local}
if [ -z "$UDEVDIR" ]; then
  case ${PREFIX%/} in
    /usr)
      UDEVDIR="/usr/lib"
      ;;
    *)
      UDEVDIR="/etc"
      ;;
  esac
fi

TMP_INSTALL_DIR="$CARGO_TARGET_DIR/install"
CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
PATH="$PATH:$TMP_INSTALL_DIR/bin" \
cargo install --force --path "$SCRIPT_DIR" --root "$TMP_INSTALL_DIR" --no-track

sed -e "s|/usr/local|$PREFIX|" 99-hid-bpf.rules > "$CARGO_TARGET_DIR"/bpf/99-hid-bpf.rules

echo "Using sudo to install files into $PREFIX. You may be asked for your password now"
$DRY_RUN sudo install -D -t "$PREFIX"/bin/ "$TMP_INSTALL_DIR"/bin/udev-hid-bpf
$DRY_RUN sudo install -D -t "$PREFIX"/lib/firmware/hid/bpf "$CARGO_TARGET_DIR"/bpf/*.bpf.o
$DRY_RUN sudo install -D -m 644 -t "$UDEVDIR"/udev/rules.d "$CARGO_TARGET_DIR"/bpf/99-hid-bpf.rules
$DRY_RUN sudo install -D -m 644 -t "$UDEVDIR"/udev/hwdb.d "$CARGO_TARGET_DIR"/bpf/99-hid-bpf.hwdb
$DRY_RUN sudo udevadm control --reload
$DRY_RUN sudo systemd-hwdb update
