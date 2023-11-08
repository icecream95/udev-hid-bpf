#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

usage () {
  echo "Usage: $(basename "$0") [-v|--verbose] [--dry-run]"
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

set -e

CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}
TMP_INSTALL_DIR="$CARGO_TARGET_DIR/install"

# some cleanup
rm -rf $TMP_INSTALL_DIR
rm -rf "$CARGO_TARGET_DIR"/bpf/*.bpf.o

# force rebuild of bpf objects
touch $SCRIPT_DIR/src/bpf/

PATH="$PATH:$TMP_INSTALL_DIR/bin" \
 cargo install --force --path "$SCRIPT_DIR" --root "$TMP_INSTALL_DIR" --no-track

install -D -t "$TMP_INSTALL_DIR"/lib/firmware/hid/bpf "$CARGO_TARGET_DIR"/bpf/*.bpf.o
install -D -m 644 -t "$TMP_INSTALL_DIR" "$SCRIPT_DIR"/99-hid-bpf.rules LICENSE
mkdir -p "$TMP_INSTALL_DIR"/etc/udev/rules.d/
install -D -m 644 -t "$TMP_INSTALL_DIR"/etc/udev/hwdb.d "$CARGO_TARGET_DIR"//bpf/99-hid-bpf.hwdb
install -D -m 755 "$SCRIPT_DIR"/release_install.sh "$TMP_INSTALL_DIR"/install.sh
install -D -m 755 -t "$TMP_INSTALL_DIR" "$SCRIPT_DIR"/uninstall.sh

VERSION=$($TMP_INSTALL_DIR/bin/udev-hid-bpf --version)
NAME=${VERSION/ /_}
RELEASE_DIR=$(dirname $TMP_INSTALL_DIR)

rm -rf $RELEASE_DIR/$NAME
mv $TMP_INSTALL_DIR $RELEASE_DIR/$NAME

tar cvaf ${NAME}.tar.xz -C $RELEASE_DIR $NAME
