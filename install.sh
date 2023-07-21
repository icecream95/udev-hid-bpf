#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if [ "$EUID" -ne 0 ]
then
  echo "This script needs to install global udev rules, so please run as root."
  exit 1
fi

set -ex

CARGO_USER=${SUDO_USER:-root}

PREFIX=${1:-/usr/local}
TMP_INSTALL_DIR="$SCRIPT_DIR/target/install"
sudo -u "$CARGO_USER" -i cargo install --force --path "$SCRIPT_DIR" --root "$TMP_INSTALL_DIR" --no-track

install -D -t "$PREFIX"/bin/ "$TMP_INSTALL_DIR"/bin/udev-hid-bpf

sed -e "s|/usr/local|$PREFIX|" 99-hid-bpf.rules > target/bpf/99-hid-bpf.rules

install -D -t /lib/firmware/hid/bpf target/bpf/*.bpf.o
install -D -m 644 -t /etc/udev/rules.d target/bpf/99-hid-bpf.rules
install -D -m 644 -t /etc/udev/hwdb.d target/bpf/99-hid-bpf.hwdb
udevadm control --reload
systemd-hwdb update
