#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

usage () {
  echo "Usage: $(basename "$0") [-v|--verbose]"
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
    --features)
      features=$2
      shift 2
      ;;
    --*)
      usage
      exit 1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [ $# -gt 1 ]; then
  usage
  exit 1
fi

set -e

if [ -n "$features" ]; then
  features="-Dbpfs=$features"
fi

TMP_INSTALL_DIR=$PWD/_inst
BUILDDIR=_release_builddir
meson setup \
  -Dprefix="$TMP_INSTALL_DIR" \
  -Dudevdir="$TMP_INSTALL_DIR/lib/udev" \
  -Dplaceholder-udev-rules-file=true \
  "$BUILDDIR"
meson compile -C "$BUILDDIR"
meson install -C "$BUILDDIR"

VERSION=$(git describe --tags --dirty)
NAME=udev-hid-bpf_${VERSION}

# Now get the list of installed files and generate install.sh and uninstall.sh with it

installed=$(meson introspect _release_builddir --installed | yq -r ".[] | sub(\"$TMP_INSTALL_DIR/\"; \"\")")
INSTALL_COMMANDS=""
UNINSTALL_COMMANDS=""
for f in $installed; do
  if [[ "$f" == *bpf.o* ]]; then
    INSTALL_COMMANDS="$INSTALL_COMMANDS\n\$dryrun_sudo install -D -t \"\$PREFIX/$(dirname "$f")\" \"\$SCRIPT_DIR/$f\""
    UNINSTALL_COMMANDS="$UNINSTALL_COMMANDS\n\$dryrun_sudo rm -f \"\$PREFIX/$f\""
  fi
done

sed -e "s|@@INSTALL_COMMANDS@@|$INSTALL_COMMANDS|" release_install.sh.in > "$TMP_INSTALL_DIR"/install.sh
sed -e "s|@@UNINSTALL_COMMANDS@@|$UNINSTALL_COMMANDS|" release_uninstall.sh.in > "$TMP_INSTALL_DIR"/uninstall.sh
chmod +x "$TMP_INSTALL_DIR"/install.sh "$TMP_INSTALL_DIR"/uninstall.sh

tar cvaf ${NAME}.tar.xz -C "$TMP_INSTALL_DIR" --transform "s/^\./$NAME/" .
