#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Script to help create a release tarball from two different
# compiled versions of udev-hidp-bpf.
#
# The SRCDIR is an installed version of udev-hid-bpf. That install
# is overwritten with just the rebuilt udev-hid-bpf (bpf.o files are left as-is)
#

set -e

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

usage() {
  echo "Usage: $(basename "$0") SRCDIR"
}

SRCDIR="$1"

if [[ -z "$SRCDIR" ]]; then
  usage >&2
  exit 1
fi

if ! [[ -e "$SRCDIR" ]]; then
  echo "'$SRCDIR' does not exist" >&2
  exit 1
fi

if ! [[ -e "$SRCDIR/bin/udev-hid-bpf" ]]; then
  echo "Missing file $SRCDIR/bin/udev-hid-bpf" >&2
  exit 1
fi


DSTDIR=$(mktemp -d _udev-hid-bpf-release-XXX)
MESON_BUILDDIR=$(mktemp -d _builddir.XXXX)
export MESON_BUILDDIR

# Overwrite just udev-hid-bpf with one compat with this glibc
export MESON_ARGS="--prefix=$SRCDIR -Dbpfs=[] -Dudevdir=$SRCDIR/lib/udev"

"$SCRIPT_DIR"/meson-build.sh --skip-test --run-install

python3 -m venv _venv
# shellcheck disable=SC1091
. _venv/bin/activate
pip install jinja2

"$SCRIPT_DIR"/make-release.py --verbose \
   --template "$SCRIPT_DIR"/install.sh.jinja \
   --template "$SCRIPT_DIR"/uninstall.sh.jinja \
   "$SRCDIR" "$DSTDIR"

TARBALL_NAME="udev-hid-bpf_$(git describe --tags)"
tar cvaf "${TARBALL_NAME}.tar.xz" -C "$DSTDIR" --transform "s/^\./$TARBALL_NAME/" .
echo "Tarball available as ${TARBALL_NAME}.tar.xz"
