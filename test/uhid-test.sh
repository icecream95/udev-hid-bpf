#!/bin/bash
#
# Tests the loading priorities by creating a known uhid device, then installing the always-fail, always-good bpf.o
#

usage () {
  echo "Usage: $(basename "$0") [-v|--verbose] [--wait-after-load] <test-udev-load|test-path-load|test-udev-trigger>"
  echo ""
  echo "Use --wait-after-load to pause the script after loading the BPF programs"
}

jobs=${FDO_CI_CONCURRENT:-0}

test_udev_load=""
test_udev_trigger=""
test_path_load=""
wait_after_load=""

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
        --wait-after-load)
            wait_after_load="1"
            shift
            ;;
        --*)
            usage
            exit 1
            ;;
        test-udev-trigger)
            test_udev_trigger="1"
            shift
            ;;
        test-udev-load)
            test_udev_load="1"
            shift
            ;;
        test-path-load)
            test_path_load="1"
            shift
            ;;
        *)
          break;
          ;;
  esac
done

if [ $# -gt 0 ]; then
    usage
    exit 1
fi

if [ -z "$test_path_load$test_udev_load$test_udev_trigger" ]; then
    usage
    exit 2
fi

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
HID_RECORDING="$SCRIPT_DIR/msmouse.hid.txt"
UDEV_RULE="/etc/udev/rules.d/99-hid-bpf-REMOVEME.rules"
HWDB="/etc/udev/hwdb.d/99-hid-bpf-REMOVEME.hwdb"
MESON_SOURCEDIR="$SCRIPT_DIR/.."

die() {
    echo "$1" >&2
    exit 1
}

# Die if the given file does not exist
exists_or_fail() {
    file="$1"
    if ! [ -e "$file" ]; then
        die "Missing required file: $file"
    fi
}

# Die if the given file does not exist (checking with sudo)
sudo_exists_or_fail() {
    file="$1"
    if ! sudo test -e "$file"; then
        die "Missing required file: $file"
    fi
}

echo "Asking for your sudo password now because I'll need it in a few seconds"
sudo -v

exists_or_fail "$MESON_SOURCEDIR/meson_options.txt"

hwdb_tool="$SCRIPT_DIR/../tools/generate-hwdb.py"
exists_or_fail "$hwdb_tool"

if ! command -v hid-replay > /dev/null; then
    die "hid-replay not found in \$PATH, cannot proceed"
fi

if [ -z "$MESON_BUILDDIR" ]; then
  MESON_BUILDDIR=udev-hid-bpf-test-builddir
  echo "Using MESON_BUILDDIR of $MESON_BUILDDIR"
fi

set -u
meson_subcommand="configure"
if ! [ -e "$MESON_BUILDDIR" ]; then
    meson_subcommand="setup"
fi

instdir=$(realpath "$MESON_BUILDDIR/")/_inst
fwdir="$instdir/lib/firmware/hid/bpf"
udev_hid_bpf="$instdir/bin/udev-hid-bpf"

meson $meson_subcommand -Dbpfs=testing,stable -Dprefix="$instdir" -Dudevdir="$instdir/etc/udev" "$MESON_BUILDDIR"
meson compile -C "$MESON_BUILDDIR" -j "$jobs"
meson install -C "$MESON_BUILDDIR"
exists_or_fail "$instdir/lib/firmware/hid/bpf"

# Create the UHID device
sudo hid-replay "$HID_RECORDING" >/dev/null &
hid_replay_pid=$!
cleanup () {
    sudo kill $hid_replay_pid
    wait $hid_replay_pid || true
    sudo rm -f "$UDEV_RULE"
    sudo rm -f "$HWDB"
    sudo udevadm control --reload
    sudo systemd-hwdb update
}
trap cleanup EXIT
sleep 0.5

syspath=$(find /sys/devices/virtual/misc/uhid -name "0003:045E:00D1.*" -print -quit)
if [ -z "$syspath" ]; then
    die "UHID device not found"
fi
fwpath="/sys/fs/bpf/hid"
fwpath_device=$(basename "$syspath" | sed -e 's/[:\.]/_/g')
fwpath_device="$fwpath/$fwpath_device"

# Convert a foo.bpf.o into the corresponding entry in /sys/fs/bpf/hid...
to_bpf_name() {
    local -n DEST=$1
    filename=$(basename "$2")
    filename=${filename/.bpf.o/_bpf}
    # shellcheck disable=SC2034
    DEST="$fwpath_device/$filename"
}

# Check that a bpf file is loaded
bpf_is_loaded() {
    bpf=""   # to shut up shellcheck: bpf never assigned
    to_bpf_name bpf "$1"
    if ! sudo test -e "$bpf"; then
        die "ERROR: Missing expected bpf: $bpf"
    fi
}
bpf_is_not_loaded() {
    bpf=""   # to shut up shellcheck: bpf never assigned
    to_bpf_name bpf "$1"
    if sudo test -e "$bpf"; then
        die "ERROR: Unexpected bpf: $bpf"
    fi
}

test_cmd_add_with_path() {
    fail_bpf="$MESON_BUILDDIR/src/bpf/userhacks/10-noop-probe-fail.bpf.o"
    success_bpf="$MESON_BUILDDIR/src/bpf/userhacks/10-noop-probe-succeed.bpf.o"
    exists_or_fail "$fail_bpf"
    exists_or_fail "$success_bpf"

    install --mode=644 "$fail_bpf" "$fwdir"
    install --mode=644 "$success_bpf" "$fwdir"

    bpf=""   # to shut up shellcheck: bpf never assigned

    "$udev_hid_bpf" --version
    sudo "$udev_hid_bpf" --verbose --debug add "$syspath" "$success_bpf"
    sudo tree "$fwpath"

    if [ -n "$wait_after_load" ]; then
        echo "Ctrl+C to continue"
        read -r -d ''
    fi

    bpf_is_loaded "$success_bpf"

    to_bpf_name bpf "$fail_bpf"
    sudo "$udev_hid_bpf" --verbose --debug add "$syspath" "$fail_bpf"
    sudo tree "$fwpath"
    bpf_is_not_loaded "$fail_bpf"
}

test_cmd_add_via_udev() {
    mode="$1"

    fail_bpf="$MESON_BUILDDIR/src/bpf/userhacks/10-noop-probe-fail.bpf.o"
    succeed_bpf="$MESON_BUILDDIR/src/bpf/userhacks/10-noop-probe-succeed.bpf.o"
    exists_or_fail "$fail_bpf"
    exists_or_fail "$succeed_bpf"

    install --mode=644 "$fail_bpf" "$fwdir/03-one.bpf.o"
    install --mode=644 "$succeed_bpf" "$fwdir/02-one.bpf.o"
    install --mode=644 "$succeed_bpf" "$fwdir/01-one.bpf.o"
    install --mode=644 "$succeed_bpf" "$fwdir/02-two.bpf.o"
    install --mode=644 "$succeed_bpf" "$fwdir/01-two.bpf.o"
    install --mode=644 "$fail_bpf" "$fwdir/02-three.bpf.o"
    install --mode=644 "$succeed_bpf" "$fwdir/01-three.bpf.o"

    udev_rule="/etc/udev/rules.d/99-hid-bpf-REMOVEME.rules"

    $udev_hid_bpf inspect "$fwdir"/*{one,two,three}.bpf.o | $hwdb_tool | sudo tee $HWDB
    sudo systemd-hwdb update
    sudo install --mode=644 "$instdir/etc/udev/rules.d/81-hid-bpf.rules" "$udev_rule"
    # If we're testing the load (not the trigger), comment out the RUN line for action add
    if [ "$mode" == "load" ]; then
        sudo sed -i 's/.*udev-hid-bpf add.*/# \0/' "$udev_rule"
        cat "$udev_rule"
    fi
    sudo udevadm control --reload

    sudo udevadm trigger --action=add "$syspath"
    sudo udevadm test "$syspath"

    # If we're testing the load (not the trigger), run it manually now
    if [ "$mode" == "load" ]; then
        sudo "$udev_hid_bpf" --verbose --debug add "$syspath"
    fi

    maxwait=20
    while [ $maxwait -gt 0 ]; do
        if sudo test -e  "$fwpath_device"; then
            break
        fi
        sleep 0.2
        maxwait=$((maxwait - 1))
    done

    sudo tree "$fwpath_device"

    if [ -n "$wait_after_load" ]; then
        echo "Ctrl+C to continue"
        trap exit INT
        read -r -d ''
        trap INT
    fi

    # The trigger should've loaded our bpf files so we can check them
    bpf=""   # to shut up shellcheck: bpf never assigned
    bpf_is_loaded "02-one.bpf.o"
    bpf_is_loaded "02-two.bpf.o"
    bpf_is_loaded "01-three.bpf.o"

    bpf_is_not_loaded "03-one.bpf.o"
    bpf_is_not_loaded "01-one.bpf.o"
    bpf_is_not_loaded "01-two.bpf.o"
    bpf_is_not_loaded "02-three.bpf.o"
}

if [ -e "/sys/fs/bpf/" ]; then
    sudo mount bpffs -t bpf /sys/fs/bpf/
fi

if [ -n "$test_path_load" ]; then
    test_cmd_add_with_path
fi

if [ -n "$test_udev_load" ]; then
    test_cmd_add_via_udev "load"
fi

if [ -n "$test_udev_trigger" ]; then
    test_cmd_add_via_udev "trigger"
fi
