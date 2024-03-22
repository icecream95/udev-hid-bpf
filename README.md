# udev-hid-bpf

An automatic HID-BPF loader based on udev events written in Rust. This repository aims to
provide a simple way for users to write a HID-BPF program that fixes their device. Knowledge of Rust
should not be required.

## Getting started

You can build and install using Rust's `cargo` and our custom install script:

```
$ git clone https://gitlab.freedesktop.org/libevdev/udev-hid-bpf.git
$ cd udev-hid-bpf/
$ cargo build
$ ./install.sh
# this will ask for your sudo password to install udev rules and hwdb files
```

Once installed, unplug/replug any supported device, and the bpf program will automatically be attached to the HID kernel device.

For details on required dependencies etc. please see [our documentation](https://libevdev.pages.freedesktop.org/udev-hid-bpf/).

## Quirks, user hack, testing and stable

`udev-hid-bpf` divide HID-BPF programs into two categories: quirks and user hacks. Quirks are programs that
fix a device that objectively has a hardware or firmware bug. Examples include axis that are inverted, provide
the wrong ranges/values or event sequences that are logically impossible.
We expect that quirks are eventually upstreamed into the kernel.

User hacks are HID-BPF programs that change a user-subjective preference on a device. Examples include swapping
buttons for convenience or muting an axis to avoid crashes in a specific application. These programs will
never be upstreamed as they are user and use-case specific. `udev-hid-bpf` maintains a set of user hacks
as examples and starting point for users who want to develop their own hacks.

To divide this we use the following directory structure:

- `bpf/testing/` is where all new quirks should go. Once they have proven to be good enough, they should be
   submitted to the upstream kernel.
- `bpf/stable/` is where quirks move to once upstream has accepted them and they will be part of the next kernel release.
   Distributions that package `udev-hid-bpf` should package these stable quirks.
- `bpf/userhacks` is where all user hacks should go. Unlike quirks these will never move to stable.

By default, only `testing` is enabled during `cargo build`. To select which one to install, use
`cargo build --features testing,stable,userhacks` or a subset thereof.

## Adding custom files

The filename of a HID-BPF program must follow the following syntax:

```
bBBBBgGGGGv0000VVVVp0000PPPP-some-identifier.bpf.c
```

Where:
- `BBBB` is the bus raw value (in uppercase hexadecimal) (`0003` for USB, `0018` for I2C, `0005` for Bluetooth, etc...)
- `GGGG` is the HID group as detected by HID (again, in uppercase hexadecimal)
- `VVVV` and `PPPP` are respectively the vendor ID and product ID (as in `lsusb`, so uppercase hexadecimal too)
- `some-identifier` is a string aimed at humans to identify what the program does, e.g. `correct-mouse-button`.

Instead of building this name yourself, it is way more efficient to simply use the
modalias of the device as provided by the kernel:
```
$> cat /sys/bus/hid/devices/0003:04D9:A09F.0009/modalias
hid:b0003g0001v000004D9p0000A09F

$> cat /sys/class/hidraw/hidraw0/device/modalias
hid:b0003g0001v000004D9p0000A09F
```

Just strip out the `hid:` prefix and done.

For details on file name and how they are matched to devices please see [our documentation](https://libevdev.pages.freedesktop.org/udev-hid-bpf/).
