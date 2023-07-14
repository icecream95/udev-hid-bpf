# udev-hid-bpf

An automatic HID-BPF loader based on udev events written in Rust. This repository aims to
provide a simple way for users to write a HID-BPF program that fixes their device. Knowledge of Rust
should not be required.

## Getting started

### Dependencies

- rust: install through your package manager or with `rustup`

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source "$HOME/.cargo/env"
```

- udev and llvm: Check the [.gitlab-ci.yml](https://gitlab.freedesktop.org/bentiss/udev-hid-bpf/-/blob/main/.gitlab-ci.yml)
for `FEDORA_PACKAGES`.

### Installation

Clone the repo, `cd` into it, and build the loader *and* the various example HID-BPF programs
by using the standard Rust build process:
```
$ git clone https://gitlab.freedesktop.org/bentiss/udev-hid-bpf.git
$ cd udev-hid-bpf/
$ cargo build
```

The above `cargo` command will build the tool and any eBPF programs it finds in `src/bpf/*.bpf.c`.
Please see the [cargo documentation](https://doc.rust-lang.org/cargo/) for more details on invoking `cargo`.

Then, we can install the binary with the following command:
```
$ sudo ./install.sh
```

The above command will (re)build the tool and any eBPF programs it finds in `src/bpf/*.bpf.c`.
It will then install
- the tool itself into in `/usr/local/bin`
- the compiled eBPF objects in`/lib/firmware/hid/bpf`.
- a udev rule to trigger the tool in `/etc/udev/rules.d/99-hid-bpf.rules`

Once installed, unplug/replug any supported device, and the bpf program will automatically be attached to the HID kernel device.

## Matching eBPF programs to a device

This tool supports multiple ways of matching a eBPF program to a HID device:

### Filename modalias matches

The filename of a HID-BPF program should follow the following syntax:

```
bBBBBgGGGGvVVVVpPPPPsome-identifier.bpf.c
```

Where:
- `BBBB` is the bus raw value (in hexadecimal) (`0003` for USB, `0018` for I2C, `0005` for Bluetooth, etc...)
- `GGGG` is the HID group as detected by HID (again, in hexadecimal)
- `VVVV` and `PPPP` are respectively the vendor ID and product ID (as in `lsusb`, so hexadecimal too)
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

#### Sharing the same eBPF program for different devices

The modalias supports basic globbing features: any of
`BBBB`, `GGGG`, `VVVV` or `PPPP` may be the literal character `*`.
Any device that matches all the other fields will thus match. For example
a filename of `b0003g*v*p*foo.bpf.c` will match any USB device.

### Run-time probe

Sometimes having just the static modalias is not enough to know if a program needs to be loaded.
For example, one mouse I am doing tests with (`b0003g0001v04d9pa09f-mouse.bpf.c`) exports 3 HID interfaces,
but the eBPF program only applies to one of those HID interfaces.

`udev-hid-bpf` provides a similar functionality as the kernel with a `probe` function.
Before loading and attaching any eBPF program to a given HID device, `udev-hid-bpf` executes the syscall `probe` in the `.bpf.c` file if there is any.

The arguments of this syscall are basically the unique id of the HID device, its report descriptor and its report descriptor size.
If the eBPF program sets the `ctx->retval` to zero, the  eBPF program is loaded for this device. A nonzero value (typically `-EINVAL`)
prevents the eBPF program from loading. See the `b0003g0001v04d9pa09f-mouse.bpf.c` program for an example of this functionality.
