# udev-hid-bpf

An automatic HID-BPF loader based on udev events written in Rust. This repository aims to
provide a simple way for users to write a HID-BPF program that fixes their device. Knowledge of Rust
should not be required.

## Getting started

To build the loader *and* the various example HID-BPF programs use the standard Rust build process:

```
$ cargo build
```

The above `cargo` command will build the tool and any eBPF programs it finds in `src/bpf/*.bpf.c`.
Please see the [cargo documentation](https://doc.rust-lang.org/cargo/) for more details on invoking `cargo`.

Then, we can start the binary with the following command:

```
sudo ./target/debug/udev-hid-bpf
```

The program will check for any currently plugged in HID device and load any eBPF program that matches.
It will then listen for udev events and will load automatically eBPF programs when they are available.

## Matching eBPF programs to a device

This tool supports multiple ways of matching a eBPF program to a HID device:

### Filename modalias matches

The filename of a HID-BPF program should follow the following syntax:

```
bBBBBgGGGGvVVVVpPPPPanything.bpf.c
```

Where:
- `BBBB` is the bus raw value (in hexadecimal) (`0003` for USB, `0018` for I2C, `0005` for Bluetooth, etc...)
- `GGGG` is the HID group as detected by HID (again, in hexadecimal)
- `VVVV` and `PPPP` are respectively the vendor ID and product ID (as in `lsusb`, so hexadecimal too)
- `anything` can be anything and can be used to have separate eBPF programs based on the functionality for the same HID device

Instead of building this name yourself, it is way more efficient to simply use the
modalias of the device as provided by the kernel:
```
# filesystem version:
$> cat /sys/bus/hid/devices/0003:04D9:A09F.0009/modalias
hid:b0003g0001v000004D9p0000A09F

# udevadm version (fancy way of going from hidraw to the modalias)
$> udevadm info --query=property --property=MODALIAS /sys/$(udevadm info --query=path /dev/hidraw0)/../..
MODALIAS=hid:b0003g0001v000004D9p0000A09F
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
