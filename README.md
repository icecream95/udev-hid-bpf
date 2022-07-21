# udev-hid-bpf

An automatic HID-BPF loader based on udev events written in rust

## Getting started

```
cargo build
```

The above `cargo` command will build the tool and any bpf programs it finds in `src/bpf/*.bpf.c`.

Then, we can start the binary by doing the following:

```
sudo ./target/debug/udev-hid-bpf
```

The program will check for any currently plugged in HID device, and load any eBPF program that matches.
It will then listen for udev events and will load automatically eBPF programs when they are availaable.

## Why an eBPF program is bound to a given device?

A couple of elements are used to chose if a given eBPF program needs to be loaded against a given HID device:

### filename

The filenames of the HID-BPF programs should follow the following syntax:

```
bBBBBgGGGGvVVVVpPPPPanything.bpf.c
```

Where:
- `BBBB` is the bus raw value (in hexadecimal) (USB, I2C, Bluetooth, etc...)
- `GGGG` is the HID group as detected by HID (again, in hexadecimal)
- `VVVV` and `PPPP` are respectively the vendor ID and product ID (as in lsusb, so hexadecimal too)
- `anything` can be anything and can be used to have separate eBPF programs based on the fonctionality for the same HID device

Instead of building this name yourself, it is way more efficient to simply rely on the modalias of the device:
```
# filesystem version:
$> cat /sys/bus/hid/devices/0003:04D9:A09F.0009/modalias
hid:b0003g0001v000004D9p0000A09F

# udevadm version (fancy way of going from hidraw to the modalias)
$> udevadm info --query=property --property=MODALIAS /sys/$(udevadm info --query=path /dev/hidraw0)/../..
MODALIAS=hid:b0003g0001v000004D9p0000A09F
```

Just strip out `hid:` and you are done.

#### But I want to share an eBPF program between 2 similar devices with a different modalias?

The tool implements another fancy feature regarding filenames: you can replace any `BBBB`, `GGGG`, `VVVV` or `PPPP` by the single character `*` and any device that matches all the other fields will get picked up.

### probe-like feature

Sometimes having just the static modalias is not enough to know if a program needs to be loaded.

For instance, one mouse I am doing tests with (`b0003g0001v04d9pa09f-mouse.bpf.c`) exports 3 HID interfaces. If we start randomly changing the incoming bytes, the results can be unexpected.

`udev-hid-bpf` provides a similar functionality than the kernel in the `probe` functionality.

Before loading and attaching any eBPF program to a given HID device, `udev-hid-bpf` executes the syscall `probe` in the `.bpf.c` file if there is any.

The arguments of this syscall are basically the unique id of the HID device, its report descriptor and its report descriptor size.

This way, you can chose whether or not the device should be handled by the `.bpf.c` by changing the ctx field `ctx->retval` to `0`.
