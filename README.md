# udev-hid-bpf

An automatic HID-BPF loader based on udev events written in Rust. This repository aims to
provide a simple way for users to write a HID-BPF program that fixes their device. Knowledge of Rust
should not be required.

## Getting started

Our build system uses [meson](https://mesonbuild.com/) which in turn wraps Rust's `cargo`.

```
$ git clone https://gitlab.freedesktop.org/libevdev/udev-hid-bpf.git
$ cd udev-hid-bpf/
$ meson setup builddir/
$ meson compile -C builddir/
$ meson install -C builddir
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

By default, only `testing` is enabled during `meson setup`. To select which one to install, run
`meson configure -Dbpfs=testing,stable,userhacks builddir/` (or a subset
thereof) or pass `-Dbpfs` to the initial `meson setup` call.

To build and install only one specific file use the `-Dfilter-bpf` option. This option takes one or more comma-separated strings,
any `bpf.c` file that contains one of the strings will be installed. For example,
to build and install all BPF files with `Foo` or `Bar` in their file name use `-Dfilter-bpf=Foo,Bar`.
Specifying a filter automatically enables all of testing, stable and userhacks.

Note that all the `bpf.c` files that are known to meson (so registered in `src/bpf/*/meson.build`) are recompiled
when there is a change. So for `bpf/userhacks`, in most cases, no meson option needs to be added: just recompile
with `ninja` and then use `udev-hid-bpf install ./builddir/src/bpf/userhacks/my_awesome_hid_bpf_filter.bpf.c`.
