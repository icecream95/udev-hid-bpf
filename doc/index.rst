udev-hid-bpf
============

An automatic HID-BPF loader based on udev events written in Rust. This repository aims to
provide a simple way for users to write a HID-BPF program that fixes their device.


Knowledge of Rust should not be required, it is only used for scaffolding,
users intending to write a HID-BPF program do not need to edit the Rust code and the
resulting BPF programs have no Rust dependencies.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting-started
   device-matches
