udev-hid-bpf
============

An automatic HID-BPF loader based on udev events. This repository aims to
provide a simple way for users to write a HID-BPF program that fixes their
device.

See :ref:`how_it_works` for details on how everything fits together.

This project is written in Rust but knowledge of Rust should not be required,
it is only used for scaffolding. Users intending to write a HID-BPF program do
not need to edit the Rust code and the resulting BPF programs have no Rust
dependencies.

The BPF programs themselves are in C.

Project home page
-----------------

``udev-hid-bpf`` is hosted on https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/

To file an issue please go to `our issue tracker <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/issues>`_.

License
-------

``udev-hid-bpf`` is licensed under the `GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>`_ license.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   how-it-works
   getting-started
   tutorial
   filename-conventions
   stable-testing-userhacks
   device-matches
   metadata
   udev-properties
   report-descriptor-macros
