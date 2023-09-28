Matching eBPF programs to a device
==================================

This tool supports multiple ways of matching a eBPF program to a HID device:

Filename modalias matches
-------------------------

The filename of a HID-BPF program must follow the following syntax::

   bBBBBgGGGGv0000VVVVp0000PPPP-some-identifier.bpf.c

Where:

- ``BBBB`` is the bus raw value (in uppercase hexadecimal) (``0003`` for USB, ``0018`` for I2C, ``0005`` for Bluetooth, etc...)
- ``GGGG`` is the HID group as detected by HID (again, in uppercase hexadecimal)
- ``VVVV`` and ``PPPP`` are respectively the vendor ID and product ID (as in ``lsusb``, so uppercase hexadecimal too)
- ``some-identifier`` is a string aimed at humans to identify what the program does, e.g. ``correct-mouse-button``.

Instead of building this name yourself, it is way more efficient to simply use the
modalias of the device as provided by the kernel::

   $ cat /sys/bus/hid/devices/0003:04D9:A09F.0009/modalias
   hid:b0003g0001v000004D9p0000A09F

   $ cat /sys/class/hidraw/hidraw0/device/modalias
   hid:b0003g0001v000004D9p0000A09F

Just strip out the ``hid:`` prefix and done.

Sharing the same eBPF program for different devices
---------------------------------------------------

The modalias supports basic globbing features: any of
``BBBB``, ``GGGG``, ``VVVV`` or ``PPPP`` may be the literal character ``*``.
Any device that matches all the other fields will thus match. For example
a filename of ``b0003g*v*p*foo.bpf.c`` will match any USB device.

Run-time probe
--------------

Sometimes having just the static modalias is not enough to know if a program needs to be loaded.
For example, one mouse I am doing tests with (``b0003g0001v04d9pa09f-mouse.bpf.c``) exports 3 HID interfaces,
but the eBPF program only applies to one of those HID interfaces.

``udev-hid-bpf`` provides a similar functionality as the kernel with a ``probe`` function.
Before loading and attaching any eBPF program to a given HID device, ``udev-hid-bpf`` executes the syscall ``probe`` in the ``.bpf.c`` file if there is any.

The arguments of this syscall are basically the unique id of the HID device, its report descriptor and its report descriptor size.
If the eBPF program sets the ``ctx->retval`` to zero, the  eBPF program is loaded for this device. A nonzero value (typically ``-EINVAL``)
prevents the eBPF program from loading. See the ``b0003g0001v04d9pa09f-mouse.bpf.c`` program for an example of this functionality.
