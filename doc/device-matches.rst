.. _matching_programs:

Matching eBPF programs to a device
==================================

This tool supports multiple ways of matching a eBPF program to a HID device:

Manual loading
--------------

Users can manually attach a HID-BPF program to a device::

   $ sudo udev-hid-bpf add /sys/bus/hid/devices/0003:05F3:0405 trace_hid_events.bpf.o

Note that the filename doesn't contain the full path. The list of available
programs are in::

   $ ls ./target/bpf/*.bpf.o /lib/firmware/hid/*.bpf.*

Metadata in the HID-BPF sources (modalias matches)
--------------------------------------------------

Each program can tell which devices it is supposed to be bound to.
If those metadata are given, udev will automatically bind the HID-BPF
program to the device on plug.

To do so, add the following metadata to your HID-BPF sources:

.. code-block:: c

   union {
       HID_DEVICE(BBBB, GGGG, 0xVVVV, 0xPPPP);
   } HID_BPF_CONFIG(device_ids)

Where:

- ``BBBB`` is the bus value (in hexadecimal or by using the ``#define`` in ``hid_bpf_helpers.h``)
  (``3`` or ``BUS_USB`` for USB, ``0x18`` or ``BUS_I2C`` for I2C, ``0x5`` or ``BUS_BLUETOOTH`` for Bluetooth, etc...)
- ``GGGG`` is the HID group as detected by HID (again, in hexadecimal or by using one of the ``#define``)
- ``VVVV`` and ``PPPP`` are respectively the vendor ID and product ID (as in ``lsusb``, so hexadecimal is easier too)

For the curious, there is a page on :ref:`metadata` that explains how these metadata are
embedded in the resulting BPF object.

Instead of building this metadata yourself, it is way more efficient to simply use
the ``show-modalias`` tool provided in this repository::

   $ ./tools/show-modalias
   /sys/bus/hid/devices/0003:045E:07A5.0001
     - name:         Microsoft Microsoft® 2.4GHz Transceiver v9.0
     - modalias:     b0003g0001v0000045Ep000007A5
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5)
   /sys/bus/hid/devices/0003:045E:07A5.0002
     - name:         Microsoft Microsoft® 2.4GHz Transceiver v9.0
     - modalias:     b0003g0001v0000045Ep000007A5
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5)
   /sys/bus/hid/devices/0003:045E:07A5.0003
     - name:         Microsoft Microsoft® 2.4GHz Transceiver v9.0
     - modalias:     b0003g0001v0000045Ep000007A5
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5)
   /sys/bus/hid/devices/0003:046D:4088.0009
     - name:         Logitech ERGO K860
     - modalias:     b0003g0102v0000046Dp00004088
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_LOGITECH_DJ_DEVICE, 0x046D, 0x046D)
   /sys/bus/hid/devices/0003:046D:C52B.0004
     - name:         Logitech USB Receiver
     - modalias:     b0003g0001v0000046Dp0000C52B
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0xC52B)
   /sys/bus/hid/devices/0003:046D:C52B.0005
     - name:         Logitech USB Receiver
     - modalias:     b0003g0001v0000046Dp0000C52B
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0xC52B)
   /sys/bus/hid/devices/0003:046D:C52B.0006
     - name:         Logitech USB Receiver
     - modalias:     b0003g0001v0000046Dp0000C52B
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0xC52B)
   /sys/bus/hid/devices/0003:1050:0407.0007
     - name:         Yubico YubiKey OTP+FIDO+CCID
     - modalias:     b0003g0001v00001050p00000407
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x1050, 0x0407)
   /sys/bus/hid/devices/0003:1050:0407.0008
     - name:         Yubico YubiKey OTP+FIDO+CCID
     - modalias:     b0003g0001v00001050p00000407
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x1050, 0x0407)

As shown above, many devices export multiple HID interfaces. See :ref:`run_time_probe` for details
on how to handle this situation.

Alternatively, the modalias of the device is provided by the kernel::

   $ cat /sys/bus/hid/devices/0003:04D9:A09F.0009/modalias
   hid:b0003g0001v000004D9p0000A09F

   $ cat /sys/class/hidraw/hidraw0/device/modalias
   hid:b0003g0001v000004D9p0000A09F

Just strip out the ``hid:`` prefix, extract the bus, group, vid, pid and done.

Sharing the same eBPF program for different devices
---------------------------------------------------

The metadata supports basic globbing features: any of
``BBBB``, ``GGGG``, ``VVVV`` or ``PPPP`` may be the catch all value ``BUS_ANY``,
``HID_GROUP_ANY`` or ``HID_ANY_ID`` (the latter is for ``VVVV`` and ``PPPP``).
Any device that matches all the other fields will thus match. For example
a metadata entry of ``HID_DEVICE(BUS_USB, HID_GROUP_ANY, HID_ANY_ID, HID_ANY_ID)``
will match any USB device.

.. _run_time_probe:

Run-time probe
--------------

Sometimes having just the static modalias is not enough to know if a program needs to be loaded.
For example, one mouse I am doing tests with (``G10-Mechanical-Gaming-Mouse.bpf.c`` with
``HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x04d9, 0xa09f)``) exports 3 HID interfaces,
but the eBPF program only applies to one of those HID interfaces.

``udev-hid-bpf`` provides a similar functionality as the kernel with a ``probe`` function.
Before loading and attaching any eBPF program to a given HID device, ``udev-hid-bpf`` executes the syscall ``probe`` in the ``.bpf.c`` file if there is any.

The arguments of this syscall are basically the unique id of the HID device, its report descriptor and its report descriptor size.
If the eBPF program sets the ``ctx->retval`` to zero, the  eBPF program is loaded for this device. A nonzero value (typically ``-EINVAL``)
prevents the eBPF program from loading. See the ``G10-Mechanical-Gaming-Mouse.bpf.c`` program for an example of this functionality.

Also note that ``probe`` is executed as a ``SEC("syscall")``, which means that the bpf function
``hid_bpf_hw_request()`` is available if you need to configure the device before customizing
it with HID-BPF.
