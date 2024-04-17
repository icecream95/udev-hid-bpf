.. _matching_programs:

Matching BPF programs to a device
==================================

This tool supports multiple ways of matching a BPF program to a HID device:

Manual loading
--------------

Users can manually attach a HID-BPF program to a device::

   $ sudo udev-hid-bpf add /sys/bus/hid/devices/0003:05F3:0405 trace_hid_events.bpf.o
   $ sudo udev-hid-bpf add /sys/bus/hid/devices/0003:05F3:0405 /path/to/my-hack.bpf.o

Note that the filename does not need to be a full path. The list of available
programs can be shown with::

   $ udev-hid-bpf list-bpf-programs

.. note:: If invoked from the git repository, this will show the BPF programs
          in the currently configured lookup directories. Use
          ``udev-hid-bpf list-bpf-programs --bpfdir builddir`` to list the
          programs in the builddir.


Metadata in the HID-BPF sources (modalias matches)
--------------------------------------------------

Each HID-BPF program can tell which devices it is supposed to be bound to.
If those metadata are given, udev will automatically bind the HID-BPF
program to the device on plug.

To do so, add metadata to your HID-BPF sources specifying the **bus**, the
**HID group**, and the **vendor** and **product** IDs. Here's an example of a
BPF program that matches multiple different devices and uses the ``#defines``
in ``hid_bpf_helpers.h``:

.. code-block:: c

   HID_BPF_CONFIG(
       /* A specific Logitech (0x046D) USB device on the generic HID group */
       HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0x1234),

       /* A specific Yubikey (0x1040) USB device on the generic HID group */
       HID_DEVICE(0x3, HID_GROUP_GENERIC, 0x1040, 0x0407),

       /* Any logitech (0x046D) bluetooth device on the generic HID group */
       HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_GENERIC, 0x046D, HID_PID_ANY),

       /* Any i2c device */
       HID_DEVICE(BUS_I2C, HID_GROUP_ANY, HID_VID_ANY, HID_PID_ANY)
   );

As you can see, the arguments to the ``HID_DEVICE`` macro are

- the bus as either numerical value or one of ``BUS_USB``, ``BUS_BLUETOOTH``, ...
- the HID group as either numerical value or one of ``HID_GROUP_GENERIC``, ...
- the vendor ID in hexadecimal (see the ``lsusb`` output)
- the product ID in hexadecimal (see the ``lsusb`` output)

As used in the example above, ``BUS_ANY``, ``HID_GROUP_ANY``, ``HID_VID_ANY``
and ``HID_PID_ANY`` are wildcards.

For the curious, there is a page on :ref:`metadata` that explains how these metadata are
embedded in the resulting BPF object.

The easiest way to obtain the metadata is to use the
``udev-hid-bpf list-devices`` command::

   $ udev-hid-bpf list-devices
   /sys/bus/hid/devices/0003:045E:07A5.0001
     - name:         Microsoft Microsoft® 2.4GHz Transceiver v9.0
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5)
   /sys/bus/hid/devices/0003:045E:07A5.0002
     - name:         Microsoft Microsoft® 2.4GHz Transceiver v9.0
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5)
   /sys/bus/hid/devices/0003:045E:07A5.0003
     - name:         Microsoft Microsoft® 2.4GHz Transceiver v9.0
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5)
   /sys/bus/hid/devices/0003:046D:4088.0009
     - name:         Logitech ERGO K860
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_LOGITECH_DJ_DEVICE, 0x046D, 0x046D)
   /sys/bus/hid/devices/0003:046D:C52B.0004
     - name:         Logitech USB Receiver
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0xC52B)
   /sys/bus/hid/devices/0003:046D:C52B.0005
     - name:         Logitech USB Receiver
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0xC52B)
   /sys/bus/hid/devices/0003:046D:C52B.0006
     - name:         Logitech USB Receiver
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x046D, 0xC52B)
   /sys/bus/hid/devices/0003:1050:0407.0007
     - name:         Yubico YubiKey OTP+FIDO+CCID
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x1050, 0x0407)
   /sys/bus/hid/devices/0003:1050:0407.0008
     - name:         Yubico YubiKey OTP+FIDO+CCID
     - device entry: HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x1050, 0x0407)

As shown above, many devices export multiple HID interfaces. See :ref:`run_time_probe` for details
on how to handle this situation.

Alternatively, the bus, group, vendor ID and product ID (``b``, ``g``, ``v``, ``p``)
can be extracted from the modalias of the device as provided by the kernel::

   $ cat /sys/bus/hid/devices/0003:04D9:A09F.0009/modalias
   hid:b0003g0001v000004D9p0000A09F

   $ cat /sys/class/hidraw/hidraw0/device/modalias
   hid:b0003g0001v000004D9p0000A09F

Just strip out the ``hid:`` prefix, extract the bus, group, vid, pid and done.

Sharing the same BPF program for different devices
---------------------------------------------------

The metadata supports basic globbing features via the special values of ``BUS_ANY``,
``HID_GROUP_ANY``, ``HID_VID_ANY`` or ``HID_PID_ANY``.
Any device that matches all the other fields will thus match. For example
a metadata entry of ``HID_DEVICE(BUS_USB, HID_GROUP_ANY, HID_VID_ANY, HID_PID_ANY)``
will match any USB device.

.. _run_time_probe:

Run-time probe
--------------

Sometimes having just the vendor/product ID is not enough to know if a program needs to be loaded.
For example, one mouse I am doing tests with (``mouse_invert_y.bpf.c`` with
``HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x04d9, 0xa09f)``) exports 3 HID interfaces,
but the BPF program only applies to one of those HID interfaces.

``udev-hid-bpf`` provides a similar functionality as the kernel with a ``probe`` function.
Before loading and attaching any BPF program to a given HID device, ``udev-hid-bpf`` executes the syscall ``probe`` in the ``.bpf.c`` file if there is any.

.. code-block:: c

  SEC("syscall")
  int probe(struct hid_bpf_probe_args *ctx)
  {
      /* zero if we want to bind, nonzero otherwise*/
      ctx->retval = 0;

      return 0;
  }

The arguments of this syscall are basically the unique id of the HID device, its report descriptor and its report descriptor size:


.. code-block:: c

  struct hid_bpf_probe_args {
    unsigned int hid;
    unsigned int rdesc_size;  /* number of valid bytes */
    unsigned char rdesc[4096]; /* the actual report descriptor */
    int retval;
  };

If the BPF program sets the ``ctx->retval`` to zero, the  BPF program is loaded for this device. A nonzero value (typically ``-EINVAL``)
prevents the BPF program from loading. See the
``mouse_invert_y.bpf.c`` program for an example of this
functionality or the :ref:`tutorial_probe` section of the :ref:`tutorial`.

Also note that ``probe`` is executed as a ``SEC("syscall")``, which means that the bpf function
``hid_bpf_hw_request()`` is available if you need to configure the device before customizing
it with HID-BPF.
