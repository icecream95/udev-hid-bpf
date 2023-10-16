.. _tutorial:

Tutorial
========

This tutorial will guide you step-by-step through writing your first HID BPF program.
The assumption is that you have successfully :ref:`compiled and installed <installation>` this repo.

The HID report descriptor for this device is listed in the :ref:`example_report_descriptor`.

Identifying the device
----------------------

Let's assume we have a mouse that needs some fixes, for example a mouse that
keeps sending events for a button that doesn't even exist on the device.

There is a page on :ref:`matching_programs` but for now we'll use the tool::

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
   ...

.. note:: This device has multiple HID interfaces, so we will have to use the
         :ref:`run_time_probe` in our program.


Scaffolding
-----------

Let's create the file and fill it with enough information to compile::

  $ touch ./src/bpf/ignore-button.bpf.c

And this file contains:

.. code-block:: c

  // SPDX-License-Identifier: GPL-2.0-only
  #include "vmlinux.h"
  #include "hid_bpf.h"
  #include "hid_bpf_helpers.h"
  #include <bpf/bpf_tracing.h>

   union {
       HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x045E, 0x07A5);
   } HID_BPF_CONFIG(device_ids)

  SEC("fmod_ret/hid_bpf_rdesc_fixup")
  int BPF_PROG(ignore_button_fix_rdesc, struct hid_bpf_ctx *hctx)
  {
      return 0;
  }

  SEC("fmod_ret/hid_bpf_device_event")
  int BPF_PROG(ignore_button_fix_event, struct hid_bpf_ctx *hid_ctx)
  {
      return 0;
  }

  /* If your device only has a single HID interface you can skip
     the probe function altogether */
  SEC("syscall")
  int probe(struct hid_bpf_probe_args *ctx)
  {
      /* Bind to any device, we don't do anything yet anyway */
      ctx->retval = 0;

      return 0;
  }

  char _license[] SEC("license") = "GPL";

This doesn't do anything but it should be buildable, can be installed and
we can attempt to load it manually::

  $ sudo ./install.sh
  $ sudo udev-hid-bpf --verbose add /sys/bus/hid/devices/0003:045E:07A5.0001 ignore-button.bpf.o
  DEBUG - device added 0003:045E:07A5.0001, filename: target/bpf/ignore-button.bpf.o
  DEBUG - loading BPF object at "target/bpf/ignore-button.bpf.o"
  DEBUG - successfully attached ignore_button_fix_event to device id 1
  DEBUG - Successfully pinned prog at /sys/fs/bpf/hid/0003_045E_07A5_0001/ignore_button_fix_event

Because the BPF program is "pinned" it will remain even after the loading process terminates.
And indeed, the BPF program shows up in the bpffs::

  $ sudo tree /sys/fs/bpf/hid/
    /sys/fs/bpf/hid/
    └── 0003_045E_07A5_0001
        └── ignore_button_fix_event

And we can remove it again (so we can re-add it later)::

  $ sudo udev-hid-bpf --verbose remove /sys/bus/hid/devices/0003:045E:07A5.0001


.. note:: The official tool for listing BPF programs is ``bpftool prog`` which
          will list all currently loaded BPF programs. Our program will be
          listed as ``ignore_button_fix_rdesc`` and/or ``ignore_button_fix_event``.

Probing
-------

.. note:: If your device only has one HID interface you do not need a ``probe``
          function. Feel free to skip this section.

Now, before we do anything we want to make sure our program is only called for
the HID interface we actually want to fix up. Most complex devices
(gaming mice, anything on a receiver, etc.) will expose multiple HID interfaces
and we don't want to change the HID reports on the wrong device. We do this by looking
at the HID report descriptor that is passed to us as a byte array in the ``ctx`` struct:

.. code-block:: c

  struct hid_bpf_probe_args {
    unsigned int hid;
    unsigned int rdesc_size;  /* number of valid bytes */
    unsigned char rdesc[4096]; /* the actual report descriptor */
    int retval;
  };

In our case, we want to operate on the device that has a HID Usage `Generic Desktop, Mouse`
(this particular device has a `Keyboard` and a `Consumer Control`). So our ``probe()``
changes to check exactly that:

.. code-block:: c

  SEC("syscall")
  int probe(struct hid_bpf_probe_args *ctx)
  {
      if (ctx->rdesc_size > 4 &&
          ctx->rdesc[0] == 0x05 && /* Usage Page */
          ctx->rdesc[1] == 0x01 && /* Generic Desktop */
          ctx->rdesc[2] == 0x09 && /* Usage */
          ctx->rdesc[3] == 0x02)   /* Mouse */
          ctx->retval = 0;
      else
          ctx->retval = -22;

      return 0;
  }

.. note:: Use the ``hid-recorder`` tool from `hid-tools <https://gitlab.freedesktop.org/libevdev/hid-tools/>`_.
          to analyze HID report descriptors.

Now, as it turns out we actually stop loading the program now. Why? Because the device
path we provided to the ``udev-hid-bpf`` tool is the Keyboard device, not the Mouse.
Passing in the other interface (with the ``0002`` suffix) works::

  $ sudo udev-hid-bpf --verbose add /sys/bus/hid/devices/0003:045E:07A5.0001 ignore-button.bpf.o
  DEBUG - device added 0003:045E:07A5.0001, filename: /lib/firmware/hid/bpf/ignore-button.bpf.o
  DEBUG - loading BPF object at "/lib/firmware/hid/bpf/ignore-button.bpf.o"

  $ sudo udev-hid-bpf --verbose add /sys/bus/hid/devices/0003:045E:07A5.0002 ignore-button.bpf.o
  DEBUG - device added 0003:045E:07A5.0002, filename: /lib/firmware/hid/bpf/ignore-button.bpf.o
  DEBUG - loading BPF object at "/lib/firmware/hid/bpf/ignore-button.bpf.o"
  DEBUG - successfully attached ignore_button_fix_event to device id 2
  DEBUG - Successfully pinned prog at /sys/fs/bpf/hid/0003_045E_07A5_0002/ignore_button_fix_event

This indicates our probe is working correctly.

Modifying the HID Reports
-------------------------

Now that the program loads for the right device, let's make sure our fake buttons
don't go through. Our device sends a report with ID 26 with 5 bits that represent
the buttons (see the :ref:`example_report_descriptor`). The report is 6 bytes long
(Report ID, button bits, two 16-bit values for x/y). So all we have to do is unset the bit
for the annoying button:

.. code-block:: c

  SEC("fmod_ret/hid_bpf_device_event")
  int BPF_PROG(ignore_button_fix_event, struct hid_bpf_ctx *hid_ctx)
  {
      const int expected_length = 6;
      const int expected_report_id = 26;
      __u8 *data;

      if (hid_ctx->size < expected_length)
          return 0;

      data = hid_bpf_get_data(hid_ctx, 0, expected_length);
      if (!data || data[0] != expected_report_id)
          return 0; /* EPERM or the wrong report ID */

      data[1] &= 0x7; /* Unset all buttons but left/middle/right */

      return 0;
  }

The only noteworthy bit here is that we don't automatically get passed the data
for the HID report, we have to fetch it with ``hid_bpf_get_data(ctx, offset, length)``.
The returned buffer is the kernel buffer, not a copy, so modifications have
near-zero costs.


Modifying the HID Report Descriptor
-----------------------------------

With our code in place we no longer get fake button events. But it would be nice if the
device doesn't even advertise those buttons to begin with. For that we can manipulate the
report descriptor, much in the same way as we manipulated the HID report above:

.. code-block:: c

  SEC("fmod_ret/hid_bpf_rdesc_fixup")
  int BPF_PROG(ignore_button_fix_rdesc, struct hid_bpf_ctx *hctx)
  {
      const int expected_length = 223;
      if (hid_ctx->size != expected_length)
          return 0;

      __u8 *data = hid_bpf_get_data(hid_ctx, 0 /* offset */, 4096 /* size */);
      if (!data)
          return 0; /* EPERM */

      /* Safety check, our probe() should take care of this though */
      if (data[1] != 0x01 /* Generic Desktop */ || data[3] != 0x2 /* Mouse */)
          return 0;

      /* The report descriptor has 5 buttons and 3 pad bits, swap that around.
       * With some minimal safety check to ensure we're on the right HID fields
       * here. */
      if (data[22] == 0x29 && /* Usage Maximum */
          data[24] == 0x95 && /* Report Count */
          data[34] == 0x75) { /* Report Size */
          data[23] = 3; /* Usage Maximum to 3 buttons */
          data[25] = 3; /* Report count to 3 bits */
          data[35] = 5; /* Report size for padding bits to 5 bits */
      }

      return 0;
  }

The ``data`` returned this time is the HID Report Descriptor as an allocated 4K
buffer.

Because we're modifying the HID report descriptor, injecting the BPF program causes
a disconnect of our real HID device and a reconnect of the modified device (see
``dmesg`` or ``udevadm monitor``). Likewise, removing our BPF program causes a
disconnect of the modified device and a reconnect of the real HID device.

Bringing it all together
------------------------

Once the BPF program works as expected, :ref:`installing it <installation>` sets up
the systemd hwdb and the udev rules for the program to be loaded automatically whenever
the device is plugged in. This can be verified by checking wether the
``HID_BPF_n`` property exists on the device::

  $ udevadm info /sys/bus/hid/devices/0003:045E:07A5*
  P: /devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/0003:045E:07A5.0022
  M: 0003:045E:07A5.0022
  R: 0022
  U: hid
  V: hid-generic
  E: DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/0003:045E:07A5.0022
  E: SUBSYSTEM=hid
  E: DRIVER=hid-generic
  E: HID_ID=0003:0000045E:000007A5
  E: HID_NAME=Microsoft Microsoft® 2.4GHz Transceiver v9.0
  E: HID_PHYS=usb-0000:00:14.0-4/input0
  E: HID_UNIQ=
  E: MODALIAS=hid:b0003g0001v0000045Ep000007A5
  E: USEC_INITIALIZED=4768059665
  E: HID_BPF_27=ignore-button.bpf.o

  ...

This property is set by ``udev-hid-bpf``'s hwdb entries and udev rule and if it
exists, plugging/unplugging the device will load or unload the BPF program
for this device.
