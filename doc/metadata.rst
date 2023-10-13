.. _metadata:

HID-BPF metadata
================

Overview
--------

The metadata of which device is a target for which bpf program is
stored directly in the bpf resulting object file.

The syntax is the following::

   union {
       HID_DEVICE(BBBB, GGGG, 0xVVVV, 0xPPPP);
   } HID_BPF_CONFIG(device_ids)

Where:

- ``BBBB`` is the bus value (in hexadecimal or by using the ``#define`` in ``hid_bpf_helpers.h``)
  (``3`` or ``BUS_USB`` for USB, ``0x18`` or ``BUS_I2C`` for I2C, ``0x5`` or ``BUS_BLUETOOTH`` for Bluetooth, etc...)
- ``GGGG`` is the HID group as detected by HID (again, in hexadecimal or by using one of the ``#define``)
- ``VVVV`` and ``PPPP`` are respectively the vendor ID and product ID (as in ``lsusb``, so hexadecimal is easier too)

We can also add more than one match::

   union {
       HID_DEVICE(BUS_USB, HID_GROUP_ANY, HID_ANY_ID, HID_ANY_ID);
       HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_ANY, HID_ANY_ID, HID_ANY_ID);
   } HID_BPF_CONFIG(device_ids)

The above metadata will match on any USB or Bluetooth device.

How this is interpreted?
------------------------

The idea of these metadata was borrowed from the `libxdp project <https://github.com/xdp-project/xdp-tools>`_.

The macro ``HID_BPF_CONFIG`` defines a new section in the elf object that is later
parsed by BTF and our ``build.rs`` script when geenrating the hwdb::

   #define COMBINE(X,Y) X ## Y  // helper macro
   #define HID_BPF_CONFIG(f) COMBINE(_, f) SEC(".hid_bpf_config")

So this basically declares a new global variable, that is never instantiated.

The metadata information is then stored in the *type* of this global variable (simplified version)::

   #define HID_DEVICE(b, g, ven, prod)					\
   	struct {							\
   		__uint(bus, (b));	\
   		__uint(group, (g));	\
   		__uint(vid, (ven));	\
   		__uint(pid, (prod));	\
   	}

And each field of this struct here defines an array of length ``n``, where ``n`` is the metadata value.

Because we are using a ``union`` to have multiple matches, we can not have multiple time
``bus`` as an anonymous struct field, so we use the line number as a prefix to have unique
names.

See the ``src/bpf/hid_bpf_helpers.h`` in the repository to see the details.
