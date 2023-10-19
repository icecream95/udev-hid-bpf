.. _metadata:

HID-BPF metadata
================

Overview
--------

The metadata of which device is a target for which bpf program is
stored directly in the bpf resulting object file.

The syntax is the following:

.. code-block:: c

   HID_BPF_CONFIG(
       HID_DEVICE(BBBB, GGGG, 0xVVVV, 0xPPPP)
   );

Where:

- ``BBBB`` is the bus value (in hexadecimal or by using the ``#define`` in ``hid_bpf_helpers.h``)
  (``0x3`` or ``BUS_USB`` for USB, ``0x18`` or ``BUS_I2C`` for I2C, ``0x5`` or ``BUS_BLUETOOTH`` for Bluetooth, etc...)
- ``GGGG`` is the HID group as detected by HID (again, in hexadecimal or by using one of the ``#define``)
- ``VVVV`` and ``PPPP`` are respectively the vendor ID and product ID (as in ``lsusb``, so hexadecimal is easier too)

We can also add more than one match:

.. code-block:: c

   HID_BPF_CONFIG(
       HID_DEVICE(BUS_USB, HID_GROUP_ANY, HID_VID_ANY, HID_PID_ANY),
       HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_ANY, HID_VID_ANY, HID_PID_ANY)
   );

The above metadata will match on any USB or Bluetooth device.

How this is interpreted?
------------------------

The idea of these metadata was borrowed from the `libxdp project <https://github.com/xdp-project/xdp-tools>`_.
See the ``src/bpf/hid_bpf_helpers.h`` in the repository to see the actual macros.

The macro ``HID_BPF_CONFIG`` defines a new section in the ELF object that is later
parsed by BTF and our ``build.rs`` script when generating the hwdb. The actual C code
expands to something like this:

.. code-block:: c

   union {
     /* HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x1234, 0xabcd); */
     struct { int (*bus)[0x3]; int (*group)[0x1]; int (*vid)[0x1234]; int (*pid)[0xabcd] } entry1;
     /* HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_GENERIC, 0x5678, 0xdead); */
     struct { int (*bus)[0x5]; int (*group)[0x1]; int (*vid)[0x5678]; int (*pid)[0xdead] } entry2;
   } _device_ids;

So this declares a global variable that is a union containing a set of structs. Note that the variable is
never actually instantiated, this variable is only used for **introspection** via BTF.

The metadata information is then stored in the *type* of this global variable
(simplified version). During parsing we can iterate through the union and
inspect each field of the struct, including the size of the declared (pointer
to) array. In the above case: because the ``bus`` field is a pointer to an
array of size 3 we know the bus was 0x03 - USB.

See the ``src/bpf/hid_bpf_helpers.h`` in the repository to see the details.
