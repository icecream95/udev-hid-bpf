.. _how_it_works:

How it works
============

Below is a high-level overview of how HID-BPF works and how ``udev-hid-bpf``
enables us to take advantage of it immediately on plug-in.

Note that the udev-hid-bpf repository contains there distinct components:

- ``udev-hid-bpf`` the binary that loads HID-BPF programs
- A set of HID-BPF programs (see the ``src/bpf`` directory)
- Scaffolding to automate loading of HID-BPF programs via udev.

How HID-BPF works
-----------------

HID-BPF is a feature available in kernels 6.3 and newer.

Most input devices today are HID devices (HID can be used over USB, Bluetooth, etc.).
HID devices have two packets of information that get exchanged between the host
and the device: the HID Report Descriptor and HID Reports. Both are simply arrays
of bytes, the HID Report Descriptor describes how the bytes in HID Reports can
be interpreted - it will effectively say e.g "bit 8 is button left" or "bits
9-16 is a relative x axis". The HID Report Descriptor is static for a device and
only exchanged once.

HID Reports are the actual events. Reports can be input reports (device to
host, i.e. an event), output reports (host to device, e.g. setting an LED) and
feature report (bidirectional, for on-device-configuration). The following only
focuses on input reports but the same applies to output and feature reports.
See :ref:`hid_primer` for more details.

HID-BPF is a kernel feature that allows inserting an eBPF program that can change
the data that is exchanged between the host and the device.

Typically, a report by the device is sent as-is to the kernel
(``hid-generic`` is the recipient driver in virtually all cases)::

    device: [ab|12|cd|34] -------------------------------> [kernel]

But where a HID BPF program is loaded for that device, that program
can change the data before it arrives at the kernel driver::

    device: [ab|12|cd|34] ----->[HID BPF program]
                                        |
                                        v
                                  [ab|99|cd|34]----------> [kernel]

This applies to both HID Report Descriptors and to HID Reports. In other words,
the BPF program can either change the data itself (e.g. "changing y to -y")
or it can change how the data is interpreted (e.g. change "bits 1/2/3 are buttons
left/middle/right" to "bits 1/2/3 are buttons right/middle/left").

How udev-hid-bpf works
----------------------

``udev-hid-bpf`` - the binary - works similar to ``modprobe`` or ``insmod``. It opens
a given ``.bpf.o`` compiled BPF object file and loads it for the given device.

The binary can be invoked manually but in most cases we will trigger it via udev.

During ``meson compile`` we generate udev rules and hwdb entries that tells us
which of our BPF object files matches which device. For example, such a hwdb
entry may look like this::

    hid-bpf:hid:b0003g0001v000024AEp00002015
      HID_BPF_T_002=0009-Rapoo__M50-Plus-Silent.bpf.o

Together with our udev rule this hwdb entry means that if a device with the
``0x24AE`` vendor ID and ``0x2015`` product ID is plugged in, the udev property
``HID_BPF_T_002`` (ignore the weird name) is set to the value
``0009-Rapoo__M50-Plus-Silent.bpf.o``.

Our udev rule also calls ``udev-hid-bpf`` for every device with such a property
set and ``udev-hid-bpf`` will thus load the ``0009-Rapoo__M50-Plus-Silent.bpf.o``
BPF object file for the newly plugged-in HID device.

In summary, our flow is:

   1. HID device is plugged in, udev runs its rules
   2. our udev rule runs the hwdb builtin for the device's modalias

      * the hwdb builtin sets the udev properties ``HID_BPF_...`` if there is a match
   3. our udev rule runs the ``udev-hid-bpf`` binary if there is a ``HID_BPF...`` property

      * ``udev-hid-bpf`` loads the BPF program for the device
   4. device sends HID reports, altered by BPF if applicable
