:orphan:

.. _hid_primer:

An overview of HID
==================

Most input devices today are HID devices (HID can be used over USB, Bluetooth, etc.).
HID devices have two packets of information that get exchanged between the host
and the device. The two main components of HID are **HID Reports** and the
**HID Report Descriptor**.
The `HID Protocol
Specification <https://www.usb.org/sites/default/files/hid1_11.pdf>`_ is
publicly accessible, this page is a short primer on understanding the
high-level concepts.

HID is little endian, i.e. a 16-bit field shown as ``00 ff`` in the various
outputs below is of value ``0xff00``.

In the kernel, the HID core subsystem is typically responsible for converting
HID events into evdev devices and events. In many cases a single HID device is
split into several evdev input devices with a suffixed (e.g. "Mouse",
"Keyboard", "Pen", "Finger").

A single physical device may provide multiple HID devices which then get multiple
evdev node - it is common that plugging in one device results in four or five
evdev nodes.

.. _hid_primer_reports:

HID Reports
-----------

HID Reports are arrays of bytes that represent dynamic data to exchange. They
come in three different forms:

- **Input Reports** are sent from the device to the host, i.e. input events
- **Output Reports** are sent from the host to the device. These are used to
  e.g. toggle LED state on the device.
- **Feature Reports** are used to configure on-device features. These are
  bidirectional and typically the host reads the current state and then sends
  the modified state back to the device. This is used e.g. in gaming mice to
  change the resolution.

A device may provide multiple HID Reports. For example, it is common for
multifunctional devices to send pointer data through one HID Input Report and
keyboard data through a different HID Input Report.

Each HID Report is a simple array of bytes with a fixed length though
different HID Reports may have a different length. If more than one HID Report
is available on the device, the first byte is always the HID Report ID.
Unfortunately, the HID Report ID is unique only for the current type of report and
a device may have an input and output report with the same ID but different
layouts.

A typical HID Input Report may look like this::

   [ Report ID | modifier state | key | key | key | key ]
   [ Report ID | x | y | button state | wheel | horiz wheel ]

Only the HID Report ID is guaranteed to be the first byte, all other values may
be of any length and in any position. To know which bytes (or bits) contain
which information a host must parse the :ref:`hid_primer_report_descriptor`.

.. _hid_primer_report_descriptor:

HID Report Descriptor
---------------------

As mentioned in :ref:`hid_primer_reports`, a host must parse the
the HID Report Descriptor to know which reports are available and
what data is contained in each report. The blog post
`Understanding HID
Report Descriptors <https://who-t.blogspot.com/2018/12/understanding-hid-report-descriptors.html>`_
describes how the parsing works in more detail, this page provides
the high-level concepts only.

The HID Report Descriptor is a fixed array of bytes comprised of HID Fields that
are parsed in sequence and together describe which bit in a HID Report represents
a particular value. For example, the outcome of such parsing may be the equivalent
of "bits 8-15 are the X axis with has a logical range of -127 to 127".

A convenient tool to look at HID Report Descriptors is
`hid-recorder <https://github.com/hidutils/hid-recorder>`_.

A field that results in a full description of an item in the HID Report typically
has at least:
- a Report Size in bits
- a Report Count
- one or more Usages (comprised of Usage Page | Usage ID)
- a logical minimum and maximum to specify what ranges we can expect

A HID Report Descriptor is a stack, pushing a field on the
stack means it applies to subsequent fields until it is popped off the stack.
When this happens depends on the HID Field, see the `HID Protocol
Specificiation <https://www.usb.org/sites/default/files/hid1_11.pdf>`_ for
details.

For example a pair of x/y axes may appear as this::

    Usage Page (Generic Desktop)
    Usage (X)
    Usage (Y)
    Logical Minimum (-32768)
    Logical Maximum (32767)
    Report Size (16)
    Report Count (2)
    Input (Data,Var,Rel)

Here the device declares that subsequent fields have the :ref:`hid_primer_hut`
usage `Generic Desktop / X` and `Generic Desktop / Y`, with two specified
minimum/maximum values. Each field is 16 bits long and we have 2 fields
followed by the ``Input`` field which "pops" the stack and causes the
current state to apply to the current HID Input report. We thus end up knowing
what the next 4 bytes in the current HID Report are. In this case ``Input``
also specifies that the data is a relative value.

.. note:: The HID Report Descriptor describes items sequentially per
          report. A parser must maintain the correct bit offset in
          the current report.

For example a set of 5 bits representing 5 buttons would appear as this::

    Usage Page (Button)
    UsageMinimum (1)
    UsageMaximum (5)
    Logical Minimum (0)
    Logical Maximum (1)
    Report Count (5)
    Report Size (1)
    Input (Data,Var,Abs)

This describes the next usages as going from `Button / 1` to `Button / 5`, each
with a logical zero or one state. The report size is 1 bit per item and we have
5 items. These items again are ``Input``, i.e. in the current HID Input Report but
this time they're absolute, not relative.

Each HID Report Descriptor may describe multiple HID Reports.


.. _hid_primer_hut:

HID Usage Tables
----------------

The HID Usage Tables (HUT) are effectively a large datase that maps the
numerical values in the HID Report Descriptor for Usage Pages and Usage IDs
to the respective semantic value. They allow a HID Report Descriptor
parser to look up e.g. Usage Page ``0x01`` / Usage ID ``0x30`` and resolve it
to ``Generic Desktop / X``

The most recent specification is `HID Usage v1.5 <https://usb.org/sites/default/files/hut1_5.pdf>`_.


.. _hid_primer_vendor_usages:

Vendor-defined Usages
.....................

A special case within the HUT are the ``Vendor Defined Usage Pages``, each containing
a set of ``Vendor Defined Usage ID``. This is HID's approach to allow for proprietary
data to be sent from or to the device that cannot be interpreted by the kernel without
a custom parser, specifically for this device.

For example, a device may have a HID Report Descriptor like this::

  Usage Page (Vendor Defined Page 0xFF00)
  Usage (Vendor Usage 0x01)
  Collection (Application)
    Report ID (8)
    Report Size (88)
    Report Count (1)
    Usage (Vendor Usage 0x01)
    Input (Data,Var,Abs)
  End Collection

There is nothing to know about this HID Report other than that it is 12 bytes
(88 bits) long. Without knowing what those bits represent we cannot extract information
from it. As a result, the kernel simply ignores any vendor-defined reports or
vendor-defined fields within reports.
