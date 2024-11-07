:orphan:

.. _huion_k20:

Implementing support for the Huion KeyDial K20
===============================================

This is step-by-step guide on how to get a new device running. In this case
the `Huion KeyDial K20 <https://store.huion.com/products/huion-keydial-mini>`_.
This device is a TV-remote-like device without a Pen. If you read along you too
should then be able to get a similar device working with udev-hid-bpf.
The merge request for this device is
`udev-hid-bpf MR!158 <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/merge_requests/158>`_.

Our goal is to fix the HID Reports and/or HID Report
Descriptors via udev-hid-bpf so that the kernel does the right thing
automatically, without needing a special kernel driver.

You will need some understanding of the HID protocol, see :ref:`hid_primer`.

.. note:: This tutorial was written in November 2024 and will not be updated
          for API changes. It's intention is to guide users into **understanding**
          how to implement device support, not to be a template.

.. contents:: Table of Contents

Prerequisites
-------------

The tools you will need installed to follow along with this tutorial are:

- kernel 6.3+ for udev-hid-bpf to work
- `hid-recorder <https://github.com/hidutils/hid-recorder>`_ - for looking at HID Reports
- `libinput record <https://gitlab.freedesktop.org/libinput/libinput.git>`_ - for looking at
  kernel evdev data for a device
- `huion-switcher <https://github.com/whot/huion-switcher>`_ - for switching a Huion tablet
  into vendor mode
- `udev-hid-bpf <https://gitlab.freedesktop.org/libevev/udev-hid-bpf.git>`_
  from git - for adding a new BPF to support this device
- `libwacom <https://github.com/linuxwacom/libwacom>`_ from git - for adding
  our device to its database

Follow the instructions in each repository on how to install the tools or grab
them from your distribution packages. In the case of udev-hid-bpf and libwacom
we want the git repos since we'll be adding our support for it.

Things to know about Huion devices
----------------------------------

Huion tablets have two modes that we'll call "firmware mode" and "vendor mode".
Firmware mode is the default after plugging in the device and is designed for
maximum usefulness without operating system support. Vendor mode requires
switching the device and provides more accurate data but needs operating system
support to interpret the data from the device.

Huion re-used USB product IDs (PIDs) between different devices so any device with a
PID of ``0x6d``, ``0x6e`` or ``0x6f`` cannot be uniquely identified
via the PID alone. To correctly identify devices with those PIDs libwacom
requires that the ``UNIQ`` udev property is set to the firmware version.  The
6.10 kernel ``hid-uclogic`` driver does this automatically for devices
supported by that driver. The `huion-switcher <https://github.com/whot/huion-switcher>`_
tool can set that property too.

Analysing the HID report descriptors
------------------------------------

Let's plug in the K20 and check what hid-recorder shows us::

    $ sudo hid-recorder
    # Available devices:
    # /dev/hidraw0:     ELAN Touchscreen
    # /dev/hidraw1:     HUION Huion Keydial_K20
    # /dev/hidraw2:     HUION Huion Keydial_K20
    # /dev/hidraw3:     HUION Huion Keydial_K20
    # Select the device event number [0-9]:

Huion devices always export three hidraw nodes. Let's have a look at the first
one::

    $ sudo hid-recorder /dev/hidraw1
    # HUION Huion Keydial_K20
    # Report descriptor length: 18 bytes
    #   0x06, 0x00, 0xff,              // Usage Page (Vendor Defined Page 0xFF00)   0
    #   0x09, 0x01,                    // Usage (Vendor Usage 0x01)                 3
    #   0xa1, 0x01,                    // Collection (Application)                  5
    # ┅ 0x85, 0x08,                    //   Report ID (8)                           7
    #   0x75, 0x58,                    //   Report Size (88)                        9
    #   0x95, 0x01,                    //   Report Count (1)                        11w
    #   0x09, 0x01,                    //   Usage (Vendor Usage 0x01)               13
    # ┇ 0x81, 0x02,                    //   Input (Data,Var,Abs)                    15
    #   0xc0,                          // End Collection                            17
    R: 18 06 00 ff 09 01 a1 01 85 08 75 58 95 01 09 01 81 02 c0
    N: HUION Huion Keydial_K20
    I: 3 256c 69
    # Report descriptor:
    # ------- Input Report -------
    # ░ Report ID: 8
    # ░  | Report size: 96 bits
    # ░ Bits:   8..=95  Usage: ff00/0001: Vendor Defined Usage ff00 / 0001            Logical Range:     0..=0
    ##############################################################################
    # Recorded events below in format:
    # E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]
    #

The ``I:`` line tells us the device ID: here we can see that we have a
USB (``0x3``) with a vendor ID (VID) of ``0x256c`` and a product ID (PID) of ``0x69``.
The ``0x69`` is (as of writing this) a unique PID.

This report descriptor is for the "vendor mode" reports of the device. It
merely says that "reports are 12 bytes long with vendor-private data" - such
reports are ignored by the kernel.  However, until the device is switched into
vendor mode no such reports are sent anyway.

There are two other hidraw nodes so let's look at those::

    $ sudo hid-recorder /dev/hidraw2
    # HUION Huion Keydial_K20
    # Report descriptor length: 135 bytes
    #   0x05, 0x01,                    // Usage Page (Generic Desktop)              0
    #   0x09, 0x06,                    // Usage (Keyboard)                          2
    #   0xa1, 0x01,                    // Collection (Application)                  4
    # ┅ 0x85, 0x03,                    //   Report ID (3)                           6
    #   0x05, 0x07,                    //   Usage Page (Keyboard/Keypad)            8
    #   0x19, 0xe0,                    //   UsageMinimum (224)                      10
    #   0x29, 0xe7,                    //   UsageMaximum (231)                      12
    #   0x15, 0x00,                    //   Logical Minimum (0)                     14
    #   0x25, 0x01,                    //   Logical Maximum (1)                     16
    #   0x75, 0x01,                    //   Report Size (1)                         18
    #   0x95, 0x08,                    //   Report Count (8)                        20
    # ┇ 0x81, 0x02,                    //   Input (Data,Var,Abs)                    22
    #   0x05, 0x07,                    //   Usage Page (Keyboard/Keypad)            24
    #   0x19, 0x00,                    //   UsageMinimum (0)                        26
    #   0x29, 0xff,                    //   UsageMaximum (255)                      28
    #   0x26, 0xff, 0x00,              //   Logical Maximum (255)                   30
    #   0x75, 0x08,                    //   Report Size (8)                         33
    #   0x95, 0x06,                    //   Report Count (6)                        35
    # ┇ 0x81, 0x00,                    //   Input (Data,Arr,Abs)                    37
    #   0xc0,                          // End Collection                            39
    #   0x05, 0x0c,                    // Usage Page (Consumer)                     40
    #   0x09, 0x01,                    // Usage (Consumer Control)                  42
    #   0xa1, 0x01,                    // Collection (Application)                  44
    # ┅ 0x85, 0x04,                    //   Report ID (4)                           46
    #   0x05, 0x0c,                    //   Usage Page (Consumer)                   48
    #   0x19, 0x00,                    //   UsageMinimum (0)                        50
    #   0x2a, 0x80, 0x03,              //   UsageMaximum (896)                      52
    #   0x15, 0x00,                    //   Logical Minimum (0)                     55
    #   0x26, 0x80, 0x03,              //   Logical Maximum (896)                   57
    #   0x75, 0x10,                    //   Report Size (16)                        60
    #   0x95, 0x01,                    //   Report Count (1)                        62
    # ┇ 0x81, 0x00,                    //   Input (Data,Arr,Abs)                    64
    #   0xc0,                          // End Collection                            66
    #   0x05, 0x01,                    // Usage Page (Generic Desktop)              67
    #   0x09, 0x02,                    // Usage (Mouse)                             69
    #   0xa1, 0x01,                    // Collection (Application)                  71
    #   0x09, 0x01,                    //   Usage (Pointer)                         73
    # ┅ 0x85, 0x05,                    //   Report ID (5)                           75
    #   0xa1, 0x00,                    //   Collection (Physical)                   77
    #   0x05, 0x09,                    //     Usage Page (Button)                   79
    #   0x19, 0x01,                    //     UsageMinimum (1)                      81
    #   0x29, 0x05,                    //     UsageMaximum (5)                      83
    #   0x15, 0x00,                    //     Logical Minimum (0)                   85
    #   0x25, 0x01,                    //     Logical Maximum (1)                   87
    #   0x95, 0x05,                    //     Report Count (5)                      89
    #   0x75, 0x01,                    //     Report Size (1)                       91
    # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                  93
    #   0x95, 0x01,                    //     Report Count (1)                      95
    #   0x75, 0x03,                    //     Report Size (3)                       97
    # ┇ 0x81, 0x01,                    //     Input (Cnst,Arr,Abs)                  99
    #   0x05, 0x01,                    //     Usage Page (Generic Desktop)          101
    #   0x09, 0x30,                    //     Usage (X)                             103
    #   0x09, 0x31,                    //     Usage (Y)                             105
    #   0x16, 0x00, 0x80,              //     Logical Minimum (-32768)              107
    #   0x26, 0xff, 0x7f,              //     Logical Maximum (32767)               110
    #   0x75, 0x10,                    //     Report Size (16)                      113
    #   0x95, 0x02,                    //     Report Count (2)                      115
    # ┇ 0x81, 0x06,                    //     Input (Data,Var,Rel)                  117
    #   0x95, 0x01,                    //     Report Count (1)                      119
    #   0x75, 0x08,                    //     Report Size (8)                       121
    #   0x05, 0x01,                    //     Usage Page (Generic Desktop)          123
    #   0x09, 0x38,                    //     Usage (Wheel)                         125
    #   0x15, 0x81,                    //     Logical Minimum (-127)                127
    #   0x25, 0x7f,                    //     Logical Maximum (127)                 129
    # ┇ 0x81, 0x06,                    //     Input (Data,Var,Rel)                  131
    #   0xc0,                          //   End Collection                          133
    #   0xc0,                          // End Collection                            134
    R: 135 05 01 09 06 a1 01 85 03 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 05 07 19 00 29 ff 26 ff 00 75 08 95 06 81 00 c0 05 0c 09 01 a1 01 85 04 05 0c 19 00 2a 80 03 15 00 26 80 03 75 10 95 01 81 00 c0 05 01 09 02 a1 01 09 01 85 05 a1 00 05 09 19 01 29 05 15 00 25 01 95 05 75 01 81 02 95 01 75 03 81 01 05 01 09 30 09 31 16 00 80 26 ff 7f 7510 95 02 81 06 95 01 75 08 05 01 09 38 15 81 25 7f 81 06 c0 c0
    N: HUION Huion Keydial_K20
    I: 3 256c 69
    # Report descriptor:
    # ------- Input Report -------
    # ▓ Report ID: 3
    # ▓  | Report size: 64 bits
    # ▓ Bit:    8       Usage: 0007/00e0: Keyboard/Keypad / Keyboard LeftControl      Logical Range:     0..=1
    # ▓ Bit:    9       Usage: 0007/00e1: Keyboard/Keypad / Keyboard LeftShift        Logical Range:     0..=1
    # ▓ Bit:   10       Usage: 0007/00e2: Keyboard/Keypad / Keyboard LeftAlt          Logical Range:     0..=1
    # ▓ Bit:   11       Usage: 0007/00e3: Keyboard/Keypad / Keyboard Left GUI         Logical Range:     0..=1
    # ▓ Bit:   12       Usage: 0007/00e4: Keyboard/Keypad / Keyboard RightControl     Logical Range:     0..=1
    # ▓ Bit:   13       Usage: 0007/00e5: Keyboard/Keypad / Keyboard RightShift       Logical Range:     0..=1
    # ▓ Bit:   14       Usage: 0007/00e6: Keyboard/Keypad / Keyboard RightAlt         Logical Range:     0..=1
    # ▓ Bit:   15       Usage: 0007/00e7: Keyboard/Keypad / Keyboard Right GUI        Logical Range:     0..=1
    # ▓ Bits:  16..=63  Usages:                                                       Logical Range:     0..=255
    # ▓                 0007/0000: <unknown>
    # ▓                 0007/0001: Keyboard/Keypad / ErrorRollOver
    # ▓                 0007/0002: Keyboard/Keypad / POSTFail
    # ▓                 0007/0003: Keyboard/Keypad / ErrorUndefined
    # ▓                 0007/0004: Keyboard/Keypad / Keyboard A
    # ▓                 ... use --full to see all usages
    # ------- Input Report -------
    # ▚ Report ID: 4
    # ▚  | Report size: 24 bits
    # ▚ Bits:   8..=23  Usages:                                                Logical Range:     0..=896
    # ▚                 000c/0000: <unknown>
    # ▚                 000c/0001: Consumer / Consumer Control
    # ▚                 000c/0002: Consumer / Numeric Key Pad
    # ▚                 000c/0003: Consumer / Programmable Buttons
    # ▚                 000c/0004: Consumer / Microphone
    # ▚                 ... use --full to see all usages
    # ------- Input Report -------
    # ▞ Report ID: 5
    # ▞  | Report size: 56 bits
    # ▞ Bit:    8       Usage: 0009/0001: Button / Button 1                           Logical Range:     0..=1
    # ▞ Bit:    9       Usage: 0009/0002: Button / Button 2                           Logical Range:     0..=1
    # ▞ Bit:   10       Usage: 0009/0003: Button / Button 3                           Logical Range:     0..=1
    # ▞ Bit:   11       Usage: 0009/0004: Button / Button 4                           Logical Range:     0..=1
    # ▞ Bit:   12       Usage: 0009/0005: Button / Button 5                           Logical Range:     0..=1
    # ▞ Bits:  13..=15  ######### Padding
    # ▞ Bits:  16..=31  Usage: 0001/0030: Generic Desktop / X                         Logical Range: -32768..=32767
    # ▞ Bits:  32..=47  Usage: 0001/0031: Generic Desktop / Y                         Logical Range: -32768..=32767
    # ▞ Bits:  48..=55  Usage: 0001/0038: Generic Desktop / Wheel                     Logical Range:  -127..=127
    ##############################################################################
    # Recorded events below in format:
    # E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]
    #

Note the summary printed by hid-recorder: we have 3 different input reports,

  - Report ID 3 is like a keyboard with modifiers
  - Report ID 4 is a bitmask of of consumer control buttons
  - Report ID 5 is like a mouse with 5 buttons and a wheel.


Finally we have a third hidraw node::

    $ sudo hid-recorder /dev/hidraw3
    # HUION Huion Keydial_K20
    # Report descriptor length: 108 bytes
    #   0x05, 0x01,                    // Usage Page (Generic Desktop)              0
    #   0x09, 0x0e,                    // Usage (System Multi-Axis Controller)      2
    #   0xa1, 0x01,                    // Collection (Application)                  4
    # ┅ 0x85, 0x11,                    //   Report ID (17)                          6
    #   0x05, 0x0d,                    //   Usage Page (Digitizers)                 8
    #   0x09, 0x21,                    //   Usage (Puck)                            10
    #   0xa1, 0x02,                    //   Collection (Logical)                    12
    #   0x15, 0x00,                    //     Logical Minimum (0)                   14
    #   0x25, 0x01,                    //     Logical Maximum (1)                   16
    #   0x75, 0x01,                    //     Report Size (1)                       18
    #   0x95, 0x01,                    //     Report Count (1)                      20
    #   0xa1, 0x00,                    //     Collection (Physical)                 22
    #   0x05, 0x09,                    //       Usage Page (Button)                 24
    #   0x09, 0x01,                    //       Usage (Button 1)                    26
    # ┇ 0x81, 0x02,                    //       Input (Data,Var,Abs)                28
    #   0x05, 0x0d,                    //       Usage Page (Digitizers)             30
    #   0x09, 0x33,                    //       Usage (Touch)                       32
    # ┇ 0x81, 0x02,                    //       Input (Data,Var,Abs)                34
    #   0x95, 0x06,                    //       Report Count (6)                    36
    # ┇ 0x81, 0x03,                    //       Input (Cnst,Var,Abs)                38
    #   0xa1, 0x02,                    //       Collection (Logical)                40
    #   0x05, 0x01,                    //         Usage Page (Generic Desktop)      42
    #   0x09, 0x37,                    //         Usage (Dial)                      44
    #   0x16, 0x00, 0x80,              //         Logical Minimum (-32768)          46
    #   0x26, 0xff, 0x7f,              //         Logical Maximum (32767)           49
    #   0x75, 0x10,                    //         Report Size (16)                  52
    #   0x95, 0x01,                    //         Report Count (1)                  54
    # ┇ 0x81, 0x06,                    //         Input (Data,Var,Rel)              56
    #   0x35, 0x00,                    //         Physical Minimum (0)              58
    #   0x46, 0x10, 0x0e,              //         Physical Maximum (3600)           60
    #   0x15, 0x00,                    //         Logical Minimum (0)               63
    #   0x26, 0x10, 0x0e,              //         Logical Maximum (3600)            65
    #   0x09, 0x48,                    //         Usage (Resolution Multiplier)     68
    # ║ 0xb1, 0x02,                    //         Feature (Data,Var,Abs)            70
    #   0x45, 0x00,                    //         Physical Maximum (0)              72
    #   0xc0,                          //       End Collection                      74
    #   0x75, 0x08,                    //       Report Size (8)                     75
    #   0x95, 0x01,                    //       Report Count (1)                    77
    # ┇ 0x81, 0x01,                    //       Input (Cnst,Arr,Abs)                79
    #   0x75, 0x08,                    //       Report Size (8)                     81
    #   0x95, 0x01,                    //       Report Count (1)                    83
    # ┇ 0x81, 0x01,                    //       Input (Cnst,Arr,Abs)                85
    #   0x75, 0x08,                    //       Report Size (8)                     87
    #   0x95, 0x01,                    //       Report Count (1)                    89
    # ┇ 0x81, 0x01,                    //       Input (Cnst,Arr,Abs)                91
    #   0x75, 0x08,                    //       Report Size (8)                     93
    #   0x95, 0x01,                    //       Report Count (1)                    95
    # ┇ 0x81, 0x01,                    //       Input (Cnst,Arr,Abs)                97
    #   0x75, 0x08,                    //       Report Size (8)                     99
    #   0x95, 0x01,                    //       Report Count (1)                    101
    # ┇ 0x81, 0x01,                    //       Input (Cnst,Arr,Abs)                103
    #   0xc0,                          //     End Collection                        105
    #   0xc0,                          //   End Collection                          106
    #   0xc0,                          // End Collection                            107
    R: 108 05 01 09 0e a1 01 85 11 05 0d 09 21 a1 02 15 00 25 01 75 01 95 01 a1 00 05 09 09 01 81 02 05 0d 09 33 81 02 95 06 81 03 a1 02 05 01 09 37 16 00 80 26 ff 7f 75 10 95 01 81 06 35 00 46 10 0e 15 00 26 10 0e 09 48 b1 02 45 00 c0 75 08 95 01 81 01 75 08 95 01 81 01 75 08 95 01 81 01 75 08 95 01 81 01 75 08 95 01 81 01 c0 c0 c0
    N: HUION Huion Keydial_K20
    I: 3 256c 69
    # Report descriptor:
    # ------- Input Report -------
    # ▓ Report ID: 17
    # ▓  | Report size: 72 bits
    # ▓ Bit:    8       Usage: 0009/0001: Button / Button 1                           Logical Range:     0..=1
    # ▓ Bit:    9       Usage: 000d/0033: Digitizers / Touch                          Logical Range:     0..=1
    # ▓ Bits:  10..=15  ######### Padding
    # ▓ Bits:  16..=31  Usage: 0001/0037: Generic Desktop / Dial                      Logical Range: -32768..=32767
    # ▓ Bits:  32..=39  ######### Padding
    # ▓ Bits:  40..=47  ######### Padding
    # ▓ Bits:  48..=55  ######### Padding
    # ▓ Bits:  56..=63  ######### Padding
    # ▓ Bits:  64..=71  ######### Padding
    # ------- Feature Report -------
    # ▓ Report ID: 17
    # ▓  | Report size: 24 bits
    # ▓ Bits:   8..=23  Usage: 0001/0048: Generic Desktop / Resolution Multiplier     Logical Range:     0..=3600  Physical Range:     0..=3600
    ##############################################################################
    # Recorded events below in format:
    # E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]


The summary here shows we have one button and a dial but also a "touch" bit. That is in part
so it gets detected correctly as tablet. What also matters here is that the report descriptor
specifies ``Usage Page (Digitizers)/Usage (Puck)``. A "puck" is a special mouse
that only works on top of Wacom tablets - they haven't been produced in a long time
but userspace support for it has existed for decades so claiming to be a puck
means a better out-of-the-box experience.


.. note:: If this was a normal tablet instead of a TV-remote-like device the
          puck hidraw node would be ``Usage Page (Digitizers)/Usage (Stylus)`` and
          represent the pen events.

Let's summarise what we have found so far:

- a HID device with a vendor-private HID report (ignored by the kernel)
- a HID device with reports that make it look like a keyboard and a mouse
- a HID device with reports that look like a tablet puck


Analyzing the HID Reports in firmware mode
------------------------------------------

Let's observe some HID Reports (i.e. events) from the device.
Pressing and releasing the top-left button on the numpad-like set produces this::

    $ sudo hid-recorder /dev/hidraw2
    ...
    # ▓  Report ID: 3 /
    # ▓               Keyboard LeftControl:     0 |Keyboard LeftShift:     0 |Keyboard LeftAlt:     0 |Keyboard Left GUI:     0 |
    #                 Keyboard RightControl:     0 |Keyboard RightShift:     0 |Keyboard RightAlt:     0 |Keyboard Right GUI:     0 |
    #                 Keyboard K:    14| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0
    E: 000000.000231 8 03 00 0e 00 00 00 00 00
    # ▓  Report ID: 3 /
    # ▓               Keyboard LeftControl:     0 |Keyboard LeftShift:     0 |Keyboard LeftAlt:     0 |Keyboard Left GUI:     0 |
    #                 Keyboard RightControl:     0 |Keyboard RightShift:     0 |Keyboard RightAlt:     0 |Keyboard Right GUI:     0 |
    #                 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0
    E: 000000.033629 8 03 00 00 00 00 00 00 00


As per above, hidraw2's report ID 3 is basically a keyboard with modifiers.
Modifiers are 1 bit per modifier and then we have 6 bytes for actual keys
(suggesting we could have up to 6 keys down simultaneously).
The event we get is a ``k`` - note a modifier state of zero and ``0x0e`` for
``Keyboard K:    14``. Pressing the other buttons yields similar events
with keys ``k``, ``g``, ``l``, ``Del``,  ``Space``, etc. The second row from bottom
produces pure modifiers, e.g.::

    # ▓  Report ID: 3 /
    # ▓               Keyboard LeftControl:     1 |Keyboard LeftShift:     0 |Keyboard LeftAlt:     0 |Keyboard Left GUI:     0 |
    #                 Keyboard RightControl:     0 |Keyboard RightShift:     0 |Keyboard RightAlt:     0 |Keyboard Right GUI:     0 |
    #                 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0
    E: 000401.738938 8 03 01 00 00 00 00 00 00
    # ▓  Report ID: 3 /
    # ▓               Keyboard LeftControl:     0 |Keyboard LeftShift:     0 |Keyboard LeftAlt:     0 |Keyboard Left GUI:     0 |
    #                 Keyboard RightControl:     0 |Keyboard RightShift:     0 |Keyboard RightAlt:     0 |Keyboard Right GUI:     0 |
    #                 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0| 0007/0000:     0
    E: 000401.907120 8 03 00 00 00 00 00 00 00

This particular button is identical to a left control down key press. Pressing
this button together with the ``k`` button would thus produce ``Ctrl+k``.
Pressing multiple buttons together fills in the buttons in-order over the last
6 bytes of the report.

How about the dial and the little button inside? They send reports on the other hidraw node::

    $ sudo hid-recorder /dev/hidraw2
    ...
    # ▓  Report ID: 17 /
    # ▓               Button 1:     0 |Touch:     0
    # ▓               Dial:     1
    E: 000003.142187 9 11 00 01 00 00 00 00 00 00

Fairly obviously a dial event and rotating it in the other direction gives us
``Dial: -1``.

.. note:: The tested device was not reliable for dial events with the direction
          not switching immediately and some dial events with value zero. This
          indicates buggy firmware.

The little round button in the center of the dial does this::

    # ▓  Report ID: 17 /
    # ▓               Button 1:     1 |Touch:     1
    # ▓               Dial:     0
    E: 000006.596226 9 11 03 00 00 00 00 00 00 00

This tells us button 1 is down (and touch down too but that's mostly for
tablet-compatibility).

.. note:: The tested device did not send ``Button 1: 0`` events on release.
          Even rotating the dial after releasing would keep the button logically
          down for several events.  This indicates buggy firmware.

In summary, we now know what all events do in firmware mode:

- the normal buttons send key press events for various keys including modifiers
- the dial sends (unreliable) relative dial events
- the little round button inside the dial sends (unreliable) tablet button events

The kernel ignores events from the dial/dial button altogether and we only get
two event nodes::

    $ sudo libinput record
    ...
    /dev/input/event18:	HUION Huion Keydial_K20 Keyboard
    /dev/input/event19:	HUION Huion Keydial_K20 Mouse


These are a keyboard and a mouse, respectively, but both are from the hidraw2
node (which pretends to be a keyboard and a mouse).

Switching the device to vendor mode
-----------------------------------

To switch a Huion device to vendor mode we need to read the USB string
descriptor index 200 from the English (US) language id (0x409). This returns
not only the firmware ID string but also switches the tablet to vendor mode.
From then until unplug, the device will only send events via the vendor hidraw
node and the other two hidraw nodes no longer send events.

The `huion-switcher <https://github.com/whot/huion-switcher>`_ does exactly this. Running it prints::

    $ sudo huion-switcher --all
    HUION_FIRMWARE_ID="HUION_T21h_230511"
    HUION_MAGIC_BYTES="1403010000010000000000000013008040002808"

Since we only have one device we can supply ``--all``, which will attempt to switch all
connected devices with Huion's VID of ``0x256c``.

To switch the device automatically on plug, see the
`huion-switcher <https://github.com/whot/huion-switcher>`_ instructions. This is required
for any device that does **not** have a unique PID - huion-switcher's udev rule will
propagate the firmware ID into the ``UNIQ`` udev property and thus make it available to
libwacom and other userspace components.

Analysing the HID Reports in vendor mode
----------------------------------------

Now that device is in vendor mode let's check what happens on the top-left
button on the hidraw1 vendor node. ::

    $ sudo hid-recorder /dev/hidraw1
    # HUION Huion Keydial_K20
    # Report descriptor length: 18 bytes
    #   0x06, 0x00, 0xff,              // Usage Page (Vendor Defined Page 0xFF00)   0
    #   0x09, 0x01,                    // Usage (Vendor Usage 0x01)                 3
    #   0xa1, 0x01,                    // Collection (Application)                  5
    # ┅ 0x85, 0x08,                    //   Report ID (8)                           7
    #   0x75, 0x58,                    //   Report Size (88)                        9
    #   0x95, 0x01,                    //   Report Count (1)                        11
    #   0x09, 0x01,                    //   Usage (Vendor Usage 0x01)               13
    # ┇ 0x81, 0x02,                    //   Input (Data,Var,Abs)                    15
    #   0xc0,                          // End Collection                            17
    R: 18 06 00 ff 09 01 a1 01 85 08 75 58 95 01 09 01 81 02 c0
    N: HUION Huion Keydial_K20
    I: 3 256c 69
    # Report descriptor:
    # ------- Input Report -------
    # ░ Report ID: 8
    # ░  | Report size: 96 bits
    # ░ Bits:   8..=95  Usage: ff00/0001: Vendor Defined Usage ff00 / 0001            Logical Range:     0..=0
    ##############################################################################
    # Recorded events below in format:
    # E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]
    # ░  Report ID: 8 /
    # ░               Vendor Usage 0x01: e0 01 01 01 00 00 00 00 00 00 00
    E: 000000.000123 12 08 e0 01 01 01 00 00 00 00 00 00 00
    # ░  Report ID: 8 /
    # ░               Vendor Usage 0x01: e0 01 01 00 00 00 00 00 00 00 00
    E: 000000.079629 12 08 e0 01 01 00 00 00 00 00 00 00 00
    # ░  Report ID: 8 /
    # ░               Vendor Usage 0x01: e0 01 01 02 00 00 00 00 00 00 00
    E: 000037.960053 12 08 e0 01 01 02 00 00 00 00 00 00 00
    # ░  Report ID: 8 /
    # ░               Vendor Usage 0x01: e0 01 01 00 00 00 00 00 00 00 00
    E: 000038.037927 12 08 e0 01 01 00 00 00 00 00 00 00 00

Or to make it more obvious, here are buttons 1, 2, 10, and 16 and the
round dial button::

    E: 000000.000123 12 08 e0 01 01 01 00 00 00 00 00 00 00
    E: 000000.000123 12 08 e0 01 01 02 00 00 00 00 00 00 00
    E: 000000.000123 12 08 e0 01 01 00 02 00 00 00 00 00 00
    E: 000000.000123 12 08 e0 01 01 00 00 02 00 00 00 00 00
    E: 000000.000123 12 08 e0 01 01 00 00 04 00 00 00 00 00

So we can see there's a fixed prefix of ``08 e0 01 01`` followed by
and three bytes that are the button mask. Pressing two or more buttons
simultaneously combines the individual masks as expected.

.. note:: In vendor mode the dial and dial button produce reliable
          reports, unlike in firmware mode.

And the dial reports show  different prefix (``08 f1 01 01``) but otherwise it's
a predictable ``01`` for CW and ``02`` for CCW::

    # ░  Report ID: 8 /
    # ░               Vendor Usage 0x01: f1 01 01 00 01 00 00 00 00 00 00
    E: 000240.276450 12 08 f1 01 01 00 01 00 00 00 00 00 00
    # ░  Report ID: 8 /
    # ░               Vendor Usage 0x01: f1 01 01 00 02 00 00 00 00 00 00
    E: 000242.262430 12 08 f1 01 01 00 02 00 00 00 00 00 00


So in summary: we have identified where each feature of the device sits
in the vendor report.

The wheel occupies the same index as the button mask, something that HID does
not support. This is something we will have to work around.

Overwriting the vendor HID Report Descriptor
--------------------------------------------

.. note:: See the :ref:`tutorial` that explains the structure of a HID BPF file

The data in the vendor HID report is reliable, so if we can make the kernel
parse it, we can get reliable data from the device. For this we need
``udev-hid-bpf``::

  $ git clone https://gitlab.freedesktop.org/libevdev/udev-hid-bpf.git
  $ cd udev-hid-bpf
  $ git switch -c wip/huion-k20
  $ $EDITOR src/bpf/testing/0010-Huion__KeydialK20.bpf.c


.. note:: Run ``sudo cat /sys/kernel/debug/tracing/trace_pipe`` in another terminal
          to see any ``bpf_printk()`` calls.

Note that this is an abridged version to point out just the bits that are
specific to this device. For the full source, see the
`udev-hid-bpf MR!158 <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/merge_requests/158>`_.

We define our VID/PID and make sure our BPF attaches to that device:

.. code:: c

  #define VID_HUION 0x256C
  #define PID_KEYDIAL_K20 0x0069

  HID_BPF_CONFIG(
	  HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_HUION, PID_KEYDIAL_K20),
  );

Because our ID is unique we don't have to worry about attaching to the wrong
device but we still put some safety checks in so we only attach if
the report descriptor lengths match up:

.. code:: c

  /* see the hid-recorder output */
  #define PAD_REPORT_DESCRIPTOR_LENGTH 135
  #define PUCK_REPORT_DESCRIPTOR_LENGTH 108
  #define VENDOR_REPORT_DESCRIPTOR_LENGTH 18

  SEC("syscall")
  int probe(struct hid_bpf_probe_args *ctx)
  {
	  switch (ctx->rdesc_size) {
	  case PAD_REPORT_DESCRIPTOR_LENGTH:
	  case PUCK_REPORT_DESCRIPTOR_LENGTH:
	  case VENDOR_REPORT_DESCRIPTOR_LENGTH:
		  ctx->retval = 0;
		  break;
	  default:
		  ctx->retval = -EINVAL;
	  }

	  return 0;
  }

Now let's run this - it won't do anything but we can get our commandline history sorted.
The hidraw nodes will change as we load/unload the BPF so let's find the path to the device.

::

    $ ls -l /sys/class/hidraw/hidraw1 -> ../../devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/0003:256C:0069.0042/hidraw/hidraw1
    # Note this terminates at 0069
    $ export HIDDEVICE=/sys/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/0003:256C:0069
    $ cd udev-hid-bpf
    $ meson compile -C builddir
    $ sudo ./builddir/udev-hid-bpf --verbose add --replace $HIDDEVICE.* ./builddir/src/bpf/0010-Huion__KeydialK20.bpf.o
    DEBUG - loading BPF object at "./build/src/bpf/0010-Huion__KeydialK20.bpf.o"
    DEBUG - libbpf: elf: skipping unrecognized data section(11) .hid_bpf_config
    DEBUG - Using HID_BPF_STRUCT_OPS
    INFO - Successfully loaded "./build/src/bpf/0010-Huion__KeydialK20.bpf.o"

Our HID device has four-part component: ``0003:256C:0069.0042``. The last one
(``0042``) increments as the device is added - which will happen as you replace
the report descriptor. The simple approach is thus to skip that part in the
`HIDDEVICE` export and use a glob as shown above.

Once this works, you can rebuild and re-run the last command to replace the
currently loaded BPF (if any) with the new one.

Back to our BPF. Our goal is to replace the vendor usages with something
meaningful that the kernel can handle. Let's do that by composing a report
descriptor that does what we want - using our convenient macros:

.. code:: c

  #define VENDOR_REPORT_ID 8
  // The length of our vendor report in bytes (the report, not the report descriptor)
  #define VENDOR_REPORT_LENGTH 12

  static const __u8 fixed_rdesc_vendor[] = {
      UsagePage_GenericDesktop
      Usage_GD_Keypad
      CollectionApplication(
          // Byte 0
          // We send our pad events on the vendor report id because why not.
          // Really this number can be anything but leaving it as-is means
          // we can leave that byte as-is.
          ReportId(VENDOR_REPORT_ID)
          UsagePage_Digitizers
          Usage_Dig_TabletFunctionKeys  // Makes this a pad
          CollectionPhysical(
              // Byte 1 is a button so we look like a tablet
              Usage_Dig_BarrelSwitch  // gives us BTN_STYLUS, needed so we get to be a tablet pad
              ReportCount(1)  // one element of...
              ReportSize(1)   // one bit size...
              Input(Var|Abs)  // and it's an "input" report (i.e. device -> host)
              ReportCount(7)  // Report Size 1 carries over, padding 7 bits to round to the byte barrier
              Input(Const)    // Const means value never changes so it's ignored, i.e. it's padding
              // Bytes 2/3 - x/y just exist so we get to be a tablet pad
              UsagePage_GenericDesktop
              Usage_GD_X      // two usages for 2 elements each with size 8 bits
              Usage_GD_Y
              LogicalMinimum_i8(0x0)
              LogicalMaximum_i8(0x1)
              ReportCount(2)
              ReportSize(8)
              Input(Var|Abs)  // variable == can change, Abs means abs value
              // Bytes 4-7 are the button state for 19 buttons + pad out to u32
              // We send the first 10 buttons as buttons 1-10 which is BTN_0 -> BTN_9
              UsagePage_Button
              UsageMinimum_i8(1)
              UsageMaximum_i8(10) // button usages are simply numeric so this is buttons 1-10
              LogicalMinimum_i8(0x0)
              LogicalMaximum_i8(0x1)  // logically either 0 or 1
              ReportCount(10)
              ReportSize(1)  // 10 elements each size 1 bit
              Input(Var|Abs)
              // We send the other 9 buttons as buttons 0x31 and above, this gives us BTN_A - BTN_TL2
              UsageMinimum_i8(0x31)
              UsageMaximum_i8(0x3a)
              ReportCount(9) // 9 elements each size 1 bit
              ReportSize(1)
              Input(Var|Abs)
              ReportCount(13) // pad out to 32 bits, makes life easier
              ReportSize(1)
              Input(Const) // padding
              // Byte 6 is the wheel
              UsagePage_GenericDesktop
              Usage_GD_Wheel
              LogicalMinimum_i8(-1)
              LogicalMaximum_i8(1)  // can be -1 to 1
              ReportCount(1)
              ReportSize(8)  // 1 byte of 8 bits
              Input(Var|Rel) // input event, variable and a relative axis
          )
          // Make sure we match our original report length
          // This is a requirement by the kernel, our modified hid report
          // descriptor needs to have at least one HID report that
          // is the same size the original report descriptor contained.
          // This macro expands to a vendor report that is exactly of the
          // length given here.
          FixedSizeVendorReport(VENDOR_REPORT_LENGTH)
      )
  };


The above is a HID Report Descriptor that has 1 bit for a stylus button
in the first byte, then an x/y in bytes 2 and 3 followed by a 19-bit sized
mask for the buttons (padded to u32) followed by a single byte for the wheel.
The button mask and Report ID conveniently match the existing vendor report so
we should be able to use those as-is.

So all we need to do now is to tell the BPF that we want this one as our
new report descriptor. And we do this by simply memcpy-ing the new report
descriptor over the old one in the corresponding hook.

.. code:: c

  SEC(HID_BPF_RDESC_FIXUP)
  int BPF_PROG(k20_fix_rdesc, struct hid_bpf_ctx *hctx)
  {
      __u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);
      __s32 rdesc_size = hctx->size;
      __u8 have_fw_id;

      if (!data)
          return 0; /* EPERM check */

      if (rdesc_size == VENDOR_REPORT_DESCRIPTOR_LENGTH) {
          __builtin_memcpy(data, fixed_rdesc_vendor, sizeof(fixed_rdesc_vendor));
          return sizeof(fixed_rdesc_vendor);
      }

      return 0;
  }

  HID_BPF_OPS(keydial_k20) = {
      .hid_rdesc_fixup = (void *)k20_fix_rdesc,
  };


Note that the ``HID_BPF_RDESC_FIXUP`` function will be called for all
report descriptors on the device so the check for the correct ``rdesc_size``
prevents us from accidentally overwriting the firmware mode report descriptors.

Overwriting the vendor HID Reports
----------------------------------

As said above - because the wheel is on the same bytes as the button masks we will
need a workaround for that. And that workaround is to shuffle the bits around in
the BPF function that is called for each input report:

.. code:: c

  __u32 last_button_state;

  SEC(HID_BPF_DEVICE_EVENT)
  int BPF_PROG(k20_fix_events, struct hid_bpf_ctx *hctx)
  {
      __u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 10 /* size */);

      if (!data)
          return 0; /* EPERM check */

      /* Only sent if tablet is in raw mode */
      if (data[0] == VENDOR_REPORT_ID) {
          /* This struct matches the report layout we composed in fixed_rdesc_vendor */
          struct pad_report {
              __u8 report_id;
              __u8 btn_stylus:1;
              __u8 pad:7;
              __u8 x;
              __u8 y;
              __u32 buttons;
              __u8 wheel;
          } __attribute__((packed)) *pad_report;

          __u8 wheel = 0;

          /* Wheel report */
          if (data[1] == 0xf1) {
              if (data[5] == 2)
                  wheel = 0xff; // -1 in 8 bits
              else
                  wheel = data[5];
          } else {
              /* We need to always send the current button state so
               * the button doesn't get released if we get a wheel event while a button
               * is down.
               * data[4..6] is the button mask, we can otherwise use it as-is
               */
              last_button_state = data[4] | (data[5] << 8) | (data[6] << 16);
              wheel = 0;
          }

          pad_report = (struct pad_report *)data;
          /* This needs to match our ReportId(VENDOR_REPORT_ID) */
          pad_report->report_id = VENDOR_REPORT_ID;
          /* These three can be always zero, they only exist so we're a tablet pad */
          pad_report->btn_stylus = 0;
          pad_report->x = 0;
          pad_report->y = 0;
          pad_report->buttons = last_button_state;
          pad_report->wheel = wheel;

          return sizeof(struct pad_report);
      }

      return 0;
  }

  HID_BPF_OPS(keydial_k20) = {
	  .hid_device_event = (void *)k20_fix_events,
	  .hid_rdesc_fixup = (void *)k20_fix_rdesc,
  };


And that's it! I if we load this BPF program and run hid-recorder against
our hidraw node (which will have changed number as changing an report descriptor
re-creates the device)::

  $ sudo hid-recorder /dev/hidraw4
  # HUION Huion Keydial_K20
  # Report descriptor length: 102 bytes
  #   0x05, 0x01,                    // Usage Page (Generic Desktop)              0
  #   0x09, 0x07,                    // Usage (Keypad)                            2
  #   0xa1, 0x01,                    // Collection (Application)                  4
  # ┅ 0x85, 0x08,                    //   Report ID (8)                           6
  #   0x05, 0x0d,                    //   Usage Page (Digitizers)                 8
  #   0x09, 0x39,                    //   Usage (Tablet Function Keys)            10
  #   0xa1, 0x00,                    //   Collection (Physical)                   12
  #   0x09, 0x44,                    //     Usage (Barrel Switch)                 14
  #   0x95, 0x01,                    //     Report Count (1)                      16
  #   0x75, 0x01,                    //     Report Size (1)                       18
  # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                  20
  #   0x95, 0x07,                    //     Report Count (7)                      22
  # ┇ 0x81, 0x01,                    //     Input (Cnst,Arr,Abs)                  24
  #   0x05, 0x01,                    //     Usage Page (Generic Desktop)          26
  #   0x09, 0x30,                    //     Usage (X)                             28
  #   0x09, 0x31,                    //     Usage (Y)                             30
  #   0x95, 0x02,                    //     Report Count (2)                      32
  #   0x75, 0x08,                    //     Report Size (8)                       34
  # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                  36
  #   0x05, 0x09,                    //     Usage Page (Button)                   38
  #   0x19, 0x01,                    //     UsageMinimum (1)                      40
  #   0x29, 0x0a,                    //     UsageMaximum (10)                     42
  #   0x15, 0x00,                    //     Logical Minimum (0)                   44
  #   0x25, 0x01,                    //     Logical Maximum (1)                   46
  #   0x95, 0x0a,                    //     Report Count (10)                     48
  #   0x75, 0x01,                    //     Report Size (1)                       50
  # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                  52
  #   0x19, 0x31,                    //     UsageMinimum (49)                     54
  #   0x29, 0x3a,                    //     UsageMaximum (58)                     56
  #   0x95, 0x09,                    //     Report Count (9)                      58
  #   0x75, 0x01,                    //     Report Size (1)                       60
  # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                  62
  #   0x95, 0x0d,                    //     Report Count (13)                     64
  #   0x75, 0x01,                    //     Report Size (1)                       66
  # ┇ 0x81, 0x01,                    //     Input (Cnst,Arr,Abs)                  68
  #   0x05, 0x01,                    //     Usage Page (Generic Desktop)          70
  #   0x09, 0x38,                    //     Usage (Wheel)                         72
  #   0x15, 0xff,                    //     Logical Minimum (-1)                  74
  #   0x25, 0x01,                    //     Logical Maximum (1)                   76
  #   0x95, 0x01,                    //     Report Count (1)                      78
  #   0x75, 0x08,                    //     Report Size (8)                       80
  # ┇ 0x81, 0x06,                    //     Input (Data,Var,Rel)                  82
  #   0xc0,                          //   End Collection                          84
  #   0x06, 0xff, 0xff,              //   Usage Page (Vendor Defined Page 0xFFFF) 85
  #   0x09, 0x01,                    //   Usage (Vendor Usage 0x01)               88
  #   0xa1, 0x00,                    //   Collection (Physical)                   90
  # ┅ 0x85, 0xac,                    //     Report ID (172)                       92
  #   0x75, 0x08,                    //     Report Size (8)                       94
  #   0x95, 0x0b,                    //     Report Count (11)                     96
  # ┇ 0x81, 0x01,                    //     Input (Cnst,Arr,Abs)                  98
  #   0xc0,                          //   End Collection                          100
  #   0xc0,                          // End Collection                            101
  R: 102 05 01 09 07 a1 01 85 08 05 0d 09 39 a1 00 09 44 95 01 75 01 81 02 95 07 81 01 05 01 09 30 09 31 95 02 75 08 81 02 05 09 19 01 29 0a 15 00 25 01 95 0a 75 01 81 02 19 31 29 3a 95 09 75 01 81 02 95 0d 75 01 81 01 05 01 09 38 15 ff 25 01 95 01 75 08 81 06 c0 06 ff ff 09 01 a1 00 85 ac 75 08 95 0b 81 01 c0 c0
  N: HUION Huion Keydial_K20
  I: 3 256c 69
  # Report descriptor:
  # ------- Input Report -------
  # ░ Report ID: 8
  # ░  | Report size: 72 bits
  # ░ Bit:    8       Usage: 000d/0044: Digitizers / Barrel Switch                  Logical Range:     0..=0
  # ░ Bits:   9..=15  ######### Padding
  # ░ Bits:  16..=23  Usage: 0001/0030: Generic Desktop / X                         Logical Range:     0..=0
  # ░ Bits:  24..=31  Usage: 0001/0031: Generic Desktop / Y                         Logical Range:     0..=0
  # ░ Bit:   32       Usage: 0009/0001: Button / Button 1                           Logical Range:     0..=1
  # ░ Bit:   33       Usage: 0009/0002: Button / Button 2                           Logical Range:     0..=1
  # ░ Bit:   34       Usage: 0009/0003: Button / Button 3                           Logical Range:     0..=1
  # ░ Bit:   35       Usage: 0009/0004: Button / Button 4                           Logical Range:     0..=1
  # ░ Bit:   36       Usage: 0009/0005: Button / Button 5                           Logical Range:     0..=1
  # ░ Bit:   37       Usage: 0009/0006: Button / Button 6                           Logical Range:     0..=1
  # ░ Bit:   38       Usage: 0009/0007: Button / Button 7                           Logical Range:     0..=1
  # ░ Bit:   39       Usage: 0009/0008: Button / Button 8                           Logical Range:     0..=1
  # ░ Bit:   40       Usage: 0009/0009: Button / Button 9                           Logical Range:     0..=1
  # ░ Bit:   41       Usage: 0009/000a: Button / Button 10                          Logical Range:     0..=1
  # ░ Bit:   42       Usage: 0009/0031: Button / Button 49                          Logical Range:     0..=1
  # ░ Bit:   43       Usage: 0009/0032: Button / Button 50                          Logical Range:     0..=1
  # ░ Bit:   44       Usage: 0009/0033: Button / Button 51                          Logical Range:     0..=1
  # ░ Bit:   45       Usage: 0009/0034: Button / Button 52                          Logical Range:     0..=1
  # ░ Bit:   46       Usage: 0009/0035: Button / Button 53                          Logical Range:     0..=1
  # ░ Bit:   47       Usage: 0009/0036: Button / Button 54                          Logical Range:     0..=1
  # ░ Bit:   48       Usage: 0009/0037: Button / Button 55                          Logical Range:     0..=1
  # ░ Bit:   49       Usage: 0009/0038: Button / Button 56                          Logical Range:     0..=1
  # ░ Bit:   50       Usage: 0009/0039: Button / Button 57                          Logical Range:     0..=1
  # ░ Bits:  51..=63  ######### Padding
  # ░ Bits:  64..=71  Usage: 0001/0038: Generic Desktop / Wheel                     Logical Range:    -1..=1
  # ------- Input Report -------
  # ▚ Report ID: 172
  # ▚  | Report size: 96 bits
  # ▚ Bits:   8..=95  ######### Padding
  ##############################################################################
  # Recorded events below in format:
  # E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]

So: 1 bit for the stylus button, x/y, then 19 buttons and a byte for the wheel. Just as intended.
If we press/release button 2 we get the following events::

  # ░  Report ID: 8 /
  # ░               Barrel Switch:     0 |<7 bits padding> |X:     0 |Y:     0 |Button 1:     0 |Button 2:     1 |Button 3:     0 |Button 4:     0 |Button 5:     0 |Button 6:     0 |Button 7:     0 |Button 8:     0 |Button 9:     0 |Button 10:     0 |Button 49:     0 |Button 50:     0 |Button 51:     0 |Button 52:     0 |Button 53:     0 |Button 54:     0 |Button 55:     0 |Button 56:     0 |Button 57:     0 |<13 bits padding> |Wheel:     0
  B: 000000.000073 36 08 e0 01 01 02 00 00 00 00 00 00 00
  E: 000000.000071 9 08 e0 00 00 02 00 00 00 00
  # ░  Report ID: 8 /
  # ░               Barrel Switch:     0 |<7 bits padding> |X:     0 |Y:     0 |Button 1:     0 |Button 2:     0 |Button 3:     0 |Button 4:     0 |Button 5:     0 |Button 6:     0 |Button 7:     0 |Button 8:     0 |Button 9:     0 |Button 10:     0 |Button 49:     0 |Button 50:     0 |Button 51:     0 |Button 52:     0 |Button 53:     0 |Button 54:     0 |Button 55:     0 |Button 56:     0 |Button 57:     0 |<13 bits padding> |Wheel:     0
  B: 000000.055942 36 08 e0 01 01 00 00 00 00 00 00 00 00
  E: 000000.055942 9 08 e0 00 00 00 00 00 00 00


.. note:: The `B:` line in the output is a BPF tracing program inserted by ``hid-recorder`` to show
          the data from the device **before** our BPF modified it. Great for debugging.


And if we move the dial one detent CCW we get::

  # ░  Report ID: 8 /
  # ░               Barrel Switch:     0 |<7 bits padding> |X:     0 |Y:     0 |Button 1:     0 |Button 2:     0 |Button 3:     0 |Button 4:     0 |Button 5:     0 |Button 6:     0 |Button 7:     0 |Button 8:     0 |Button 9:     0 |Button 10:     0 |Button 49:     0 |Button 50:     0 |Button 51:     0 |Button 52:     0 |Button 53:     0 |Button 54:     0 |Button 55:     0 |Button 56:     0 |Button 57:     0 |<13 bits padding> |Wheel:    -1
  B: 000094.421180 36 08 f1 01 01 00 02 00 00 00 00 00 00
  E: 000094.421178 9 08 f0 00 00 00 00 00 00 ff


Because this is now mapped correctly, our device will show up and behave
correctly as an evdev node, as shown by ``libinput record``::

  # libinput record
  version: 1
  ndevices: 1
  libinput:
    version: "1.26.2"
    git: "unknown"
  system:
    os: "fedora:41"
    kernel: "6.11.3-300.fc41.x86_64"
    dmi: "dmi:bvnLENOVO:bvrN2YET34W(1.23):bd12/31/2021:br1.23:efr1.8:svnLENOVO:pn20T1S94K00:pvrThinkPadT14sGen1:rvnLENOVO:rn20T1S94K00:rvrSDK0J40697WIN:cvnLENOVO:ct10:cvrNone:skuLENOVO_MT_20T1_BU_Think_FM_ThinkPadT14sGen1:"
  devices:
  - node: /dev/input/event20
    evdev:
      # Name: HUION Huion Keydial_K20
      # ID: bus 0x0003 (usb) vendor 0x256c product 0x0069 version 0x0110
      # Size in mm: unknown, missing resolution
      # Supported Events:
      # Event type 0 (EV_SYN)
      # Event type 1 (EV_KEY)
      #   Event code 256 (BTN_0)
      #   Event code 257 (BTN_1)
      #   Event code 258 (BTN_2)
      #   Event code 259 (BTN_3)
      #   Event code 260 (BTN_4)
      #   Event code 261 (BTN_5)
      #   Event code 262 (BTN_6)
      #   Event code 263 (BTN_7)
      #   Event code 264 (BTN_8)
      #   Event code 265 (BTN_9)
      #   Event code 304 (BTN_SOUTH)
      #   Event code 305 (BTN_EAST)
      #   Event code 306 (BTN_C)
      #   Event code 307 (BTN_NORTH)
      #   Event code 308 (BTN_WEST)
      #   Event code 309 (BTN_Z)
      #   Event code 310 (BTN_TL)
      #   Event code 311 (BTN_TR)
      #   Event code 312 (BTN_TL2)
      #   Event code 313 (BTN_TR2)
      #   Event code 331 (BTN_STYLUS)
      # Event type 2 (EV_REL)
      #   Event code 8 (REL_WHEEL)
      #   Event code 11 (REL_WHEEL_HI_RES)
      # Event type 3 (EV_ABS)
      #   Event code 0 (ABS_X)
      #       Value           0
      #       Min             0
      #       Max             0
      #       Fuzz            0
      #       Flat            0
      #       Resolution      0
      #   Event code 1 (ABS_Y)
      #       Value           0
      #       Min             0
      #       Max             0
      #       Fuzz            0
      #       Flat            0
      #       Resolution      0
      # Event type 4 (EV_MSC)
      #   Event code 4 (MSC_SCAN)
      # Properties:
      name: "HUION Huion Keydial_K20"
      id: [3, 9580, 105, 272]
      codes:
        0: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] # EV_SYN
        1: [256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 331] # EV_KEY
        2: [8, 11] # EV_REL
        3: [0, 1] # EV_ABS
        4: [4] # EV_MSC
      absinfo:
        0: [0, 0, 0, 0, 0]
        1: [0, 0, 0, 0, 0]
      properties: []
    hid: [
      0x05, 0x01, 0x09, 0x07, 0xa1, 0x01, 0x85, 0x08, 0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00, 0x09, 0x44,
      0x95, 0x01, 0x75, 0x01, 0x81, 0x02, 0x95, 0x07, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31,
      0x95, 0x02, 0x75, 0x08, 0x81, 0x02, 0x05, 0x09, 0x19, 0x01, 0x29, 0x0a, 0x15, 0x00, 0x25, 0x01,
      0x95, 0x0a, 0x75, 0x01, 0x81, 0x02, 0x19, 0x31, 0x29, 0x3a, 0x95, 0x09, 0x75, 0x01, 0x81, 0x02,
      0x95, 0x0d, 0x75, 0x01, 0x81, 0x01, 0x05, 0x01, 0x09, 0x38, 0x15, 0xff, 0x25, 0x01, 0x95, 0x01,
      0x75, 0x08, 0x81, 0x06, 0xc0, 0x06, 0xff, 0xff, 0x09, 0x01, 0xa1, 0x00, 0x85, 0xac, 0x75, 0x08,
      0x95, 0x0b, 0x81, 0x01, 0xc0, 0xc0
    ]
    udev:
      properties:
      - ID_INPUT=1
      - ID_INPUT_TABLET=1
      - ID_INPUT_TABLET_PAD=1
      - LIBINPUT_DEVICE_GROUP=3/256c/69:usb-0000:00:14.0-4
      - DRIVER=hid-generic
    quirks:
    - AttrResolutionHint=205x328
    events:
    # Current time is 20:42:35
    - evdev:
      - [  0,      0,   4,   4,  589826] # EV_MSC / MSC_SCAN             589826
      - [  0,      0,   1, 257,       1] # EV_KEY / BTN_1                     1
      - [  0,      0,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +0ms
    - evdev:
      - [ 88,  38334,   2,   8,      -1] # EV_REL / REL_WHEEL                -1
      - [ 88,  38334,   2,  11,    -120] # EV_REL / REL_WHEEL_HI_RES       -120
      - [ 88,  38334,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +3630ms


And that is it - our BPF works and the device behaves as expected.


Disabling unused HID Reports
----------------------------

.. note:: This is a cosmetic feature only, not required for functionality.

Once the device is in vendor mode the firmware nodes will no longer send
events. They will however have the same name and generally just confuse
things. To remove them we need the kernel to ignore them.

This is done by overwriting those nodes' Report Descriptors
with a vendor-only HID Report Descriptor. Just like the vendor hidraw node that
the kernel ignored before we changed to to a meaningful one it will now ignore
the firmware nodes.

But to be on the safe side: we only do this if the ``HUION_FIRMWARE_ID`` udev
property is set. huion-switcher will set that property when it switches the
tablet to vendor mode so if it is present we know we're in vendor mode and the
firmware nodes are mute anyway.

.. code:: c

  /* Any global prefixed with UDEV_PROP will be set to the value of that udev property.
   * If huion-switcher is run via the provided udev rule it will set the
   * HUION_FIRMWARE_ID udev property to the firmware value.
   */
  char UDEV_PROP_HUION_FIRMWARE_ID[64];

  /* The prefix of the firmware ID we expect for this device. The full firmware
   * string has a date suffix, e.g. HUION_T21h_230511 but we don't want
   * this BPF to stop working if the date changes.
   */
  char EXPECTED_FIRMWARE_ID[] = "HUION_T21H_";

  /* See hid-recorder */
  #define PAD_KBD_REPORT_LENGTH 8
  #define PAD_CC_REPORT_LENGTH 3
  #define PAD_MOUSE_REPORT_LENGTH 7
  #define PUCK_REPORT_LENGTH 9

  static const __u8 disabled_rdesc_puck[] = {
      FixedSizeVendorReport(PUCK_REPORT_LENGTH)
  };

  static const __u8 disabled_rdesc_pad[] = {
      FixedSizeVendorReport(PAD_KBD_REPORT_LENGTH)
      FixedSizeVendorReport(PAD_CC_REPORT_LENGTH)
      FixedSizeVendorReport(PAD_MOUSE_REPORT_LENGTH)
  };

  SEC(HID_BPF_RDESC_FIXUP)
  int BPF_PROG(k20_fix_rdesc, struct hid_bpf_ctx *hctx)
  {
      __u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);
      __s32 rdesc_size = hctx->size;
      __u8 have_fw_id;

      if (!data)
          return 0; /* EPERM check */

      /* If we have a firmware ID and it matches our expected prefix, we
       * disable the default pad/puck nodes. They won't send events
       * but cause duplicate devices.
       */
      have_fw_id = __builtin_memcmp(UDEV_PROP_HUION_FIRMWARE_ID,
                        EXPECTED_FIRMWARE_ID,
                        sizeof(EXPECTED_FIRMWARE_ID) - 1) == 0;
      if (have_fw_id) {
        if (rdesc_size == PAD_REPORT_DESCRIPTOR_LENGTH) {
              __builtin_memcpy(data, disabled_rdesc_pad, sizeof(disabled_rdesc_pad));
              return sizeof(disabled_rdesc_pad);
        }
        if (rdesc_size == PUCK_REPORT_DESCRIPTOR_LENGTH) {
              __builtin_memcpy(data, disabled_rdesc_puck, sizeof(disabled_rdesc_puck));
              return sizeof(disabled_rdesc_puck);
        }
      }
      /* Always fix the vendor mode so the tablet will work even if nothing sets
       * the udev property (e.g. huion-switcher run manually)
       */
      if (rdesc_size == VENDOR_REPORT_DESCRIPTOR_LENGTH) {
          __builtin_memcpy(data, fixed_rdesc_vendor, sizeof(fixed_rdesc_vendor));
          return sizeof(fixed_rdesc_vendor);
      }
      return 0;
  }

Adding an entry to libwacom
---------------------------

Now that our device works fine we can `Add a new device to libwacom
<https://github.com/linuxwacom/libwacom/wiki/Adding-a-new-device>`_. This will
make our device show up with the correct properties in the various GUI
configuration programs like GNOME Settings.

First, let's verify the expected::

    $ libwacom-list-local-devices
    /dev/input/event20 is a tablet but not supported by libwacom
    Failed to find any devices known to libwacom.

Let's get started. First we collect some info about the tablet for the
`wacom-hid-descriptors <https://github.com/linuxwacom/wacom-hid-descriptors>`_
repository. This repo keeps a record of the various devices so the
maintainers can (in the future) track down bugs or look up missing features for
devices.

::

    $ git clone https://github.com/linuxwacom/wacom-hid-descriptors
    $ cd wacom-hid-descriptors
    $ sudo ./scripts/sysinfo.sh
    Gathering system and tablet information. This may take a few seconds.
      * General host information...
      * Kernel driver information...
      * Kernel device information...
         - /sys/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/0003:256C:0069.0049...
         - /sys/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.1/0003:256C:0069.004A...
         - /sys/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.2/0003:256C:0069.004B...
         - /sys/devices/pci0000:00/0000:00:14.0/usb1/1-6/1-6:1.0/0003:04F3:2D4A.0001...
         - udev...
      * Unbinding devices...
      * Rebinding devices...
      * Userspace driver information...
      * Userspace device information...
      * Device display information...
      * System logs...
      * System config files...
      * Desktop configuration data...
      * Removing identifying information...
      * Tarball generation...
    Finished. Data available in 'sysinfo.lvuqy3Kjgl.tar.gz'

Now we file an issue in the `wacom-hid-descriptors <https://github.com/linuxwacom/wacom-hid-descriptors>`_
repository and attach that ``sysinfo.*.tar.gz`` tarball to that issue. Once we have
that issue URL we can use it in our ``.tablet`` file.

Next we find an existing device that's similar to ours, for example the `Wacom
EK Remote <https://github.com/linuxwacom/libwacom/blob/master/data/wacom-ek-remote.tablet>`_.
So we copy it and start editing it::

   $ git clone https://github.com/linuxwacom/libwacom
   $ meson setup builddir && meson compile -C builddir
   $ cp data/wacom-ek-remote.tablet data/huion-keydial-k20.tablet
   $ $EDITOR data/huion-keydial-k20.tablet


libwacom's ``.tablet`` files are relatively self-explanatory. But in our
case we need to modify the file to this ::

    # Huion
    # Keydial K20
    #
    # sysinfo.lvuqy3Kjgl.tar.gz
    # https://github.com/linuxwacom/wacom-hid-descriptors/issues/425
    #
    #   __________
    #  |( S )     |
    #  +----------+
    #  |  A B C D |
    #  |  E F G H |
    #  |  I J K L |
    #  |  M N O P |
    #  |   Q  R   |
    #  +----------+

    [Device]
    Name=Huion Keydial K20
    ModelName=K20
    # This appears to be a unique PID, if that changes the FW prefix is HUION_T21h
    DeviceMatch=usb|256c|0069
    Layout=huion-keydial-k20.svg
    IntegratedIn=Remote

    [Features]
    Stylus=false
    # Unlike the Wacom EK Remote this device does not have an absolute Ring
    # but rather a relative Dial.
    NumDials=1
    DialNumModes=4

    [Buttons]
    Left=A;B;C;D;E;F;G;H;I;J;K;L;M;N;O;P;Q;R;S
    EvdevCodes=BTN_0;BTN_1;BTN_2;BTN_3;BTN_4;BTN_5;BTN_6;BTN_7;BTN_8;BTN_9;BTN_SOUTH;BTN_EAST;BTN_C;BTN_NORTH;BTN_WEST;BTN_Z;BTN_TL;BTN_TR;BTN_TL2

Then we need to fire up ``inkscape`` to create the
``data/layouts/huion-keydial-kd20.svg`` file. As with the tablet
file it's easier to copy an existing file and modify it::

   $ cp data/layouts/wacom-ek-remote.svg data/layouts/huion-keydial-k20.svg
   $ sed -i 's|Ring|Dial|` data/layouts/huion-keydial-k20.svg
   $ inscape data/layouts/huion-keydial-k20.svg
   $ meson test -C builddir

libwacom's SVGs have some requirements for labelling objects and the test suite
should pick up any issues. As with the ``.tablet`` file the
most notable change is that we have a dial, not a ring so replacing all
IDs and classes via a sed before editing is the simplest way to go about it.

And now we check if this file gets picked up correctly with the
in-tree ``list-local-devices`` tool (which uses the git
repo's ``data/`` directory)::

    $ ./build/list-local-devices
    devices:
    - name: 'Huion Keydial K20'
      bus: 'usb'
      vid: '0x256c'
      pid: '0x0069'
      nodes:
      - /dev/input/event20: 'HUION Huion Keydial_K20'
      styli: []


That's it - this ``.tablet`` file can now be upstreamed to libwacom. This completes
our device enablement, the rest of the stack should now work with the device, various
bugs nonwithstanding.

.. note:: The ``.tablet`` and ``.svg`` files can be placed into
          ``/etc/libwacom/`` and ``/etc/libwacom/layouts/`` until
          the local system updates to the required libwacom release.
