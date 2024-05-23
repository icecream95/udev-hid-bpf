// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define VID_HUION 0x256C
/*
 * This PID is shared with many others: Kamvas Pro 24, Kamvas Pro 13, Gaomon S56K, 1060 Plus and 420, ...
 */
#define PID_HUION_H610_PRO 0x006E

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_HUION, PID_HUION_H610_PRO)
);

/* Filled in by udev-hid-bpf */
char UDEV_PROP_HUION_FIRMWARE_ID[64];
char UDEV_PROP_HUION_MAGIC_BYTES[64];

/*
 * Huion devices return a descriptor (the magic bytes from above) with the
 * values the driver should use when one of its interfaces is queried.
 * For this device the descriptor is:
 *
 * 0e 03 40 9c a8 61 03 00 ff 07 a0 0f 08 00
 *       ----- -----       ----- -----
 *         |     |           |     |
 *         |     |           |     `- Resolution: 4000 (0fa0)
 *         |     |           `- Maximum pressure: 2047 (07ff)
 *         |     `- Logical maximum Y: 25000 (61a8)
 *         `- Logical maximum X: 40000 (9c40)
 *
 * The physical maximum is calculated as (logical_max * 1000) / resolution.
 */

/* The prefix of the firmware ID we expect for this device. */
const char EXPECTED_FIRMWARE_ID[] = "HVAN";
#define EXPECTED_X_LOGICAL_MAX 40000
#define X_LOGICAL_MAX_IDX 4 /* in UDEV_PROP_HUION_MAGIC_BYTES */
#define EXPECTED_Y_LOGICAL_MAX 25000
#define Y_LOGICAL_MAX_IDX 8 /* in UDEV_PROP_HUION_MAGIC_BYTES */
#define EXPECTED_PRESSURE_LOGICAL_MAX 2047
#define PRESSURE_LOGICAL_MAX_IDX 16 /* in UDEV_PROP_HUION_MAGIC_BYTES */
#define EXPECTED_RESOLUTION 4000
#define RESOLUTION_IDX 20 /* in UDEV_PROP_HUION_MAGIC_BYTES */


/* How this BPF program works: the tablet has two modes, firmware mode and
 * tablet mode. In firmware mode (out of the box) the tablet sends button events.
 * In tablet mode it uses a vendor specific hid report to report everything instead.
 * Depending on the mode some hid reports are never sent and the corresponding
 * devices are mute.
 *
 * To switch the tablet use e.g.  https://github.com/whot/huion-switcher
 * or one of the tools from the digimend project
 *
 * This BPF only works the vendor mode. The huion-switcher tool sets the
 * HUION_FIRMWARE_ID udev property - if that is set then we disable the firwmare
 * pad and pen reports (by making them vendor collections that are ignored).
 *
 * Default report descriptor for the first exposed hidraw node:
 *
 * # HUION PenTablet
 * # 0x05, 0x0d,                    // Usage Page (Digitizers)             0
 * # 0x09, 0x02,                    // Usage (Pen)                         2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x85, 0x07,                    //  Report ID (7)                      6
 * # 0x09, 0x20,                    //  Usage (Stylus)                     8
 * # 0xa1, 0x00,                    //  Collection (Physical)              10
 * # 0x09, 0x42,                    //   Usage (Tip Switch)                12
 * # 0x09, 0x44,                    //   Usage (Barrel Switch)             14
 * # 0x09, 0x45,                    //   Usage (Eraser)                    16
 * # 0x09, 0x3c,                    //   Usage (Invert)                    18
 * # 0x09, 0x43,                    //   Usage (Secondary Tip Switch)      20
 * # 0x09, 0x44,                    //   Usage (Barrel Switch)             22
 * # 0x15, 0x00,                    //   Logical Minimum (0)               24
 * # 0x25, 0x01,                    //   Logical Maximum (1)               26
 * # 0x75, 0x01,                    //   Report Size (1)                   28
 * # 0x95, 0x06,                    //   Report Count (6)                  30
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              32
 * # 0x09, 0x32,                    //   Usage (In Range)                  34
 * # 0x75, 0x01,                    //   Report Size (1)                   36
 * # 0x95, 0x01,                    //   Report Count (1)                  38
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              40
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)              42
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      44
 * # 0x09, 0x30,                    //   Usage (X)                         46
 * # 0x75, 0x10,                    //   Report Size (16)                  48
 * # 0x95, 0x01,                    //   Report Count (1)                  50
 * # 0xa4,                          //   Push                              52
 * # 0x55, 0x0d,                    //   Unit Exponent (-3)                53
 * # 0x65, 0x13,                    //   Unit (EnglishLinear: in)          55
 * # 0x35, 0x00,                    //   Physical Minimum (0)              57
 * # 0x46, 0x10, 0x27,              //   Physical Maximum (10000)          59
 * # 0x27, 0x40, 0x9c, 0x00, 0x00,  //   Logical Maximum (40000)           62
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              67
 * # 0x09, 0x31,                    //   Usage (Y)                         69
 * # 0x46, 0x6a, 0x18,              //   Physical Maximum (6250)           71
 * # 0x26, 0xa8, 0x61,              //   Logical Maximum (25000)           74
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              77
 * # 0xb4,                          //   Pop                               79
 * # 0x05, 0x0d,                    //   Usage Page (Digitizers)           80
 * # 0x09, 0x30,                    //   Usage (Tip Pressure)              82
 * # 0x26, 0xff, 0x07,              //   Logical Maximum (2047)            84
 * # 0x46, 0xff, 0x07,              //   Physical Maximum (2047)           87
 * # 0x55, 0x00,                    //   Unit Exponent (0)                 90
 * # 0x66, 0x11, 0xe1,              //   Unit (SILinear: cm * g * s⁻²)     92
 * # 0x75, 0x10,                    //   Report Size (16)                  95
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              97
 * # 0xc0,                          //  End Collection                     99
 * # 0xc0,                          // End Collection                      100
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        101
 * # 0x09, 0x02,                    // Usage (Mouse)                       103
 * # 0xa1, 0x01,                    // Collection (Application)            105
 * # 0x85, 0x09,                    //  Report ID (9)                      107
 * # 0x09, 0x01,                    //  Usage (Pointer)                    109
 * # 0xa1, 0x00,                    //  Collection (Physical)              111
 * # 0x05, 0x09,                    //   Usage Page (Button)               113
 * # 0x19, 0x01,                    //   Usage Minimum (1)                 115
 * # 0x29, 0x03,                    //   Usage Maximum (3)                 117
 * # 0x15, 0x00,                    //   Logical Minimum (0)               119
 * # 0x25, 0x01,                    //   Logical Maximum (1)               121
 * # 0x95, 0x03,                    //   Report Count (3)                  123
 * # 0x75, 0x01,                    //   Report Size (1)                   125
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              127
 * # 0x95, 0x05,                    //   Report Count (5)                  129
 * # 0x81, 0x01,                    //   Input (Cnst,Arr,Abs)              131
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      133
 * # 0x09, 0x30,                    //   Usage (X)                         135
 * # 0x75, 0x10,                    //   Report Size (16)                  137
 * # 0x95, 0x01,                    //   Report Count (1)                  139
 * # 0xa4,                          //   Push                              141
 * # 0x35, 0x00,                    //   Physical Minimum (0)              142
 * # 0x46, 0x00, 0x08,              //   Physical Maximum (2048)           144
 * # 0x26, 0x00, 0x08,              //   Logical Maximum (2048)            147
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              150
 * # 0x09, 0x31,                    //   Usage (Y)                         152
 * # 0x46, 0x00, 0x08,              //   Physical Maximum (2048)           154
 * # 0x26, 0x00, 0x08,              //   Logical Maximum (2048)            157
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              160
 * # 0xb4,                          //   Pop                               162
 * # 0x05, 0x0d,                    //   Usage Page (Digitizers)           163
 * # 0x09, 0x30,                    //   Usage (Tip Pressure)              165
 * # 0x26, 0xff, 0x07,              //   Logical Maximum (2047)            167
 * # 0x46, 0xff, 0x07,              //   Physical Maximum (2047)           170
 * # 0x75, 0x10,                    //   Report Size (16)                  173
 * # 0x81, 0xb2,                    //   Input (Data,Var,Abs,NonLin,NoPref,Vol) 175
 * # 0xc0,                          //  End Collection                     177
 * # 0xc0,                          // End Collection                      178
 * #
 * R: 179 05 0d 09 02 a1 01 85 07 09 20 a1 00 09 42 09 44 09 45 09 3c 09 43 09 44 15 00 25 01 75 01 95 06 81 02 09 32 75 01 95 01 81 02 81 03 05 01 09 30 75 10 95 01 a4 55 0d 65 13 35 00 46 10 27 27 40 9c 00 00 81 02 09 31 46 6a 18 26 a8 61 81 02 b4 05 0d 09 30 26 ff 07 46 ff 07 55 00 66 11 e1 75 10 81 02 c0 c0 05 01 09 02 a1 01 85 09 09 01 a1 00 05 09 19 01 29 03 15 00 25 01 95 03 75 01 81 02 95 05 81 01 05 01 09 30 75 10 95 01 a4 35 00 46 00 08 26 00 08 81 02 09 31 46 00 08 26 00 08 81 02 b4 05 0d 09 30 26 ff 07 46 ff 07 75 10 81 b2 c0 c0
 *
 * This rdesc does nothing until the tablet is switched to raw mode, see
 * https://github.com/whot/huion-switcher
 *
 *
 * Second hidraw node is the Pen. This one sends events until the tablet is
 * switched to raw mode, then it's mute.
 *
 * # Report descriptor length: 244 bytes
 * # HUION PenTablet
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
 * # 0x09, 0x02,                    // Usage (Mouse)                       2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x05, 0x01,                    //  Usage Page (Generic Desktop)       6
 * # 0x09, 0x02,                    //  Usage (Mouse)                      8
 * # 0xa1, 0x02,                    //  Collection (Logical)               10
 * # 0x85, 0x01,                    //   Report ID (1)                     12
 * # 0x09, 0x01,                    //   Usage (Pointer)                   14
 * # 0xa1, 0x00,                    //   Collection (Physical)             16
 * # 0x05, 0x09,                    //    Usage Page (Button)              18
 * # 0x19, 0x01,                    //    Usage Minimum (1)                20
 * # 0x29, 0x05,                    //    Usage Maximum (5)                22
 * # 0x95, 0x05,                    //    Report Count (5)                 24
 * # 0x75, 0x01,                    //    Report Size (1)                  26
 * # 0x15, 0x00,                    //    Logical Minimum (0)              28
 * # 0x25, 0x01,                    //    Logical Maximum (1)              30
 * # 0x81, 0x02,                    //    Input (Data,Var,Abs)             32
 * # 0x95, 0x03,                    //    Report Count (3)                 34
 * # 0x81, 0x01,                    //    Input (Cnst,Arr,Abs)             36
 * # 0x05, 0x01,                    //    Usage Page (Generic Desktop)     38
 * # 0x09, 0x30,                    //    Usage (X)                        40
 * # 0x09, 0x31,                    //    Usage (Y)                        42
 * # 0x95, 0x02,                    //    Report Count (2)                 44
 * # 0x75, 0x10,                    //    Report Size (16)                 46
 * # 0x16, 0x00, 0x80,              //    Logical Minimum (-32768)         48
 * # 0x26, 0xff, 0x7f,              //    Logical Maximum (32767)          51
 * # 0x81, 0x06,                    //    Input (Data,Var,Rel)             54
 * # 0xa1, 0x02,                    //    Collection (Logical)             56
 * # 0x85, 0x02,                    //     Report ID (2)                   58
 * # 0x09, 0x48,                    //     Usage (Resolution Multiplier)   60
 * # 0x15, 0x00,                    //     Logical Minimum (0)             62
 * # 0x25, 0x01,                    //     Logical Maximum (1)             64
 * # 0x35, 0x01,                    //     Physical Minimum (1)            66
 * # 0x45, 0x04,                    //     Physical Maximum (4)            68
 * # 0x95, 0x01,                    //     Report Count (1)                70
 * # 0x75, 0x02,                    //     Report Size (2)                 72
 * # 0xb1, 0x02,                    //     Feature (Data,Var,Abs)          74
 * # 0x85, 0x01,                    //     Report ID (1)                   76
 * # 0x09, 0x38,                    //     Usage (Wheel)                   78
 * # 0x35, 0x00,                    //     Physical Minimum (0)            80
 * # 0x45, 0x00,                    //     Physical Maximum (0)            82
 * # 0x15, 0x81,                    //     Logical Minimum (-127)          84
 * # 0x25, 0x7f,                    //     Logical Maximum (127)           86
 * # 0x75, 0x08,                    //     Report Size (8)                 88
 * # 0x81, 0x06,                    //     Input (Data,Var,Rel)            90
 * # 0xc0,                          //    End Collection                   92
 * # 0xa1, 0x02,                    //    Collection (Logical)             93
 * # 0x85, 0x02,                    //     Report ID (2)                   95
 * # 0x09, 0x48,                    //     Usage (Resolution Multiplier)   97
 * # 0x15, 0x00,                    //     Logical Minimum (0)             99
 * # 0x25, 0x01,                    //     Logical Maximum (1)             101
 * # 0x35, 0x01,                    //     Physical Minimum (1)            103
 * # 0x45, 0x04,                    //     Physical Maximum (4)            105
 * # 0x75, 0x02,                    //     Report Size (2)                 107
 * # 0xb1, 0x02,                    //     Feature (Data,Var,Abs)          109
 * # 0x35, 0x00,                    //     Physical Minimum (0)            111
 * # 0x45, 0x00,                    //     Physical Maximum (0)            113
 * # 0x75, 0x04,                    //     Report Size (4)                 115
 * # 0xb1, 0x01,                    //     Feature (Cnst,Arr,Abs)          117
 * # 0x85, 0x01,                    //     Report ID (1)                   119
 * # 0x05, 0x0c,                    //     Usage Page (Consumer Devices)   121
 * # 0x0a, 0x38, 0x02,              //     Usage (AC Pan)                  123
 * # 0x15, 0x81,                    //     Logical Minimum (-127)          126
 * # 0x25, 0x7f,                    //     Logical Maximum (127)           128
 * # 0x75, 0x08,                    //     Report Size (8)                 130
 * # 0x81, 0x06,                    //     Input (Data,Var,Rel)            132
 * # 0xc0,                          //    End Collection                   134
 * # 0xc0,                          //   End Collection                    135
 * # 0xc0,                          //  End Collection                     136
 * # 0xc0,                          // End Collection                      137
 * # 0x06, 0x01, 0xff,              // Usage Page (Vendor Usage Page 0xff01) 138
 * # 0x09, 0x00,                    // Usage (Vendor Usage 0x00)           141
 * # 0xa1, 0x01,                    // Collection (Application)            143
 * # 0x85, 0x08,                    //  Report ID (8)                      145
 * # 0x15, 0x00,                    //  Logical Minimum (0)                147
 * # 0x26, 0xff, 0x00,              //  Logical Maximum (255)              149
 * # 0x09, 0x00,                    //  Usage (Vendor Usage 0x00)          152
 * # 0x75, 0x08,                    //  Report Size (8)                    154
 * # 0x95, 0x05,                    //  Report Count (5)                   156
 * # 0xb1, 0x02,                    //  Feature (Data,Var,Abs)             158
 * # 0xc0,                          // End Collection                      160
 * # 0x05, 0x0d,                    // Usage Page (Digitizers)             161
 * # 0x09, 0x02,                    // Usage (Pen)                         163
 * # 0xa1, 0x01,                    // Collection (Application)            165
 * # 0x85, 0x0a,                    //  Report ID (10)                     167
 * # 0x09, 0x20,                    //  Usage (Stylus)                     169
 * # 0xa1, 0x00,                    //  Collection (Physical)              171
 * # 0x09, 0x42,                    //   Usage (Tip Switch)                173
 * # 0x09, 0x44,                    //   Usage (Barrel Switch)             175
 * # 0x09, 0x45,                    //   Usage (Eraser)                    177
 * # 0x09, 0x3c,                    //   Usage (Invert)                    179
 * # 0x09, 0x43,                    //   Usage (Secondary Tip Switch)      181
 * # 0x09, 0x44,                    //   Usage (Barrel Switch)             183
 * # 0x15, 0x00,                    //   Logical Minimum (0)               185
 * # 0x25, 0x01,                    //   Logical Maximum (1)               187
 * # 0x75, 0x01,                    //   Report Size (1)                   189
 * # 0x95, 0x06,                    //   Report Count (6)                  191
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              193
 * # 0x09, 0x32,                    //   Usage (In Range)                  195
 * # 0x75, 0x01,                    //   Report Size (1)                   197
 * # 0x95, 0x01,                    //   Report Count (1)                  199
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              201
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)              203
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      205
 * # 0x09, 0x30,                    //   Usage (X)                         207
 * # 0x09, 0x31,                    //   Usage (Y)                         209
 * # 0x55, 0x0d,                    //   Unit Exponent (-3)                211
 * # 0x65, 0x33,                    //   Unit (EnglishLinear: in³)         213
 * # 0x26, 0x00, 0x08,              //   Logical Maximum (2048)            215
 * # 0x35, 0x00,                    //   Physical Minimum (0)              218
 * # 0x46, 0x00, 0x08,              //   Physical Maximum (2048)           220
 * # 0x75, 0x10,                    //   Report Size (16)                  223
 * # 0x95, 0x02,                    //   Report Count (2)                  225
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              227
 * # 0x05, 0x0d,                    //   Usage Page (Digitizers)           229
 * # 0x09, 0x30,                    //   Usage (Tip Pressure)              231
 * # 0x26, 0xff, 0x07,              //   Logical Maximum (2047)            233
 * # 0x75, 0x10,                    //   Report Size (16)                  236
 * # 0x95, 0x01,                    //   Report Count (1)                  238
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              240
 * # 0xc0,                          //  End Collection                     242
 * # 0xc0,                          // End Collection                      243
 * #
 * R: 244 05 01 09 02 a1 01 05 01 09 02 a1 02 85 01 09 01 a1 00 05 09 19 01 29 05 95 05 75 01 15 00 25 01 81 02 95 03 81 01 05 01 09 30 09 31 95 02 75 10 16 00 80 26 ff 7f 81 06 a1 02 85 02 09 48 15 00 25 01 35 01 45 04 95 01 75 02 b1 02 85 01 09 38 35 00 45 00 15 81 25 7f 75 08 81 06 c0 a1 02 85 02 09 48 15 00 25 01 35 01 45 04 75 02 b1 02 35 00 45 00 75 04 b1 01 85 01 05 0c 0a 38 02 15 81 25 7f 75 08 81 06 c0 c0 c0 c0 06 01 ff 09 00 a1 01 85 08 15 00 26 ff 00 09 00 75 08 95 05 b1 02 c0 05 0d 09 02 a1 01 85 0a 09 20 a1 00 09 42 09 44 09 45 09 3c 09 43 09 44 15 00 25 01 75 01 95 06 81 02 09 32 75 01 95 01 81 02 81 03 05 01 09 30 09 31 55 0d 65 33 26 00 08 35 00 46 00 08 75 10 95 02 81 02 05 0d 09 30 26 ff 07 75 10 95 01 81 02 c0 c0*
 *
 *
 * Third hidraw node is the pad which sends a combination of keyboard shortcuts until
 * the tablet is switched to raw mode, then it's mute:
 *
 * # Report descriptor length: 92 bytes
 * # HUION PenTablet
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
 * # 0x09, 0x06,                    // Usage (Keyboard)                    2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x85, 0x03,                    //  Report ID (3)                      6
 * # 0x05, 0x07,                    //  Usage Page (Keyboard)              8
 * # 0x19, 0xe0,                    //  Usage Minimum (224)                10
 * # 0x29, 0xe7,                    //  Usage Maximum (231)                12
 * # 0x15, 0x00,                    //  Logical Minimum (0)                14
 * # 0x25, 0x01,                    //  Logical Maximum (1)                16
 * # 0x75, 0x01,                    //  Report Size (1)                    18
 * # 0x95, 0x08,                    //  Report Count (8)                   20
 * # 0x81, 0x02,                    //  Input (Data,Var,Abs)               22
 * # 0x05, 0x07,                    //  Usage Page (Keyboard)              24
 * # 0x19, 0x00,                    //  Usage Minimum (0)                  26
 * # 0x29, 0xff,                    //  Usage Maximum (255)                28
 * # 0x26, 0xff, 0x00,              //  Logical Maximum (255)              30
 * # 0x75, 0x08,                    //  Report Size (8)                    33
 * # 0x95, 0x06,                    //  Report Count (6)                   35
 * # 0x81, 0x00,                    //  Input (Data,Arr,Abs)               37
 * # 0xc0,                          // End Collection                      39
 * # 0x05, 0x0c,                    // Usage Page (Consumer Devices)       40
 * # 0x09, 0x01,                    // Usage (Consumer Control)            42
 * # 0xa1, 0x01,                    // Collection (Application)            44
 * # 0x85, 0x04,                    //  Report ID (4)                      46
 * # 0x19, 0x00,                    //  Usage Minimum (0)                  48
 * # 0x2a, 0x3c, 0x02,              //  Usage Maximum (572)                50
 * # 0x15, 0x00,                    //  Logical Minimum (0)                53
 * # 0x26, 0x3c, 0x02,              //  Logical Maximum (572)              55
 * # 0x95, 0x01,                    //  Report Count (1)                   58
 * # 0x75, 0x10,                    //  Report Size (16)                   60
 * # 0x81, 0x00,                    //  Input (Data,Arr,Abs)               62
 * # 0xc0,                          // End Collection                      64
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        65
 * # 0x09, 0x80,                    // Usage (System Control)              67
 * # 0xa1, 0x01,                    // Collection (Application)            69
 * # 0x85, 0x05,                    //  Report ID (5)                      71
 * # 0x19, 0x81,                    //  Usage Minimum (129)                73
 * # 0x29, 0x83,                    //  Usage Maximum (131)                75
 * # 0x15, 0x00,                    //  Logical Minimum (0)                77
 * # 0x25, 0x01,                    //  Logical Maximum (1)                79
 * # 0x75, 0x01,                    //  Report Size (1)                    81
 * # 0x95, 0x03,                    //  Report Count (3)                   83
 * # 0x81, 0x02,                    //  Input (Data,Var,Abs)               85
 * # 0x95, 0x05,                    //  Report Count (5)                   87
 * # 0x81, 0x01,                    //  Input (Cnst,Arr,Abs)               89
 * # 0xc0,                          // End Collection                      91
 * #
 * R: 92 05 01 09 06 a1 01 85 03 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 05 07 19 00 29 ff 26 ff 00 75 08 95 06 81 00 c0 05 0c 09 01 a1 01 85 04 19 00 2a 3c 02 15 00 26 3c 02 95 01 75 10 81 00 c0 05 01 09 80 a1 01 85 05 19 81 29 83 15 00 25 01 75 01 95 03 81 02 95 05 81 01 c0
 */

#define PAD_REPORT_DESCRIPTOR_LENGTH 92
#define PEN_REPORT_DESCRIPTOR_LENGTH 244
#define VENDOR_REPORT_DESCRIPTOR_LENGTH 179
#define PAD_REPORT_ID 10
#define VENDOR_REPORT_ID 7
#define PAD_REPORT_LENGTH 8
#define PEN_REPORT_LENGTH 8
#define VENDOR_REPORT_LENGTH 8

static const __u8 fixed_rdesc_vendor[] = {
	UsagePage_Digitizers
	Usage_Dig_Digitizer
	CollectionApplication(
		// -- Byte 0 in report
		ReportId(VENDOR_REPORT_ID)
		Usage_Dig_Stylus
		CollectionPhysical(
			// -- Byte 1 in report
			LogicalRange_i8(0, 1)
			ReportSize(1)
			Usage_Dig_TipSwitch
			Usage_Dig_BarrelSwitch
			Usage_Dig_SecondaryBarrelSwitch
			ReportCount(3)
			Input(Var|Abs)
			ReportCount(3) // Padding
			Input(Const)
			Usage_Dig_InRange
			ReportCount(1)
			Input(Var|Abs)
			ReportCount(1) // Padding
			Input(Const)
			ReportSize(16)
			ReportCount(1)
			PushPop(
				// -- Byte 2-3 in report
				UsagePage_GenericDesktop
				Unit(in)
				UnitExponent(-3)
				LogicalRange_i16(0, 40000)
				PhysicalRange_i16(0, 10000)
				Usage_GD_X
				Input(Var|Abs)
				// -- Byte 4-5 in report
				LogicalRange_i16(0, 25000)
				PhysicalRange_i16(0, 6250)
				Usage_GD_Y
				Input(Var|Abs)
			)
			// -- Byte 6-7 in report
			LogicalRange_i16(0, 2047)
			Usage_Dig_TipPressure
			Input(Var|Abs)
		)
	)
	UsagePage_GenericDesktop
	Usage_GD_Keypad
	CollectionApplication(
		// -- Byte 0 in report
		ReportId(PAD_REPORT_ID)
		LogicalRange_i8(0, 1)
		UsagePage_Digitizers
		Usage_Dig_TabletFunctionKeys
		CollectionPhysical(
			// Byte 1 in report - just exists so we get to be a tablet pad
			Usage_Dig_BarrelSwitch	 // BtnStylus
			ReportCount(1)
			ReportSize(1)
			Input(Var|Abs)
			ReportCount(7) // Padding
			Input(Const)
			// Bytes 2/3 in report - just exists so we get to be a tablet pad
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			ReportCount(2)
			ReportSize(8)
			Input(Var|Abs)
		)
		// Byte 4 is the button state
		UsagePage_Button
		UsageRange_i8(0x01, 0x8)
		LogicalRange_i8(0x0, 0x1)
		ReportCount(8)
		ReportSize(1)
		Input(Var|Abs)
	)
};

static const __u8 disabled_rdesc_pen[] = {
	FixedSizeVendorReport(PEN_REPORT_LENGTH)
};

static const __u8 disabled_rdesc_pad[] = {
	FixedSizeVendorReport(PAD_REPORT_LENGTH)
};

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(h610_pro_fix_rdesc, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);
	__s32 rdesc_size = hctx->size;

	if (!data)
		return 0; /* EPERM check */

	/* If we have a firmware ID and it matches our expected prefix, we
	 * disable the default pad/pen nodes. They won't send events
	 * but cause duplicate devices.
	 */
	switch(rdesc_size) {
	case VENDOR_REPORT_DESCRIPTOR_LENGTH:
		__builtin_memcpy(data, fixed_rdesc_vendor, sizeof(fixed_rdesc_vendor));
		return sizeof(fixed_rdesc_vendor);
	case PAD_REPORT_DESCRIPTOR_LENGTH:
		__builtin_memcpy(data, disabled_rdesc_pad, sizeof(disabled_rdesc_pad));
		return sizeof(disabled_rdesc_pad);
	case PEN_REPORT_DESCRIPTOR_LENGTH:
		__builtin_memcpy(data, disabled_rdesc_pen, sizeof(disabled_rdesc_pen));
		return sizeof(disabled_rdesc_pen);
	}
	return 0;
}

struct stylus_report {
	__u8 report_id;
	bool tip_switch: 1;
	bool barrel_switch: 1;
	bool secondary_barrel_switch: 1;
	__u8 padding_0: 2;
	bool is_pad: 1;
	bool in_range: 1;
	bool padding_1: 1;
	__u16 x;
	__u16 y;
	__u16 pressure;
} __attribute__((packed));

struct pad_report {
	__u8 report_id;
	__u8 btn_stylus;
	__u8 x;
	__u8 y;
	__u8 btn;
} __attribute__((packed));

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(h610_pro_fix_event, struct hid_bpf_ctx *hid_ctx)
{
	struct stylus_report *data = (struct stylus_report *)hid_bpf_get_data(hid_ctx,
									      0 /* offset */,
									      sizeof(*data));

	if (!data)
		return 0; /* EPERM check */

	if (data->report_id != VENDOR_REPORT_ID)
		return 0;

	if (data->is_pad) {/* Pad event */
		struct pad_report *p = (struct pad_report *)data;

		p->report_id = PAD_REPORT_ID;

		/*
		 * force the unused values to be 0,
		 * ideally they should be declared as Const but we
		 * need them to teach userspace that this is a
		 * tablet pad device node
		 */
		p->btn_stylus = 0;
		p->x = 0;
		p->y = 0;

		return sizeof(*p);
	}

	/* In Range is inverted */
	data->in_range = !data->in_range;

	return sizeof(*data);
}

HID_BPF_OPS(h610_pro) = {
	.hid_device_event = (void *)h610_pro_fix_event,
	.hid_rdesc_fixup = (void *)h610_pro_fix_rdesc,
};

int magic_bytes_to_u16(const char *data)
{
	long int res;
	int ret;

	/* data is a char[], so we need 4 chars to get 2 bytes */
	ret = bpf_strtol(data, 4, 16, &res);
	if (ret < 0)
		return ret;

	/* bytes need to be swapped because we get the string "LLHH",
	 * which should translate as 0xHHLL while strol translates it
	 * "in the obvious manner", which is 0xLLHH.
	 */
	return __builtin_bswap16(res);
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
#define MATCHES_STRING(_input, _match)			\
	(__builtin_memcmp(_input,			\
			  _match,			\
			  sizeof(_match) - 1) == 0)
	__u8 have_fw_id = MATCHES_STRING(UDEV_PROP_HUION_FIRMWARE_ID, EXPECTED_FIRMWARE_ID);
#undef MATCHES_STRING

	int x_lmax = magic_bytes_to_u16(UDEV_PROP_HUION_MAGIC_BYTES + X_LOGICAL_MAX_IDX);
	int y_lmax = magic_bytes_to_u16(UDEV_PROP_HUION_MAGIC_BYTES + Y_LOGICAL_MAX_IDX);
	int pressure_lmax = magic_bytes_to_u16(UDEV_PROP_HUION_MAGIC_BYTES + PRESSURE_LOGICAL_MAX_IDX);
	int resolution = magic_bytes_to_u16(UDEV_PROP_HUION_MAGIC_BYTES + RESOLUTION_IDX);

	/* if firmware ID is not set or doesn't match, we abort: we don't know
	 * if the device is ours or not.
	 * Likewise, if the parameters are wrong, we abort
	 */
	if (!have_fw_id ||
	    x_lmax != EXPECTED_X_LOGICAL_MAX ||
	    y_lmax != EXPECTED_Y_LOGICAL_MAX ||
	    pressure_lmax != EXPECTED_PRESSURE_LOGICAL_MAX ||
	    resolution != EXPECTED_RESOLUTION) {
		ctx->retval = -EINVAL;
		return 0;
	}


	switch (ctx->rdesc_size) {
	case PAD_REPORT_DESCRIPTOR_LENGTH:
	case PEN_REPORT_DESCRIPTOR_LENGTH:
	case VENDOR_REPORT_DESCRIPTOR_LENGTH:
		ctx->retval = 0;
		break;
	default:
		ctx->retval = -EINVAL;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
