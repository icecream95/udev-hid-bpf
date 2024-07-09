// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define VID_MICROSOFT 0x045E
#define PID_SURFACE_DIAL 0x091B

HID_BPF_CONFIG(
	HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_GENERIC, VID_MICROSOFT, PID_SURFACE_DIAL)
);

/* How this BPF program works: the device is presented by default as a dial,
 * but we want to transform into a mouse so we can use the rotating knob as
 * a scroll wheel. We need to amend the report descriptor to export regular
 * wheel events instead of dial and X/Y coordinates needs to be reported as
 * "relative" to be understood as a mouse.
 *
 * We can control the resolution of the wheel events through the feature
 * Usage_GD_ResolutionMultiplier. And given that the device supports haptic
 * feedback, we can enable haptic 'ticks' when we are in low resolution mode.
 *
 * We have a 2 seconds timer when the button is pressed to switch between low
 * resolution and high resolution.
 *
 * We need to fix 2 other issues:
 * - bluez now doesn't remove the device when it disconnects and goes into sleep
 *   mode. We need a reasonable timer to detect that the device is likely in sleep
 *   mode and when it comes back, we thus needs to resend our haptic configuration
 *   (luckily the device is keeping the resolution after resume, so the events are
 *   not messed up, just the haptics are disabled)
 * - whenever the button is pressed, the device sends a KEY_WAKEUP event, without
 *   releasing it ever. This confuses the system a bit.
 *
 * Default report descriptor for the exposed hidraw node:
 *
 * # Surface Dial
 * # Report descriptor length: 488 bytes
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)              0
 * # 0x09, 0x0e,                    // Usage (System Multi-Axis Controller)      2
 * # 0xa1, 0x01,                    // Collection (Application)                  4
 * # 0x85, 0x01,                    //   Report ID (1)                           6
 * # 0x05, 0x0d,                    //   Usage Page (Digitizers)                 8
 * # 0x09, 0x21,                    //   Usage (Puck)                            10
 * # 0xa1, 0x02,                    //   Collection (Logical)                    12
 * # 0x15, 0x00,                    //     Logical Minimum (0)                   14
 * # 0x25, 0x01,                    //     Logical Maximum (1)                   16
 * # 0x75, 0x01,                    //     Report Size (1)                       18
 * # 0x95, 0x01,                    //     Report Count (1)                      20
 * # 0xa1, 0x00,                    //     Collection (Physical)                 22
 * # 0x05, 0x09,                    //       Usage Page (Button)                 24
 * # 0x09, 0x01,                    //       Usage (Button 1)                    26
 * # 0x81, 0x02,                    //       Input (Data,Var,Abs)                28
 * # 0x05, 0x0d,                    //       Usage Page (Digitizers)             30
 * # 0x09, 0x33,                    //       Usage (Touch)                       32
 * # 0x81, 0x02,                    //       Input (Data,Var,Abs)                34
 * # 0x95, 0x06,                    //       Report Count (6)                    36
 * # 0x81, 0x03,                    //       Input (Cnst,Var,Abs)                38
 * # 0xa1, 0x02,                    //       Collection (Logical)                40
 * # 0x05, 0x01,                    //         Usage Page (Generic Desktop)      42
 * # 0x09, 0x37,                    //         Usage (Dial)                      44
 * # 0x16, 0x01, 0x80,              //         Logical Minimum (-32767)          46
 * # 0x26, 0xff, 0x7f,              //         Logical Maximum (32767)           49
 * # 0x75, 0x10,                    //         Report Size (16)                  52
 * # 0x95, 0x01,                    //         Report Count (1)                  54
 * # 0x81, 0x06,                    //         Input (Data,Var,Rel)              56
 * # 0x35, 0x00,                    //         Physical Minimum (0)              58
 * # 0x46, 0x10, 0x0e,              //         Physical Maximum (3600)           60
 * # 0x15, 0x00,                    //         Logical Minimum (0)               63
 * # 0x26, 0x10, 0x0e,              //         Logical Maximum (3600)            65
 * # 0x09, 0x48,                    //         Usage (Resolution Multiplier)     68
 * # 0xb1, 0x02,                    //         Feature (Data,Var,Abs)            70
 * # 0x45, 0x00,                    //         Physical Maximum (0)              72
 * # 0xc0,                          //       End Collection                      74
 * # 0x55, 0x0e,                    //       Unit Exponent (-2)                  75
 * # 0x65, 0x11,                    //       Unit (SILinear: cm)                 77
 * # 0x46, 0x00, 0x00,              //       Physical Maximum (0)                79
 * # 0x26, 0x00, 0x00,              //       Logical Maximum (0)                 82
 * # 0x09, 0x30,                    //       Usage (X)                           85
 * # 0x81, 0x42,                    //       Input (Data,Var,Abs,Null)           87
 * # 0x09, 0x31,                    //       Usage (Y)                           89
 * # 0x46, 0x00, 0x00,              //       Physical Maximum (0)                91
 * # 0x26, 0x00, 0x00,              //       Logical Maximum (0)                 94
 * # 0x81, 0x42,                    //       Input (Data,Var,Abs,Null)           97
 * # 0x05, 0x0d,                    //       Usage Page (Digitizers)             99
 * # 0x09, 0x48,                    //       Usage (Width)                       101
 * # 0x15, 0x3a,                    //       Logical Minimum (58)                103
 * # 0x25, 0x3a,                    //       Logical Maximum (58)                105
 * # 0x75, 0x08,                    //       Report Size (8)                     107
 * # 0x55, 0x0f,                    //       Unit Exponent (-1)                  109
 * # 0x35, 0x3a,                    //       Physical Minimum (58)               111
 * # 0x45, 0x3a,                    //       Physical Maximum (58)               113
 * # 0x81, 0x03,                    //       Input (Cnst,Var,Abs)                115
 * # 0x55, 0x00,                    //       Unit Exponent (0)                   117
 * # 0x65, 0x00,                    //       Unit (None)                         119
 * # 0x35, 0x00,                    //       Physical Minimum (0)                121
 * # 0x45, 0x00,                    //       Physical Maximum (0)                123
 * # 0x05, 0x0e,                    //       Usage Page (Haptics)                125
 * # 0x09, 0x01,                    //       Usage (Simple Haptic Controller)    127
 * # 0xa1, 0x02,                    //       Collection (Logical)                129
 * # 0x15, 0x00,                    //         Logical Minimum (0)               131
 * # 0x26, 0xff, 0x00,              //         Logical Maximum (255)             133
 * # 0x09, 0x24,                    //         Usage (Repeat Count)              136
 * # 0xb1, 0x42,                    //         Feature (Data,Var,Abs,Null)       138
 * # 0x09, 0x24,                    //         Usage (Repeat Count)              140
 * # 0x91, 0x42,                    //         Output (Data,Var,Abs,Null)        142
 * # 0x15, 0x01,                    //         Logical Minimum (1)               144
 * # 0x25, 0x07,                    //         Logical Maximum (7)               146
 * # 0x09, 0x20,                    //         Usage (Auto Trigger)              148
 * # 0xb1, 0x42,                    //         Feature (Data,Var,Abs,Null)       150
 * # 0x09, 0x21,                    //         Usage (Manual Trigger)            152
 * # 0x91, 0x42,                    //         Output (Data,Var,Abs,Null)        154
 * # 0x25, 0x0a,                    //         Logical Maximum (10)              156
 * # 0x09, 0x28,                    //         Usage (Waveform Cutoff Time)      158
 * # 0xb1, 0x42,                    //         Feature (Data,Var,Abs,Null)       160
 * # 0x75, 0x10,                    //         Report Size (16)                  162
 * # 0x26, 0xd0, 0x07,              //         Logical Maximum (2000)            164
 * # 0x09, 0x25,                    //         Usage (Retrigger Period)          167
 * # 0xb1, 0x42,                    //         Feature (Data,Var,Abs,Null)       169
 * # 0x09, 0x25,                    //         Usage (Retrigger Period)          171
 * # 0x91, 0x42,                    //         Output (Data,Var,Abs,Null)        173
 * # 0x85, 0x02,                    //         Report ID (2)                     175
 * # 0x75, 0x20,                    //         Report Size (32)                  177
 * # 0x17, 0x37, 0x00, 0x01, 0x00,  //         Logical Minimum (65591)           179
 * # 0x27, 0x37, 0x00, 0x01, 0x00,  //         Logical Maximum (65591)           184
 * # 0x09, 0x22,                    //         Usage (Auto Trigger Associated Control) 189
 * # 0xb1, 0x02,                    //         Feature (Data,Var,Abs)            191
 * # 0x09, 0x11,                    //         Usage (Duration List)             193
 * # 0xa1, 0x02,                    //         Collection (Logical)              195
 * # 0x05, 0x0a,                    //           Usage Page (Ordinal)            197
 * # 0x95, 0x03,                    //           Report Count (3)                199
 * # 0x09, 0x03,                    //           Usage (Instance 3)              201
 * # 0x09, 0x04,                    //           Usage (Instance 4)              203
 * # 0x09, 0x05,                    //           Usage (Instance 5)              205
 * # 0x75, 0x08,                    //           Report Size (8)                 207
 * # 0x15, 0x00,                    //           Logical Minimum (0)             209
 * # 0x25, 0xff,                    //           Logical Maximum (255)           211
 * # 0xb1, 0x02,                    //           Feature (Data,Var,Abs)          213
 * # 0xc0,                          //         End Collection                    215
 * # 0x05, 0x0e,                    //         Usage Page (Haptics)              216
 * # 0x09, 0x10,                    //         Usage (Waveform List)             218
 * # 0xa1, 0x02,                    //         Collection (Logical)              220
 * # 0x05, 0x0a,                    //           Usage Page (Ordinal)            222
 * # 0x95, 0x01,                    //           Report Count (1)                224
 * # 0x15, 0x03,                    //           Logical Minimum (3)             226
 * # 0x25, 0x03,                    //           Logical Maximum (3)             228
 * # 0x36, 0x03, 0x10,              //           Physical Minimum (4099)         230
 * # 0x46, 0x03, 0x10,              //           Physical Maximum (4099)         233
 * # 0x09, 0x03,                    //           Usage (Instance 3)              236
 * # 0xb1, 0x02,                    //           Feature (Data,Var,Abs)          238
 * # 0x15, 0x04,                    //           Logical Minimum (4)             240
 * # 0x25, 0x04,                    //           Logical Maximum (4)             242
 * # 0x36, 0x04, 0x10,              //           Physical Minimum (4100)         244
 * # 0x46, 0x04, 0x10,              //           Physical Maximum (4100)         247
 * # 0x09, 0x04,                    //           Usage (Instance 4)              250
 * # 0xb1, 0x02,                    //           Feature (Data,Var,Abs)          252
 * # 0x15, 0x05,                    //           Logical Minimum (5)             254
 * # 0x25, 0x05,                    //           Logical Maximum (5)             256
 * # 0x36, 0x04, 0x10,              //           Physical Minimum (4100)         258
 * # 0x46, 0x04, 0x10,              //           Physical Maximum (4100)         261
 * # 0x09, 0x05,                    //           Usage (Instance 5)              264
 * # 0xb1, 0x02,                    //           Feature (Data,Var,Abs)          266
 * # 0x35, 0x00,                    //           Physical Minimum (0)            268
 * # 0x45, 0x00,                    //           Physical Maximum (0)            270
 * # 0xc0,                          //         End Collection                    272
 * # 0xc0,                          //       End Collection                      273
 * # 0xc0,                          //     End Collection                        274
 * # 0xc0,                          //   End Collection                          275
 * # 0xc0,                          // End Collection                            276
 * # 0x06, 0x07, 0xff,              // Usage Page (Vendor Defined Page FF07)     277
 * # 0x09, 0x70,                    // Usage (Vendor Usage 0x70)                 280
 * # 0xa1, 0x01,                    // Collection (Application)                  282
 * # 0x85, 0x30,                    //   Report ID (48)                          284
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     286
 * # 0x25, 0xff,                    //   Logical Maximum (255)                   288
 * # 0x95, 0x01,                    //   Report Count (1)                        290
 * # 0x75, 0x08,                    //   Report Size (8)                         292
 * # 0x09, 0x00,                    //   Usage (Vendor Usage 0x00)               294
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   296
 * # 0xc0,                          // End Collection                            298
 * # 0x09, 0x71,                    // Usage (Vendor Usage 0x71)                 299
 * # 0xa1, 0x01,                    // Collection (Application)                  301
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     303
 * # 0x25, 0xff,                    //   Logical Maximum (255)                   305
 * # 0x75, 0x08,                    //   Report Size (8)                         307
 * # 0x95, 0x48,                    //   Report Count (72)                       309
 * # 0x85, 0x2a,                    //   Report ID (42)                          311
 * # 0x09, 0xc6,                    //   Usage (Vendor Usage 0xc6)               313
 * # 0x82, 0x02, 0x01,              //   Input (Data,Var,Abs,Buff)               315
 * # 0x09, 0xc7,                    //   Usage (Vendor Usage 0xc7)               318
 * # 0x92, 0x02, 0x01,              //   Output (Data,Var,Abs,Buff)              320
 * # 0x95, 0x34,                    //   Report Count (52)                       323
 * # 0x09, 0xc8,                    //   Usage (Vendor Usage 0xc8)               325
 * # 0xb2, 0x03, 0x01,              //   Feature (Cnst,Var,Abs,Buff)             327
 * # 0x85, 0x2b,                    //   Report ID (43)                          330
 * # 0x09, 0xc9,                    //   Usage (Vendor Usage 0xc9)               332
 * # 0x82, 0x02, 0x01,              //   Input (Data,Var,Abs,Buff)               334
 * # 0x09, 0xca,                    //   Usage (Vendor Usage 0xca)               337
 * # 0x92, 0x02, 0x01,              //   Output (Data,Var,Abs,Buff)              339
 * # 0x09, 0xcb,                    //   Usage (Vendor Usage 0xcb)               342
 * # 0xb2, 0x02, 0x01,              //   Feature (Data,Var,Abs,Buff)             344
 * # 0x17, 0x00, 0x00, 0x00, 0x80,  //   Logical Minimum (-2147483648)           347
 * # 0x27, 0xff, 0xff, 0xff, 0x7f,  //   Logical Maximum (2147483647)            352
 * # 0x75, 0x20,                    //   Report Size (32)                        357
 * # 0x95, 0x04,                    //   Report Count (4)                        359
 * # 0x85, 0x2c,                    //   Report ID (44)                          361
 * # 0x19, 0xcc,                    //   UsageMinimum (204)                      363
 * # 0x29, 0xcf,                    //   UsageMaximum (207)                      365
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    367
 * # 0x95, 0x04,                    //   Report Count (4)                        369
 * # 0x85, 0x2d,                    //   Report ID (45)                          371
 * # 0x19, 0xd8,                    //   UsageMinimum (216)                      373
 * # 0x29, 0xdb,                    //   UsageMaximum (219)                      375
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    377
 * # 0x95, 0x04,                    //   Report Count (4)                        379
 * # 0x19, 0xdc,                    //   UsageMinimum (220)                      381
 * # 0x29, 0xdf,                    //   UsageMaximum (223)                      383
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   385
 * # 0x19, 0xe0,                    //   UsageMinimum (224)                      387
 * # 0x29, 0xe3,                    //   UsageMaximum (227)                      389
 * # 0xb1, 0x02,                    //   Feature (Data,Var,Abs)                  391
 * # 0x85, 0x2e,                    //   Report ID (46)                          393
 * # 0x19, 0xe4,                    //   UsageMinimum (228)                      395
 * # 0x29, 0xe7,                    //   UsageMaximum (231)                      397
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    399
 * # 0x19, 0xe8,                    //   UsageMinimum (232)                      401
 * # 0x29, 0xeb,                    //   UsageMaximum (235)                      403
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   405
 * # 0x95, 0x0b,                    //   Report Count (11)                       407
 * # 0x19, 0xec,                    //   UsageMinimum (236)                      409
 * # 0x29, 0xef,                    //   UsageMaximum (239)                      411
 * # 0xb1, 0x02,                    //   Feature (Data,Var,Abs)                  413
 * # 0x95, 0x04,                    //   Report Count (4)                        415
 * # 0x85, 0x2f,                    //   Report ID (47)                          417
 * # 0x19, 0xf0,                    //   UsageMinimum (240)                      419
 * # 0x29, 0xf3,                    //   UsageMaximum (243)                      421
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    423
 * # 0x19, 0xf4,                    //   UsageMinimum (244)                      425
 * # 0x29, 0xf7,                    //   UsageMaximum (247)                      427
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   429
 * # 0x19, 0xf8,                    //   UsageMinimum (248)                      431
 * # 0x29, 0xfb,                    //   UsageMaximum (251)                      433
 * # 0xb1, 0x02,                    //   Feature (Data,Var,Abs)                  435
 * # 0xc0,                          // End Collection                            437
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)              438
 * # 0x09, 0x80,                    // Usage (System Control)                    440
 * # 0xa1, 0x01,                    // Collection (Application)                  442
 * # 0x85, 0x32,                    //   Report ID (50)                          444
 * # 0x09, 0x82,                    //   Usage (System Sleep)                    446
 * # 0x09, 0x83,                    //   Usage (System Wake Up)                  448
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     450
 * # 0x25, 0x01,                    //   Logical Maximum (1)                     452
 * # 0x95, 0x02,                    //   Report Count (2)                        454
 * # 0x75, 0x01,                    //   Report Size (1)                         456
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    458
 * # 0x95, 0x06,                    //   Report Count (6)                        460
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)                    462
 * # 0xc0,                          // End Collection                            464
 * # 0x09, 0x72,                    // Usage (0x0072)                            465
 * # 0xa1, 0x01,                    // Collection (Application)                  467
 * # 0x85, 0x31,                    //   Report ID (49)                          469
 * # 0x95, 0x0a,                    //   Report Count (10)                       471
 * # 0x75, 0x08,                    //   Report Size (8)                         473
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     475
 * # 0x25, 0xff,                    //   Logical Maximum (255)                   477
 * # 0x09, 0xc6,                    //   Usage (Wireless Radio Button)           479
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    481
 * # 0x09, 0xc7,                    //   Usage (Wireless Radio LED)              483
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   485
 * # 0xc0,                          // End Collection                            487
 * R: 488 05 01 09 0e a1 01 85 01 05 0d 09 21 a1 02 15 00 25 01 75 01 95 01 a1 00 05 09 09 01 81 02 05 0d 09 33 81 02 95 06 81 03 a1 02 05 01 09 37 16 01 80 26 ff 7f 75 10 95 01 81 06 35 00 46 10 0e 15 00 26 10 0e 09 48 b1 02 45 00 c0 55 0e 65 11 46 00 00 26 00 00 09 30 81 42 09 31 46 00 00 26 00 00 81 42 05 0d 09 48 15 3a 25 3a 75 08 55 0f 35 3a 45 3a 81 03 55 00 65 00 35 00 45 00 05 0e 09 01 a1 02 15 00 26 ff 00 09 24 b1 42 09 24 91 42 15 01 25 07 09 20 b1 42 09 21 91 42 25 0a 09 28 b1 42 75 10 26 d0 07 09 25 b1 42 09 25 91 42 85 02 75 20 17 37 00 01 00 27 37 00 01 00 09 22 b1 02 09 11 a1 02 05 0a 95 03 09 03 09 04 09 05 75 08 15 00 25 ff b1 02 c0 05 0e 09 10 a1 02 05 0a 95 01 15 03 25 03 36 03 10 46 03 10 09 03 b1 02 15 04 25 04 36 04 10 46 04 10 09 04 b1 02 15 05 25 05 36 04 10 46 04 10 09 05 b1 02 35 00 45 00 c0 c0 c0 c0 c0 06 07 ff 09 70 a1 01 85 30 15 00 25 ff 95 01 75 08 09 00 91 02 c0 09 71 a1 01 15 00 25 ff 75 08 95 48 85 2a 09 c6 82 02 01 09 c7 92 02 01 95 34 09 c8 b2 03 01 85 2b 09 c9 82 02 01 09 ca 92 02 01 09 cb b2 02 01 17 00 00 00 80 27 ff ff ff 7f 75 20 95 04 85 2c 19 cc 29 cf 81 02 95 04 85 2d 19 d8 29 db 81 02 95 04 19 dc 29 df 91 02 19 e0 29 e3 b1 02 85 2e 19 e4 29 e7 81 02 19 e8 29 eb 91 02 95 0b 19 ec 29 ef b1 02 95 04 85 2f 19 f0 29 f3 81 02 19 f4 29 f7 91 02 19 f8 29 fb b1 02 c0 05 01 09 80 a1 01 85 32 09 82 09 83 15 00 25 01 95 02 75 01 81 02 95 06 81 03 c0 09 72 a1 01 85 31 95 0a 75 08 15 00 25 ff 09 c6 81 02 09 c7 91 02 c0
 *
 */

#define ORIGINAL_RDESC_SIZE 488

#define CLOCK_MONOTONIC		1

#define DIAL_INPUT_REPORT_ID	0x01

/* 72 == 360 / 5 -> 1 report every 5 degrees */
#define LOW_RESOLUTION 72

/* ideally we'd want 360 but the kernel rejects any
 * value not fitting on a byte.
 * Any value greater than 120 is also a problem because
 * it computes "hi_res = value * 120/usage->resolution_multiplier;"
 * and given that at boot the value of the feature is the same than
 * logical_max (3600), resolution_multiplier == PhysicalMax in the
 * report descriptor.
 */
#define LOW_MULTIPLIER 120

/*
 * The high resolution and the multiplier is calculated as such:
 * - 72 means 1 report every 5 degrees and has a value of 120
 * - 360 means 1 report per degree and so the value is 120 / 5 = 24
 * - 720 means 2 reports per degree and so the value is 120 / 5 / 2 = 12
 * - 2880 means 8 reports per degree and so the value is 120 / 5 / 8 = 3
 */
#define HIGH_RESOLUTION 2880
#define HIGH_MULTIPLIER 3

static int current_multiplier;

static const __u8 fixed_rdesc[] = {
	UsagePage_GenericDesktop
	Usage_GD_SystemMultiAxisController
	CollectionApplication(
		ReportId(DIAL_INPUT_REPORT_ID)
		UsagePage_Digitizers
		Usage_Dig_Puck
		CollectionLogical(
			LogicalRange_i8(0, 1)
			ReportSize(1)
			ReportCount(1)
			CollectionPhysical(
				UsagePage_Button
				Usage_i8(1)
				Input(Var|Abs)
				/* was UsagePage_Digitizers */
				/* was Usage_Dig_Touch */
				/* was Input(Var|Abs) */
				ReportCount(7) /* was ReportCount(6) */
				Input(Var|Const)
				CollectionLogical(
					UsagePage_GenericDesktop
					Usage_GD_Wheel /* was Usage_GD_Dial */
					LogicalRange_i16(-32767, 32767)
					ReportSize(16)
					ReportCount(1)
					Input(Var|Rel)
					PhysicalMinimum_i8(0)
					PhysicalMaximum_i16(LOW_MULTIPLIER) /* was 3600 */
					LogicalMinimum_i8(0)
					LogicalMaximum_i16(3600)
					Usage_GD_ResolutionMultiplier
					Feature(Var|Abs)
					PhysicalMaximum_i8(0)
				)
				UnitExponent(-2)
				Unit(cm)
				PhysicalMaximum_i16(0)
				LogicalMaximum_i16(0)
				Usage_GD_X
				Input(Var|Rel) /* was Input(Var|Abs|Null) */
				Usage_GD_Y
				PhysicalMaximum_i16(0)
				LogicalMaximum_i16(0)
				Input(Var|Rel) /* was Input(Var|Abs|Null) */
				UsagePage_Digitizers
				Usage_Dig_Width
				LogicalRange_i8(58,58)
				ReportSize(8)
				UnitExponent(-1)
				PhysicalRange_i8(58, 58)
				Input(Var|Const)
				UnitExponent(0)
				Unit(0)
				PhysicalRange_i8(0, 0)
				UsagePage_Haptics
				Usage_Hap_SimpleHapticController
				CollectionLogical(
					LogicalMinimum_i8(0)
					LogicalMaximum_i16(255)
					Usage_Hap_RepeatCount
					Feature(Var|Abs|Null)
					Usage_Hap_RepeatCount
					Output(Var|Abs|Null)
					LogicalRange_i8(1, 7)
					Usage_Hap_AutoTrigger
					Feature(Var|Abs|Null)
					Usage_Hap_ManualTrigger
					Output(Var|Abs|Null)
					LogicalMaximum_i8(10)
					Usage_Hap_WaveformCutoffTime
					Feature(Var|Abs|Null)
					ReportSize(16)
					LogicalMaximum_i16(2000)
					Usage_Hap_RetriggerPeriod
					Feature(Var|Abs|Null)
					Usage_Hap_RetriggerPeriod
					Output(Var|Abs|Null)
					ReportId(2)
					ReportSize(32)
					LogicalRange_i32(65591, 65591)
					Usage_Hap_AutoTriggerAssociatedControl
					Feature(Var|Abs)
					Usage_Hap_DurationList
					CollectionLogical(
						UsagePage_Ordinal
						ReportCount(3)
						Usage_i8(3)
						Usage_i8(4)
						Usage_i8(5)
						ReportSize(8)
						LogicalRange_i8(0, 255)
						Feature(Var|Abs)
					)
					UsagePage_Haptics
					Usage_Hap_WaveformList
					CollectionLogical(
						UsagePage_Ordinal
						ReportCount(1)
						LogicalRange_i8(3, 3)
						PhysicalRange_i16(4099, 4099)
						Usage_i8(3)
						Feature(Var|Abs)
						LogicalRange_i8(4, 4)
						PhysicalRange_i16(4100, 4100)
						Usage_i8(4)
						Feature(Var|Abs)
						LogicalRange_i8(5, 5)
						PhysicalRange_i16(4100, 4100)
						Usage_i8(5)
						Feature(Var|Abs)
						PhysicalRange_i8(0, 0)
					)
				)
			)
		)
	)
	UsagePage_Vendor(0xFF07)
	Usage_i8(0x70)
	CollectionApplication(
		ReportId(48)
		LogicalRange_i8(0, 255)
		ReportCount(1)
		ReportSize(8)
		Usage_i8(0x00)
		Output(Var|Abs)
	)
	Usage_i8(0x71)
	CollectionApplication(
		LogicalRange_i8(0, 255)
		ReportSize(8)
		ReportCount(72)
		ReportId(42)
		Usage_i8(0xc6)
		Input_i16(Var|Abs|Buff)
		Usage_i8(0xc7)
		Output_i16(Var|Abs|Buff)
		ReportCount(52)
		Usage_i8(0xc8)
		Feature_i16(Const|Var|Abs|Buff)
		ReportId(43)
		Usage_i8(0xc9)
		Input_i16(Var|Abs|Buff)
		Usage_i8(0xca)
		Output_i16(Var|Abs|Buff)
		Usage_i8(0xcb)
		Feature_i16(Var|Abs|Buff)
		LogicalRange_i32(-2147483648, 2147483647)
		ReportSize(32)
		ReportCount(4)
		ReportId(44)
		UsageRange_i8(204, 207)
		Input(Var|Abs)
		ReportCount(4)
		ReportId(45)
		UsageRange_i8(216, 219)
		Input(Var|Abs)
		ReportCount(4)
		UsageRange_i8(220, 223)
		Output(Var|Abs)
		UsageRange_i8(224, 227)
		Feature(Var|Abs)
		ReportId(46)
		UsageRange_i8(228, 231)
		Input(Var|Abs)
		UsageRange_i8(232, 235)
		Output(Var|Abs)
		ReportCount(11)
		UsageRange_i8(236, 239)
		Feature(Var|Abs)
		ReportCount(4)
		ReportId(47)
		UsageRange_i8(240, 243)
		Input(Var|Abs)
		UsageRange_i8(244, 247)
		Output(Var|Abs)
		UsageRange_i8(248, 251)
		Feature(Var|Abs)
	)
	UsagePage_GenericDesktop
	Usage_GD_SystemControl
	CollectionApplication(
		ReportId(50)
		Usage_GD_SystemSleep
		Usage_GD_SystemWakeUp
		LogicalRange_i8(0, 1)
		ReportCount(2)
		ReportSize(1)
		Input(Var|Abs)
		ReportCount(6)
		Input(Const|Var|Abs)
	)
	Usage_i8(0x72)
	CollectionApplication(
		ReportId(49)
		ReportCount(10)
		ReportSize(8)
		LogicalRange_i8(0, 255)
		Usage_GD_WirelessRadioButton
		Input(Var|Abs)
		Usage_GD_WirelessRadioLED
		Output(Var|Abs)
	)
};

/* Convert REL_DIAL into REL_WHEEL */
SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(surface_dial_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);

	if (!data)
		return 0; /* EPERM check */

	__builtin_memcpy(data, fixed_rdesc, sizeof(fixed_rdesc));
	return sizeof(fixed_rdesc);
}

enum map_key {
	MAP_KEY_HAPTIC = 0,
	MAP_KEY_SLEEP,
	MAP_KEY_MAX,
};

struct elem {
	struct bpf_timer t;
	struct bpf_wq wq;
	u32 hid;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAP_KEY_MAX);
	__type(key, u32);
	__type(value, struct elem);
} timer_map SEC(".maps");

static bool haptic_enabled = true;
static bool prev_click;
static bool initialized;

static int set_res_and_haptic(int hid, bool enable)
{
	__u8 buf[8];
	const size_t size = sizeof(buf);
	struct hid_bpf_ctx *ctx;
	int ret;

	ctx = hid_bpf_allocate_context(hid);
	if (!ctx)
		return -1; /* EPERM check */

	buf[0] = DIAL_INPUT_REPORT_ID;

	ret = hid_bpf_hw_request(ctx, buf, size, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);

	bpf_printk("surface dial %s called: original buf: %02x %02x %02x %02x %02x %02x %02x %02x",
		   __func__,
		   buf[0],
		   buf[1],
		   buf[2],
		   buf[3],
		   buf[4],
		   buf[5],
		   buf[6],
		   buf[7]);

	if (enable) {
		buf[1] = LOW_RESOLUTION & 0xff; /* resolution multiplier */
		buf[2] = LOW_RESOLUTION >> 8;  /* resolution multiplier */
		buf[3] = 0;  /* Repeat Count */
		buf[4] = 3;  /* haptic Auto Trigger */
#if 0
		/* leave the rest as-is */
		buf[5] = 5;  /* Waveform Cutoff Time */
		buf[6] = 80; /* Retrigger Period */
		buf[7] = 0;  /* Retrigger Period */
#endif
	} else {
		buf[1] = HIGH_RESOLUTION & 0xff; /* resolution multiplier */
		buf[2] = HIGH_RESOLUTION >> 8;  /* resolution multiplier */
		buf[4] = 0;
	}

	ret = hid_bpf_hw_request(ctx, buf, size, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);

	if (ret == 8)
		current_multiplier = enable ? LOW_MULTIPLIER: HIGH_MULTIPLIER;
	else
		bpf_printk("surface dial set haptic ret value: %d -> enabled: %d", ret, enable);

	/* send a small feedback notification to the user */
	buf[0] = DIAL_INPUT_REPORT_ID;
	buf[1] = 0; /* Repeat Count */
	buf[2] = 5; /* haptic Manual Trigger */
	buf[3] = 80; /* Retrigger Period */
	buf[4] = 0;  /* Retrigger Period */
	ret = hid_bpf_hw_output_report(ctx, buf, sizeof(__u8) * 5);
	if (ret != 5)
		bpf_printk("surface dial notify haptic change ret value: %d", ret);

	hid_bpf_release_context(ctx);

	return ret;
}

/* callback for hmap timers */
static int haptic_timer_cb(void *map, int *key, void *value)
{
	struct elem *e = (struct elem *)value;

	haptic_enabled = !haptic_enabled;
	bpf_wq_start(&e->wq, 0);

	return 0;
}

static int sleep_timer_cb(void *map, int *key, void *value)
{
	initialized = false;

	return 0;
}


/* callback for hmap workqueue */
static int haptic_wq_cb(void *map, int *key, void *value)
{
	struct elem *e = (struct elem *)value;

	set_res_and_haptic(e->hid, haptic_enabled);

	return 0;
}

static inline u64 ns_to_s(int seconds)
{
	return (u64)seconds * 1000UL * 1000UL * 1000UL;
}

static int delay_work_control(struct hid_bpf_ctx *hctx, int seconds, bool cancel)
{
	struct bpf_timer *timer;
	int key = MAP_KEY_HAPTIC;
	struct elem *elem;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 1;

	if (!seconds)
		return bpf_wq_start(&elem->wq, 0);

	timer = &elem->t;
	if (cancel) {
		bpf_timer_cancel(timer);
	} else {
		bpf_timer_set_callback(timer, haptic_timer_cb);
		return bpf_timer_start(timer, ns_to_s(seconds), 0);
	}

	return 0;
}

static int restart_sleep_timer(struct hid_bpf_ctx *hctx, int seconds)
{
	struct bpf_timer *timer;
	int key = MAP_KEY_SLEEP;
	struct elem *elem;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 1;

	timer = &elem->t;

	return bpf_timer_start(timer, ns_to_s(seconds), 0);
}

struct dial_report {
	__u8 report_id;
	bool button: 1;
	bool touch:1;
	__u8 padding_0: 6;
	__s16 wheel;
	__u16 x;
	__u16 y;
	__u16 padding_1;
} __attribute__((packed));

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(surface_dial_event, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 9 /* size */);
	struct dial_report *dial;
	bool click;

	if (!data)
		return 0; /* EPERM check */

	dial = (struct dial_report *)data;

	if (dial->report_id != DIAL_INPUT_REPORT_ID) {
		/* on button press (not release), the device sends
		 * a System Wake Up event. This is duplicate with
		 * the button press, and is never released. So
		 * ignore it.
		 */
		return -1;
	}

	if (!initialized) {
		delay_work_control(hctx, 0, false);
		initialized = true;
	}

	/* Touch */
	dial->touch = 0;

	click = dial->button;

	if (prev_click != click) {
		delay_work_control(hctx, 2, !click);
	}
	prev_click = click;

	dial->x = 0;
	dial->y = 0;

	dial->wheel *= current_multiplier;

	restart_sleep_timer(hctx, 120);

	return 0;
}

HID_BPF_OPS(surface_dial) = {
	.hid_device_event = (void *)surface_dial_event,
	.hid_rdesc_fixup = (void *)surface_dial_rdesc_fixup,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	struct elem *value;

	ctx->retval = ctx->rdesc_size != ORIGINAL_RDESC_SIZE;
	if (ctx->retval)
		ctx->retval = -22;

	for (int i = 0; i < MAP_KEY_MAX; i++) {
		const int key = i; /* prevent infinite loop warning */

		value = bpf_map_lookup_elem(&timer_map, &key);
		if (!value)
			return key;

		value->hid = ctx->hid;

		switch (key) {
		case MAP_KEY_HAPTIC:
			bpf_timer_init(&value->t, &timer_map, CLOCK_MONOTONIC);
			bpf_timer_set_callback(&value->t, haptic_timer_cb);

			bpf_wq_init(&value->wq, &timer_map, 0);
			bpf_wq_set_callback(&value->wq, haptic_wq_cb, 0);
			break;

		case MAP_KEY_SLEEP:
			bpf_timer_init(&value->t, &timer_map, CLOCK_MONOTONIC);
			bpf_timer_set_callback(&value->t, sleep_timer_cb);
			break;
		}
	}


	return 0;
}

char _license[] SEC("license") = "GPL";
