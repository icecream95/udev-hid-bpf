// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>

/* My device is sold as iKKEGOL "USB Foot Pedal Switch"
 * but the VID is apparently QinHeng so it's just a rebranded
 * devices.
 */
#define VID_QINHENG 0x1a86
#define PID_FOOTPEDAL 0xe026

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_QINHENG, PID_FOOTPEDAL),
);

#define FOOTPEDAL_REPORT_DESCRIPTOR_LENGTH 212
#define KEYBOARD_REPORT_ID 1

/*
 * This device exports two HID devices: one for the keyboard and one for pointer only.
 * The first one sends one event (see below), the second one doesn't send anything.
 *
 * # PCsensor FootSwitch
 * # Report descriptor length: 212 bytes
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)              0
 * # 0x09, 0x06,                    // Usage (Keyboard)                          2
 * # 0xa1, 0x01,                    // Collection (Application)                  4
 * # 0x85, 0x01,                    //   Report ID (1)                           6
 * # 0x05, 0x07,                    //   Usage Page (Keyboard/Keypad)            8
 * # 0x19, 0xe0,                    //   UsageMinimum (224)                      10
 * # 0x29, 0xe7,                    //   UsageMaximum (231)                      12
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     14
 * # 0x25, 0x01,                    //   Logical Maximum (1)                     16
 * # 0x75, 0x01,                    //   Report Size (1)                         18
 * # 0x95, 0x08,                    //   Report Count (8)                        20
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    22
 * # 0x95, 0x01,                    //   Report Count (1)                        24
 * # 0x75, 0x08,                    //   Report Size (8)                         26
 * # 0x81, 0x01,                    //   Input (Cnst,Arr,Abs)                    28
 * # 0x95, 0x03,                    //   Report Count (3)                        30
 * # 0x75, 0x01,                    //   Report Size (1)                         32
 * # 0x05, 0x08,                    //   Usage Page (LED)                        34
 * # 0x19, 0x01,                    //   UsageMinimum (1)                        36
 * # 0x29, 0x03,                    //   UsageMaximum (3)                        38
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   40
 * # 0x95, 0x05,                    //   Report Count (5)                        42
 * # 0x75, 0x01,                    //   Report Size (1)                         44
 * # 0x91, 0x01,                    //   Output (Cnst,Arr,Abs)                   46
 * # 0x95, 0x06,                    //   Report Count (6)                        48
 * # 0x75, 0x08,                    //   Report Size (8)                         50
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     52
 * # 0x25, 0xff,                    //   Logical Maximum (255)                   54
 * # 0x05, 0x07,                    //   Usage Page (Keyboard/Keypad)            56
 * # 0x19, 0x00,                    //   UsageMinimum (0)                        58
 * # 0x29, 0xff,                    //   UsageMaximum (255)                      60
 * # 0x81, 0x00,                    //   Input (Data,Arr,Abs)                    62
 * # 0xc0,                          // End Collection                            64
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)              65
 * # 0x09, 0x02,                    // Usage (Mouse)                             67
 * # 0xa1, 0x01,                    // Collection (Application)                  69
 * # 0x85, 0x02,                    //   Report ID (2)                           71
 * # 0x09, 0x01,                    //   Usage (Pointer)                         73
 * # 0xa1, 0x00,                    //   Collection (Physical)                   75
 * # 0x05, 0x09,                    //     Usage Page (Button)                   77
 * # 0x19, 0x01,                    //     UsageMinimum (1)                      79
 * # 0x29, 0x05,                    //     UsageMaximum (5)                      81
 * # 0x15, 0x00,                    //     Logical Minimum (0)                   83
 * # 0x25, 0x01,                    //     Logical Maximum (1)                   85
 * # 0x95, 0x05,                    //     Report Count (5)                      87
 * # 0x75, 0x01,                    //     Report Size (1)                       89
 * # 0x81, 0x02,                    //     Input (Data,Var,Abs)                  91
 * # 0x95, 0x01,                    //     Report Count (1)                      93
 * # 0x75, 0x03,                    //     Report Size (3)                       95
 * # 0x81, 0x03,                    //     Input (Cnst,Var,Abs)                  97
 * # 0x05, 0x01,                    //     Usage Page (Generic Desktop)          99
 * # 0x09, 0x30,                    //     Usage (X)                             101
 * # 0x09, 0x31,                    //     Usage (Y)                             103
 * # 0x09, 0x38,                    //     Usage (Wheel)                         105
 * # 0x15, 0x81,                    //     Logical Minimum (-127)                107
 * # 0x25, 0x7f,                    //     Logical Maximum (127)                 109
 * # 0x75, 0x08,                    //     Report Size (8)                       111
 * # 0x95, 0x03,                    //     Report Count (3)                      113
 * # 0x81, 0x06,                    //     Input (Data,Var,Rel)                  115
 * # 0xc0,                          //   End Collection                          117
 * # 0xc0,                          // End Collection                            118
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)              119
 * # 0x09, 0x05,                    // Usage (Gamepad)                           121
 * # 0xa1, 0x01,                    // Collection (Application)                  123
 * # 0x85, 0x04,                    //   Report ID (4)                           125
 * # 0x09, 0x01,                    //   Usage (Pointer)                         127
 * # 0xa1, 0x00,                    //   Collection (Physical)                   129
 * # 0x09, 0x30,                    //     Usage (X)                             131
 * # 0x09, 0x31,                    //     Usage (Y)                             133
 * # 0x15, 0xff,                    //     Logical Minimum (-1)                  135
 * # 0x25, 0x01,                    //     Logical Maximum (1)                   137
 * # 0x95, 0x02,                    //     Report Count (2)                      139
 * # 0x75, 0x02,                    //     Report Size (2)                       141
 * # 0x81, 0x02,                    //     Input (Data,Var,Abs)                  143
 * # 0xc0,                          //   End Collection                          145
 * # 0x95, 0x04,                    //   Report Count (4)                        146
 * # 0x75, 0x01,                    //   Report Size (1)                         148
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)                    150
 * # 0x05, 0x09,                    //   Usage Page (Button)                     152
 * # 0x19, 0x01,                    //   UsageMinimum (1)                        154
 * # 0x29, 0x08,                    //   UsageMaximum (8)                        156
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     158
 * # 0x25, 0x01,                    //   Logical Maximum (1)                     160
 * # 0x95, 0x08,                    //   Report Count (8)                        162
 * # 0x75, 0x01,                    //   Report Size (1)                         164
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    166
 * # 0xc0,                          // End Collection                            168
 * # 0x05, 0x0c,                    // Usage Page (Consumer)                     169
 * # 0x09, 0x01,                    // Usage (Consumer Control)                  171
 * # 0xa1, 0x01,                    // Collection (Application)                  173
 * # 0x85, 0x03,                    //   Report ID (3)                           175
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)            177
 * # 0x09, 0x81,                    //   Usage (System Power Down)               179
 * # 0x09, 0x82,                    //   Usage (System Sleep)                    181
 * # 0x75, 0x01,                    //   Report Size (1)                         183
 * # 0x95, 0x02,                    //   Report Count (2)                        185
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    187
 * # 0x95, 0x06,                    //   Report Count (6)                        189
 * # 0x75, 0x01,                    //   Report Size (1)                         191
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)                    193
 * # 0x05, 0x0c,                    //   Usage Page (Consumer)                   195
 * # 0x95, 0x01,                    //   Report Count (1)                        197
 * # 0x75, 0x10,                    //   Report Size (16)                        199
 * # 0x19, 0x00,                    //   UsageMinimum (0)                        201
 * # 0x2a, 0x2e, 0x02,              //   UsageMaximum (558)                      203
 * # 0x26, 0x2e, 0x02,              //   Logical Maximum (558)                   206
 * # 0x81, 0x00,                    //   Input (Data,Arr,Abs)                    209
 * # 0xc0,                          // End Collection                            211
 * R: 212 05 01 09 06 a1 01 85 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 95 01 75 08 81 01 95 03 75 01 05 08 19 01 29 03 91 02 95 05 75 01 91 01 95 06 75 08 15 00 25 ff 05 07 19 00 29 ff 81 00 c0 05 01 09 02 a1 01 85 02 09 01 a1 00 05 09 19 01 29 05 15 00 25 01 95 05 75 01 81 02 95 01 75 03 81 03 05 01 09 30 09 31 09 38 15 81 25 7f 75 08 95 03 81 06 c0 c0 05 01 09 05 a1 01 85 04 09 01 a1 00 09 30 09 31 15 ff 25 01 95 02 75 02 81 02 c0 95 04 75 01 81 03 05 09 19 01 29 08 15 00 25 01 95 08 75 01 81 02 c0 05 0c 09 01 a1 01 85 03 05 01 09 81 09 82 75 01 95 02 81 02 95 06 75 01 81 03 05 0c 95 01 75 10 19 00 2a 2e 02 26 2e 02 81 00 c0
 * N: PCsensor FootSwitch
 * I: 3 1a86 e026
 *
 * And the second one has this:
 *
 * # PCsensor FootSwitch
 * # Report descriptor length: 23 bytes
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)              0
 * # 0x09, 0x00,                    // Usage (0x0000)                            2
 * # 0xa1, 0x01,                    // Collection (Application)                  4
 * # 0x09, 0x01,                    //   Usage (Pointer)                         6
 * # 0x15, 0x00,                    //   Logical Minimum (0)                     8
 * # 0x25, 0xff,                    //   Logical Maximum (255)                   10
 * # 0x95, 0x08,                    //   Report Count (8)                        12
 * # 0x75, 0x08,                    //   Report Size (8)                         14
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)                    16
 * # 0x09, 0x01,                    //   Usage (Pointer)                         18
 * # 0x91, 0x02,                    //   Output (Data,Var,Abs)                   20
 * # 0xc0,                          // End Collection                            22
 * R: 23 05 01 09 00 a1 01 09 01 15 00 25 ff 95 08 75 08 81 02 09 01 91 02 c0
 * N: PCsensor FootSwitch
 * I: 3 1a86 e026
 */

/* The HID reports are simple enough: OOTB they send a 'b' on Report ID 1:
 * # Report ID: 1 /
 * #                Keyboard LeftControl:     0 | Keyboard LeftShift:     0 | Keyboard LeftAlt:     0 | Keyboard Left GUI:     0 | Keyboard RightControl:     0 | Keyboard RightShift:     0 | Keyboard RightAlt:     0 | Keyboard Right GUI:     0 | <8 bits padding> | Keyboard B:     5 | 0007/0000:     0 | 0007/0000:     0 | 0007/0000:     0 | 0007/0000:     0 | 0007/0000:     0 |
 * E: 000000.000024 9 01 00 00 05 00 00 00 00 00
 *
 * And all zeroes on release
 *
 * Since the report descriptor already does anything we could possibly want, we
 * don't need to fix that one. We simply change the report to the one we want.
 */

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(footpedal_2_fix_events, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 10 /* size */);

	/* We only check for the report ID which means this BPF will take
	 * effect regardless what the current configured keyboard shortcut ist.
	 * If you managed to configure the device on Windows to send some pointer
	 * or joystick event, you'll get a different report ID and need to
	 * adjust accordinly.
	 */

	if (!data || data[0] != KEYBOARD_REPORT_ID)
		return 0; /* EPERM check */

	__u8 release[9] =  {KEYBOARD_REPORT_ID, 0, 0, 0, 0, 0, 0, 0, 0};
	if (__builtin_memcmp(data, release, sizeof(release)) == 0)
		return 0;

	/* Change this to what you want it to do, here it's Ctrl+C */
	const __u8 modifiers = 0x1;
	const __u8 keycode = 6;  /* From Usage Page Keyboard */

	__u8 report[9] =  {KEYBOARD_REPORT_ID, modifiers, 0, keycode, 0, 0, 0, 0, 0};
	__builtin_memcpy(data, report, sizeof(report));
	return sizeof(report);
}

HID_BPF_OPS(footpedal_2) = {
	.hid_device_event = (void *)footpedal_2_fix_events,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	ctx->retval = ctx->rdesc_size != FOOTPEDAL_REPORT_DESCRIPTOR_LENGTH;
	if (ctx->retval)
		ctx->retval = -EINVAL;

	return 0;
}

char _license[] SEC("license") = "GPL";
