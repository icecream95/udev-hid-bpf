// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_UGEE 0x28BD /* VID is shared with SinoWealth and Glorious and prob others */
#define PID_ARTIST_PRO16_GEN2 0x095B

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_ARTIST_PRO16_GEN2)
);

/*
 * We need to amend the report descriptor for the following:
 * - the device reports Eraser instead of using Secondary Barrel Switch
 * - when the eraser button is pressed and the stylus is touching the tablet,
 *   the device sends Tip Switch instead of sending Eraser
 */
static const __u8 fixed_rdesc[] = {
	0x05, 0x0d,                    // Usage Page (Digitizers)             0
	0x09, 0x02,                    // Usage (Pen)                         2
	0xa1, 0x01,                    // Collection (Application)            4
	0x85, 0x07,                    //  Report ID (7)                      6
	0x09, 0x20,                    //  Usage (Stylus)                     8
	0xa1, 0x00,                    //  Collection (Physical)              10
	0x09, 0x42,                    //   Usage (Tip Switch)                12
	0x09, 0x44,                    //   Usage (Barrel Switch)             14
	0x09, 0x5a,                    //   Usage (Secondary Barrel Switch)   16  /* changed from 0x45 (Eraser) to 0x5a (Secondary Barrel Switch) */
	0x09, 0x3c,                    //   Usage (Invert)                    18
	0x09, 0x45,                    //   Usage (Eraser)                    16  /* created over a padding bit at offset 29-33 */
	0x15, 0x00,                    //   Logical Minimum (0)               20
	0x25, 0x01,                    //   Logical Maximum (1)               22
	0x75, 0x01,                    //   Report Size (1)                   24
	0x95, 0x05,                    //   Report Count (5)                  26  /* changed from 4 to 5 */
	0x81, 0x02,                    //   Input (Data,Var,Abs)              28
	0x09, 0x32,                    //   Usage (In Range)                  34
	0x15, 0x00,                    //   Logical Minimum (0)               36
	0x25, 0x01,                    //   Logical Maximum (1)               38
	0x95, 0x01,                    //   Report Count (1)                  40
	0x81, 0x02,                    //   Input (Data,Var,Abs)              42
	0x95, 0x02,                    //   Report Count (2)                  44
	0x81, 0x03,                    //   Input (Cnst,Var,Abs)              46
	0x75, 0x10,                    //   Report Size (16)                  48
	0x95, 0x01,                    //   Report Count (1)                  50
	0x35, 0x00,                    //   Physical Minimum (0)              52
	0xa4,                          //   Push                              54
	0x05, 0x01,                    //   Usage Page (Generic Desktop)      55
	0x09, 0x30,                    //   Usage (X)                         57
	0x65, 0x13,                    //   Unit (EnglishLinear: in)          59
	0x55, 0x0d,                    //   Unit Exponent (-3)                61
	0x46, 0xff, 0x34,              //   Physical Maximum (13567)          63
	0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           66
	0x81, 0x02,                    //   Input (Data,Var,Abs)              69
	0x09, 0x31,                    //   Usage (Y)                         71
	0x46, 0x20, 0x21,              //   Physical Maximum (8480)           73
	0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           76
	0x81, 0x02,                    //   Input (Data,Var,Abs)              79
	0xb4,                          //   Pop                               81
	0x09, 0x30,                    //   Usage (Tip Pressure)              82
	0x45, 0x00,                    //   Physical Maximum (0)              84
	0x26, 0xff, 0x3f,              //   Logical Maximum (16383)           86
	0x81, 0x42,                    //   Input (Data,Var,Abs,Null)         89
	0x09, 0x3d,                    //   Usage (X Tilt)                    91
	0x15, 0x81,                    //   Logical Minimum (-127)            93
	0x25, 0x7f,                    //   Logical Maximum (127)             95
	0x75, 0x08,                    //   Report Size (8)                   97
	0x95, 0x01,                    //   Report Count (1)                  99
	0x81, 0x02,                    //   Input (Data,Var,Abs)              101
	0x09, 0x3e,                    //   Usage (Y Tilt)                    103
	0x15, 0x81,                    //   Logical Minimum (-127)            105
	0x25, 0x7f,                    //   Logical Maximum (127)             107
	0x81, 0x02,                    //   Input (Data,Var,Abs)              109
	0xc0,                          //  End Collection                     111
	0xc0,                          // End Collection                      112
};

SEC("fmod_ret/hid_bpf_rdesc_fixup")
int BPF_PROG(hid_fix_rdesc_xppen_artistpro16gen2, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 4096 /* size */);

	if (!data)
		return 0; /* EPERM check */

	__builtin_memcpy(data, fixed_rdesc, sizeof(fixed_rdesc));

	return sizeof(fixed_rdesc);
}

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(xppen_16_fix_eraser, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 10 /* size */);

	if (!data)
		return 0; /* EPERM check */

	if ((data[1] & 0x29) != 0x29) /* tip switch=1 invert=1 inrange=1 */
		return 0;

	/* xor bits 0,3 and 4: convert Tip Switch + Invert into Eraser only */
	data[1] ^= 0x19;

	return 0;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	/*
	 * The device exports 3 interfaces.
	 */
	ctx->retval = ctx->rdesc_size != 113;
	if (ctx->retval)
		ctx->retval = -EINVAL;

	/* ensure the kernel isn't fixed already */
	if (ctx->rdesc[17] != 0x45) /* Eraser */
		ctx->retval = -EINVAL;

	return 0;
}

char _license[] SEC("license") = "GPL";
