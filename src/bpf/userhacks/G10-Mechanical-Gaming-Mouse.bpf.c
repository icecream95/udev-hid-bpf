// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "../vmlinux.h"
#include "../hid_bpf.h"
#include "../hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_HOLTEK 0x04D9
#define PID_G10_MECHANICAL_GAMING_MOUSE 0xA09F

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_HOLTEK, PID_G10_MECHANICAL_GAMING_MOUSE)
);

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_y_event, struct hid_bpf_ctx *hctx)
{
	s16 y;
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 9 /* size */);

	if (!data)
		return 0; /* EPERM check */

	y = data[3] | (data[4] << 8);

	y = -y;

	data[3] = y & 0xFF;
	data[4] = (y >> 8) & 0xFF;

	return 0;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	/*
	 * The device exports 3 interfaces.
	 * The mouse interface has a report descriptor of length 71.
	 * So if report descriptor size is not 71, mark as -EINVAL
	 */
	ctx->retval = ctx->rdesc_size != 71;
	if (ctx->retval)
		ctx->retval = -EINVAL;

	/* comment the following line to actually bind the program */
	ctx->retval = -EINVAL;

	return 0;
}

char _license[] SEC("license") = "GPL";
