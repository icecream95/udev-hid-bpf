// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_HOLTEK 0x04D9
#define PID_G10_MECHANICAL_GAMING_MOUSE 0xA09F

/*
 * This program is an example only, unless your brain can
 * process controlling a mouse with a y axis inverted.
 *
 * The following device is "supported"
 */
HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_HOLTEK, PID_G10_MECHANICAL_GAMING_MOUSE)
);

/*
 * This is a just a proof of concept, and as such a user hack:
 * we take one mouse, and whenever an event comes in, we invert the
 * Y coordinate.
 *
 * Given that the offset within the report is hardcoded, this only
 * works for the Holtek G10 mechanical mouse.
 *
 * Can be manually attached through:
 * sudo udev-hid-bpf add /sys/bus/hid/devices/0003:04D9:A09F.NNNN mouse_invert_y.bpf.o
 *
 * (Replace NNNN with the correct HID ID, the first one in the list)
 *
 * Once you are done:
 * sudo udev-hid-bpf remove /sys/bus/hid/devices/0003:04D9:A09F.NNNN
 */

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

	return 0;
}

char _license[] SEC("license") = "GPL";
