// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_LOGITECH 0x046D
#define PID_BOLT_RECEIVER		0xC548
#define PID_MX_MASTER_3B_BLUETOOTH	0xB028

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_LOGITECH, PID_BOLT_RECEIVER);
	HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_GENERIC, VID_LOGITECH, PID_MX_MASTER_3B_BLUETOOTH);
);

/*
 * This program sends a command when the device connects to
 * convert the "smart shift" button into a middle click.
 *
 * See https://discussion.fedoraproject.org/t/how-to-remap-mouse-buttons-on-gnome-with-wayland-without-running-an-extra-service/89700/9
 *
 * Note: this works well in the bluetooth case, not so much
 * in USB because we have no guarantees that the device is
 * connected and available when we attach the program to the
 * HID receiver.
 *
 * To fix that we need sleepable BPF timers, and whenever we
 * detect that the mouse is connected, we can then send
 * `disable_smart_shift` to the device.
 */

static __u8 disable_smart_shift[] = {
	0x11,  /* report ID */
	0x01,  /* device ID */
	0x09,  /* Feature Index */
	0x32,  /* Function: 0x03 /Software id: 0x02 */
	0x00,  /* cid msb */
	0xc4,  /* cid lsb */
	0x00,  /* valid flags */
	0x00,  /* remap msb */
	0x52,  /* remap lsb */
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00
};


static int check_usb_report_descriptor(struct hid_bpf_probe_args *ctx) {
	const int offset = 27;

	if (ctx->rdesc_size > (offset + 9) &&
	    ctx->rdesc[offset + 0] == 0x06 &&  /* Usage Page */
	    ctx->rdesc[offset + 1] == 0x00 &&  /* | */
	    ctx->rdesc[offset + 2] == 0xff &&  /* | Vendor Defined Page 1 */
	    ctx->rdesc[offset + 3] == 0x09 &&  /* Usage */
	    ctx->rdesc[offset + 4] == 0x02 &&  /* Vendor Usage 2 */
	    ctx->rdesc[offset + 7] == 0x85 &&  /* Report ID */
	    ctx->rdesc[offset + 8] == 0x11)    /* 0x11 */

		return 0;

	return -22;
}

static int check_bluetooth_report_descriptor(struct hid_bpf_probe_args *ctx) {
	const int offset = 69;

	if (ctx->rdesc_size > (offset + 10) &&
	    ctx->rdesc[offset + 0] == 0x06 &&  /* Usage Page */
	    ctx->rdesc[offset + 1] == 0x43 &&  /* | */
	    ctx->rdesc[offset + 2] == 0xff &&  /* | Vendor Defined Page 0xff43 */
	    ctx->rdesc[offset + 3] == 0x0a &&  /* Usage */
	    ctx->rdesc[offset + 4] == 0x02 &&  /* | */
	    ctx->rdesc[offset + 5] == 0x02 &&  /* | Vendor Usage 0x0202 */
	    ctx->rdesc[offset + 8] == 0x85 &&  /* Report ID */
	    ctx->rdesc[offset + 9] == 0x11)    /* 0x11 */

		return 0;

	return -22;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	const size_t size = sizeof(disable_smart_shift);
	struct hid_bpf_ctx *hid_ctx;
	int ret;

	if (size > sizeof(disable_smart_shift))
		return -7; /* -E2BIG */

	hid_ctx = hid_bpf_allocate_context(ctx->hid);
	if (!hid_ctx)
		return -1; /* EPERM check */

	if (hid_ctx->hid->bus == BUS_USB)
		/*
		 * On USB, the device exports 3 interfaces.
		 * We are interested in the report ID 0x11 only.
		 */
		ctx->retval = check_usb_report_descriptor(ctx);
	else
		ctx->retval = check_bluetooth_report_descriptor(ctx);

	if (ctx->retval) {
		ret = 0;
		goto out;
	}

	bpf_printk("successfully found Logitech MX Master 3B");

	ret = hid_bpf_hw_request(hid_ctx, disable_smart_shift, size, HID_OUTPUT_REPORT, HID_REQ_SET_REPORT);

	bpf_printk("disable smart shift ret value: %d", ret);

	if (ret < 0)
		ctx->retval = ret;

out:
	bpf_printk(" ** ret value: %d", ctx->retval);

	hid_bpf_release_context(hid_ctx);

	return 0;
}

char _license[] SEC("license") = "GPL";
