// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_LOGITECH			0x046D
#define PID_BOLT_RECEIVER		0xC548
//      PID_MX_MASTER_3S_BLUETOOTH	0xB028

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_LOGITECH, PID_BOLT_RECEIVER);
);

/*
 * This program inverts the horizontal scroll direction on
 * the MX Master 3S mouse.
 * Out of the box it outputs inverse values compared to
 * what's given by other mice.
 *
 * Only implemented for the Logitech Bolt receiever at the
 * moment, bluetooth might be handled by libinput already.
 */

struct master_3s_hid_report {
	__u8 report_id;
	__u16 buttons;
	__s16 x;
	__s16 y;
	__s8 wheel;
	__s8 pan;
} __attribute__((packed));

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(master_3s_fix_event, struct hid_bpf_ctx *hid_ctx)
{
	const int expected_length = 9;
	const int expected_report_id = 2;
	struct master_3s_hid_report *data = NULL;

	if (hid_ctx->size < expected_length)
		return 0;

	data = (struct master_3s_hid_report*)hid_bpf_get_data(hid_ctx, 0, sizeof(*data));
	if (!data || data->report_id != expected_report_id)
		return 0; /* EPERM check */

#if false
	bpf_printk(" ** HID Report:");
	bpf_printk("    buttons: %04x", data->buttons);
	bpf_printk("    x: %i", data->x);
	bpf_printk("    y: %i", data->y);
	bpf_printk("    wheel: %i", data->wheel);
	bpf_printk("    pan: %i", data->pan);
#endif

	// Invert the horizontal scroll direction
	data->pan = -data->pan;

	return sizeof(*data);
}

HID_BPF_OPS(master_3s) = {
	.hid_device_event = (void *)master_3s_fix_event,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	const __u8 expected_rdesc[] = {
		UsagePage_GenericDesktop
		Usage_GD_Mouse
	};

	if (ctx->rdesc_size > sizeof(expected_rdesc) &&
	    __builtin_memcmp(ctx->rdesc, expected_rdesc, sizeof(expected_rdesc)) == 0)
		ctx->retval = 0;
	else
		ctx->retval = -EINVAL;

	return 0;
}

char _license[] SEC("license") = "GPL";
