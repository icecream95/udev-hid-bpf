// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>


/*
 * this program is not bound to any device, but can be attached to any of them:
 * it just outputs the raw events in /sys/kernel/debug/tracing/trace_pipe
 *
 * Manually attach the program to the device with:
 * sudo udev-hid-bpf add /sys/bus/hid/devices/<DEVICE> trace_hid_events.bpf.o
 *
 * Then watch for events:
 * sudo cat /sys/kernel/debug/tracing/trace_pipe
 *
 * Once you are done:
 * sudo udev-hid-bpf remove /sys/bus/hid/devices/<DEVICE>
 */

char str[64];

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(trace_hid_events, struct hid_bpf_ctx *hid_ctx)
{
	int i, j;
	__u8 *data;

	bpf_printk("event: size: %d", hid_ctx->size);
	for (i = 0; i * 64 < hid_ctx->size && i < 64; i++) {
		data = hid_bpf_get_data(hid_ctx, i * 64, 64);
		if (!data)
			return 0; /* EPERM check */

		for (j = 0; j < 8 && i * 64 + j * 8 < hid_ctx->size; j++) {
			 BPF_SNPRINTF(str, sizeof(str),
				      "%02x %02x %02x %02x %02x %02x %02x %02x ",
				      data[j * 8],
				      data[j * 8 + 1],
				      data[j * 8 + 2],
				      data[j * 8 + 3],
				      data[j * 8 + 4],
				      data[j * 8 + 5],
				      data[j * 8 + 6],
				      data[j * 8 + 7]
				      );

			bpf_printk(" 0x%08x: %s", i * 64 + j * 8, str);
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
