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

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(trace_hid_events, struct hid_bpf_ctx *hid_ctx)
{
	hid_bpf_printk_event(hid_ctx);

	return 0;
}

HID_BPF_OPS(trace_hid_events_ops) = {
	.hid_device_event = (void *)trace_hid_events,
};

char _license[] SEC("license") = "GPL";
