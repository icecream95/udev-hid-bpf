// SPDX-License-Identifier: GPL-2.0-only
//
// Does nothing but always succeeds

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_ANY, HID_VID_ANY, HID_PID_ANY),
	HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_ANY, HID_VID_ANY, HID_PID_ANY)
);

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_fix_rdesc, struct hid_bpf_ctx *hctx)
{
	return 0;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	ctx->retval = 0;
	return 0;
}

char _license[] SEC("license") = "GPL";