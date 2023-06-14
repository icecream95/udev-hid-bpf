// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

SEC("fmod_ret/hid_bpf_rdesc_fixup")
int BPF_PROG(hid_fix_rdesc, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 4096 /* size */);

	if (!data)
		return 0; /* EPERM check */

	/* replace application mouse by application pointer on the second collection */
	if (data[79] == 0x02)
		data[79] = 0x01;

	return 0;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	ctx->retval = ctx->rdesc_size != 264;
	if (ctx->retval)
		ctx->retval = -22;

	return 0;
}

char _license[] SEC("license") = "GPL";
