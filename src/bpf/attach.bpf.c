// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "attach.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* following are kfuncs exported by HID for HID-BPF */
extern int hid_bpf_attach_prog(unsigned int hid_id, int prog_fd, u32 flags) __ksym;

SEC("syscall")
int attach_prog(struct attach_prog_args *ctx)
{
	ctx->retval = hid_bpf_attach_prog(ctx->hid,
					  ctx->prog_fd,
					  0);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 1;
