// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <vmlinux.h>

static struct test_callbacks {
	/* untested */
	void* (*hid_bpf_allocate_context)(unsigned int hid);
	/* untested */
	void (*hid_bpf_release_context)(void* ctx);
	int (*hid_bpf_hw_request)(struct hid_bpf_ctx *ctx,
				  uint8_t *data,
				  size_t buf__sz,
				  int type,
				  int reqtype);
	/* The data returned by hid_bpf_get_data */
	uint8_t *hid_bpf_data;
	size_t hid_bpf_data_sz;
} callbacks;

void set_callbacks(struct test_callbacks *cb)
{
	callbacks = *cb;
}

uint8_t* hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, size_t sz)
{
	if (offset + sz <= callbacks.hid_bpf_data_sz)
		return callbacks.hid_bpf_data + offset;
	else
		return NULL;
}

void* hid_bpf_allocate_context(unsigned int hid)
{
	return callbacks.hid_bpf_allocate_context(hid);
}

void hid_bpf_release_context(void* ctx)
{
	callbacks.hid_bpf_release_context(ctx);
}


int hid_bpf_hw_request(struct hid_bpf_ctx *ctx,
			      uint8_t *data,
			      size_t buf__sz,
			      int type,
			      int reqtype)
{
	return callbacks.hid_bpf_hw_request(ctx, data, buf__sz, type, reqtype);
}

int bpf_wq_set_callback_impl(struct bpf_wq *wq,
		int (callback_fn)(void *map, int *key, struct bpf_wq *wq),
		unsigned int flags__k, void *aux__ign)
{
	return 0;
}
