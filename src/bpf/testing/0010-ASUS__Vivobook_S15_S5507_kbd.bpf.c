// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Icecream95 (the.real.icecream95@gmail.com)
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_ASUS 0x0B05
#define PID_VIVOBOOK_S15_S5507_KEYBOARD 0x4543

HID_BPF_CONFIG(
       HID_DEVICE(BUS_I2C, HID_GROUP_GENERIC, VID_ASUS, PID_VIVOBOOK_S15_S5507_KEYBOARD)
);

enum work_type {
	WORK_TYPE_INIT,
	WORK_TYPE_BACKLIGHT,
	WORK_TYPE_FNLOCK,
	WORK_TYPE_COUNT,
};

struct elem {
	struct bpf_wq wq;
	int hid;
};

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, WORK_TYPE_COUNT);
        __type(key, int);
        __type(value, struct elem);
} wq_map SEC(".maps");

static __u8 current_backlight_brightness = 1;
static bool current_fn_lock = false;
static bool change_next_vendor_keyup = false;

static void set_init_unk_1(struct hid_bpf_ctx *ctx)
{
	__u8 cmd[64] = {
		0x5A, 0x05, 0x20, 0x31, 0x00, 0x08,
	};

	hid_bpf_hw_request(ctx, cmd, sizeof(cmd),
			   HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
}

static void set_init_unk_2(struct hid_bpf_ctx *ctx)
{
	__u8 cmd[64] = {
		0x5A, 0xD0, 0x8F, 0x01,
	};

	hid_bpf_hw_request(ctx, cmd, sizeof(cmd),
			   HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
}

static void set_brightness(struct hid_bpf_ctx *ctx, __u8 brightness)
{
	__u8 cmd[64] = {
		0x5A, 0xBA, 0xC5, 0xC4, brightness,
	};

	hid_bpf_hw_request(ctx, cmd, sizeof(cmd),
			   HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
}

static void set_fn_lock(struct hid_bpf_ctx *ctx, __u8 fn_lock)
{
	__u8 cmd[64] = {
		0x5A, 0xD0, 0x4E, fn_lock,
	};

	hid_bpf_hw_request(ctx, cmd, sizeof(cmd),
			   HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
}

static int work_callback(void *map, int *key, void *value)
{
	struct elem *e = (struct elem *)value;
	struct hid_bpf_ctx *ctx;

	ctx = hid_bpf_allocate_context(e->hid);
	if (!ctx)
		return 0;

	if (*key == WORK_TYPE_BACKLIGHT) {
		__u8 brightness = current_backlight_brightness;
		brightness++;
		if (brightness > 3) {
			brightness = 0;
		}

		set_brightness(ctx, brightness);
	} else if (*key == WORK_TYPE_FNLOCK) {
		__u8 fn_lock = !current_fn_lock;
		set_fn_lock(ctx, fn_lock);
	} else if (*key == WORK_TYPE_INIT) {
		set_init_unk_1(ctx);
		set_init_unk_2(ctx);
		set_brightness(ctx, current_backlight_brightness);
		set_fn_lock(ctx, current_fn_lock);
	}

	hid_bpf_release_context(ctx);

	return 0;
}

static void schedule_key_work(int type)
{
	struct elem *elem;

	elem = bpf_map_lookup_elem(&wq_map, &type);
	if (!elem) {
		return;
	}

	bpf_wq_start(&elem->wq, 0);
}

static int send_consumer_control(__u8 *data, __u8 code)
{
	data[0] = 0x37;
	data[1] = code;
	data[2] = 0x00;

	change_next_vendor_keyup = (code != 0);
	return 3;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(handle_fkeys_fix_event, struct hid_bpf_ctx *hid_ctx)
{
	__u8 *data;

	if (hid_ctx->size != 6) {
		return 0;
	}

	data = hid_bpf_get_data(hid_ctx, 0, 6);
	if (!data || data[0] != 0x5A) {
		return 0;
	}

	__u8 key = data[1];

	/*
	 * Not yet handled:
	 *
	 *   F8  (Emoji key)      : 0x7E
	 *   F9  (Microphone mute): 0x7C
	 *   F10 (Microphone mode): 0xCB
	 *   F12 (MyASUS)         : 0x86
	 *   Fn+F (Fan profile)   : 0x9D
	 *
	 * (F7 (Display mode) sends LGUI + P,
	 * and Copilot is LGUI + LSHIFT + F23.)
	 */

	switch (key) {
	case 0x4E:
		schedule_key_work(WORK_TYPE_FNLOCK);
		break;

	case 0xC7:
		schedule_key_work(WORK_TYPE_BACKLIGHT);
		break;

	case 0x10:
		// Display Brightness Decrement
		return send_consumer_control(data, 0x70);

	case 0x20:
		// Display Brightness Increment
		return send_consumer_control(data, 0x6F);

	case 0x00:
		if (change_next_vendor_keyup) {
			return send_consumer_control(data, 0x00);
		}
		break;

	default:
		break;
	}

	return 0;
}

SEC(HID_BPF_HW_REQUEST)
int BPF_PROG(handle_hw_request, struct hid_bpf_ctx *hid_ctx, unsigned char reportnum,
	     enum hid_report_type rtype, enum hid_class_request reqtype, __u64 source)
{
	__u8 *data;

	if (reportnum != 0x5A || rtype != HID_FEATURE_REPORT || reqtype != HID_REQ_SET_REPORT) {
		return 0;
	}

	if (hid_ctx->size < 64) {
		return 0;
	}

	data = hid_bpf_get_data(hid_ctx, 0, 5);
	if (!data || data[0] != 0x5A) {
		return 0;
	}

	if (data[1] == 0xBA && data[2] == 0xC5 && data[3] == 0xC4) {
		current_backlight_brightness = data[4];
	} else if (data[1] == 0xD0 && data[2] == 0x4E) {
		current_fn_lock = data[3];
	}

	return 0;
}

HID_BPF_OPS(vivobook_s15) = {
	.hid_device_event = (void *)handle_fkeys_fix_event,
	.hid_hw_request = (void *)handle_hw_request,
};

/* If your device only has a single HID interface you can skip
   the probe function altogether */
SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	struct elem *value;

	for (int i = 0; i < WORK_TYPE_COUNT; i++) {
		const int key = i;

		value = bpf_map_lookup_elem(&wq_map, &key);
		if (!value) {
			return key;
		}

		value->hid = ctx->hid;

		bpf_wq_init(&value->wq, &wq_map, 0);
		bpf_wq_set_callback(&value->wq, work_callback, 0);

		if (i == WORK_TYPE_INIT) {
			bpf_wq_start(&value->wq, 0);
		}
	}

	ctx->retval = 0;

	return 0;
}

char _license[] SEC("license") = "GPL";
