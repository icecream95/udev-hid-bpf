/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022 Benjamin Tissoires
 */

#ifndef __HID_BPF_HELPERS_H
#define __HID_BPF_HELPERS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern __u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx,
			      unsigned int offset,
			      const size_t __sz) __ksym;
extern struct hid_bpf_ctx *hid_bpf_allocate_context(unsigned int hid_id) __ksym;
extern void hid_bpf_release_context(struct hid_bpf_ctx *ctx) __ksym;
extern int hid_bpf_hw_request(struct hid_bpf_ctx *ctx,
			      __u8 *data,
			      size_t buf__sz,
			      enum hid_report_type type,
			      enum hid_class_request reqtype) __ksym;

/* extracted from <linux/input.h> */
#define BUS_ANY			0x00
#define BUS_PCI			0x01
#define BUS_ISAPNP		0x02
#define BUS_USB			0x03
#define BUS_HIL			0x04
#define BUS_BLUETOOTH		0x05
#define BUS_VIRTUAL		0x06
#define BUS_ISA			0x10
#define BUS_I8042		0x11
#define BUS_XTKBD		0x12
#define BUS_RS232		0x13
#define BUS_GAMEPORT		0x14
#define BUS_PARPORT		0x15
#define BUS_AMIGA		0x16
#define BUS_ADB			0x17
#define BUS_I2C			0x18
#define BUS_HOST		0x19
#define BUS_GSC			0x1A
#define BUS_ATARI		0x1B
#define BUS_SPI			0x1C
#define BUS_RMI			0x1D
#define BUS_CEC			0x1E
#define BUS_INTEL_ISHTP		0x1F
#define BUS_AMD_SFH		0x20

/* extracted from <linux/hid.h> */
#define HID_GROUP_ANY				0x0000
#define HID_GROUP_GENERIC			0x0001
#define HID_GROUP_MULTITOUCH			0x0002
#define HID_GROUP_SENSOR_HUB			0x0003
#define HID_GROUP_MULTITOUCH_WIN_8		0x0004
#define HID_GROUP_RMI				0x0100
#define HID_GROUP_WACOM				0x0101
#define HID_GROUP_LOGITECH_DJ_DEVICE		0x0102
#define HID_GROUP_STEAM				0x0103
#define HID_GROUP_LOGITECH_27MHZ_DEVICE		0x0104
#define HID_GROUP_VIVALDI			0x0105

/* include/linux/mod_devicetable.h defines as (~0), but that gives us negative size arrays */
#define HID_VID_ANY				0x0000
#define HID_PID_ANY				0x0000

/* Helper macro to convert (foo, __LINE__)  into foo134 so we can use __LINE__ for
 * field/variable names */
#define COMBINE1(X,Y) X ## Y
#define COMBINE(X,Y) COMBINE1(X,Y)

/* Macro magic:
 * __uint(foo, 123) creates a int (*foo)[1234]
 *
 * We use that macro to declare an anonymous struct with several
 * fields, each is the declaration of an pointer to an array of size
 * bus/group/vid/pid. (Because it's a pointer to such an array, actual storage
 * would be sizeof(pointer) rather than sizeof(array). Not that we ever
 * instantiate it anyway).
 *
 * This is only used for BTF introspection, we can later check "what size
 * is the bus array" in the introspection data and thus extract the bus ID
 * again.
 *
 * And we use the __LINE__ to give each of our structs a unique name so the
 * BPF program writer doesn't have to.
 *
 * $ bpftool btf dump file target/bpf/HP_Elite_Presenter.bpf.o
 * shows the inspection data, start by searching for .hid_bpf_config
 * and working backwards from that (each entry references the type_id of the
 * content).
 */

#define HID_DEVICE(b, g, ven, prod)					\
	struct { \
		__uint(name, 0);			\
		__uint(bus, (b));	\
		__uint(group, (g));	\
		__uint(vid, (ven));	\
		__uint(pid, (prod));	\
	} COMBINE(_entry, __LINE__)

#define HID_BPF_CONFIG(f) COMBINE(_, f) SEC(".hid_bpf_config")


#endif /* __HID_BPF_HELPERS_H */
