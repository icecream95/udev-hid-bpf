/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024 Benjamin Tissoires
 */

#ifndef __UHID_BPF_TEST_WRAPPERS_H
#define __UHID_BPF_TEST_WRAPPERS_H

#undef bpf_printk
#include <stdio.h>
#define bpf_printk(fmt, args...) printf(fmt "\n", ##args)

#endif /* __UHID_BPF_TEST_WRAPPERS_H */
