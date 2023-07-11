// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#ifndef __ATTACH_H
#define __ATTACH_H

/**
 * <div rustbindgen replaces="AttachProgArgs"></div>
 */
struct attach_prog_args {
	int prog_fd;
	unsigned int hid;
	int retval;
};

#endif /* __ATTACH_H */
