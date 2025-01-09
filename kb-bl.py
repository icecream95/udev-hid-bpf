#!/usr/bin/env python3

import hidapi
import sys

if len(sys.argv) < 2:
    print("Usage: kb-bl.py BRIGHTNESS [FNLOCK]")
    print("0 is off, -1 is unchanged, 3 is max brightness.")
    print("For FNLOCK, 1 means top row is plain F-keys.")
    exit(1)

cmds = []

# Setup commands; not required if using the BPF program
if False:
    cmds.append(f"5a0520310008")
    cmds.append(f"5ad08f01")

if len(sys.argv) > 1:
    brightness = int(sys.argv[1])
    brightness = min(max(brightness, -1), 3)

    if brightness != -1:
        cmds.append(f"5abac5c4{brightness:02x}")

if len(sys.argv) > 2:
    fn_lock = int(sys.argv[2])
    fn_lock = min(max(fn_lock, 0), 1)

    cmds.append(f"5ad04e{fn_lock:02x}")

d = hidapi.Device(next(hidapi.enumerate(0x0b05, 0x4543)))

for cmd in cmds:
    c = bytes.fromhex(cmd)
    c = c + b'\0' * (64 - len(c))
    d.send_feature_report(c[1:], c[:1])

d.close()
