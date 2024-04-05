#!/usr/bin/env python3
#
# Given the output of udev-hid-bpf inspect, generate a corresponding hwdb file

from dataclasses import dataclass
from itertools import count
from typing import Iterable

import argparse
import json
import sys


@dataclass(order=True)
class Device:
    vid: int
    pid: int
    bustype: int
    group: int
    filename: str


def extract(js) -> Iterable:
    for objfile in js:
        for device in objfile["devices"]:
            yield Device(
                filename=objfile["filename"],
                bustype=int(device["bus"], 16),
                group=int(device["group"], 16),
                vid=int(device["vid"], 16),
                pid=int(device["pid"], 16),
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", default="HID_BPF_")
    ns = parser.parse_args()
    js = json.load(sys.stdin)
    counter = count()
    devices = sorted(extract(js))
    print("# This file is generated and will be overwritten on updates. Do not edit")
    print("")
    for d in devices:
        print(f"hid-bpf:hid:b{d.bustype:04X}g{d.group:04X}v{d.vid:08X}p{d.pid:08X}")
        print(f"  {ns.prefix}{next(counter):03}={d.filename}")
        print(f"  .HID_BPF=1")  # noqa: F541
        print("")
