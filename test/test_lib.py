#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

from . import Bpf, HidProbeArgs

import logging
import struct
import pytest

logger = logging.getLogger(__name__)


@pytest.fixture
def bpf(source: str):
    """
    A fixture that allows parametrizing over a number of sources. Use with e.g.::

        @pytest.mark.parametrize("source", ["10-FR-TEC__Raptor-Mach-2"])
        def test_something(bpf):
            pass
    """
    assert source is not None
    bpf = Bpf.load(source)
    assert bpf is not None
    yield bpf


def test_probe_raptor_mach_2():
    bpf = Bpf.load("10-FR-TEC__Raptor-Mach-2")
    probe_args = HidProbeArgs(rdesc_size=232)
    probe_args.rdesc[177] = 0xEF
    pa = bpf.probe(probe_args)
    assert pa.retval == 0

    probe_args.rdesc[177] = 0x12  # random value
    pa = bpf.probe(probe_args)
    assert pa.retval == -22


def test_rdesc_fixup_raptor_mach_2():
    bpf = Bpf.load("10-FR-TEC__Raptor-Mach-2")
    rdesc = bytes(4096)

    data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
    assert data[177] == 0x07


def test_probe_userhacks_invert():
    bpf = Bpf.load("10-mouse_invert_y")
    probe_args = HidProbeArgs()
    probe_args.rdesc_size = 123
    pa = bpf.probe(probe_args)
    assert pa.retval == -22

    probe_args.rdesc_size = 71
    pa = bpf.probe(probe_args)
    assert pa.retval == 0


@pytest.mark.parametrize("y", [1, -1, 10, -256])
def test_event_userhacks_invert(y):
    bpf = Bpf.load("10-mouse_invert_y")

    # this device has reports of size 9
    values = (0, 0, 0, y, 0, 0, 0, 0, 0)
    report = struct.pack("<3bh5b", *values)

    values = bpf.hid_bpf_device_event(report=report)
    values = struct.unpack("<3bh5b", values)
    y_out = values[3]
    assert y_out == -y
