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

        @pytest.mark.parametrize("source", ["0010-FR-TEC__Raptor-Mach-2"])
        def test_something(bpf):
            pass
    """
    assert source is not None
    bpf = Bpf.load(source)
    assert bpf is not None
    yield bpf


class TestFrTecRaptorMach2:
    def test_probe(self):
        bpf = Bpf.load("0010-FR-TEC__Raptor-Mach-2")
        probe_args = HidProbeArgs(rdesc_size=232)
        probe_args.rdesc[177] = 0xEF
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

        probe_args.rdesc[177] = 0x12  # random value
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

    def test_rdesc(self):
        bpf = Bpf.load("0010-FR-TEC__Raptor-Mach-2")
        rdesc = bytes(4096)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data[177] == 0x07


class TestUserhacksInvertY:
    def test_probe(self):
        bpf = Bpf.load("0010-mouse_invert_y")
        probe_args = HidProbeArgs()
        probe_args.rdesc_size = 123
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

        probe_args.rdesc_size = 71
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

    @pytest.mark.parametrize("y", [1, -1, 10, -256])
    def test_event(self, y):
        bpf = Bpf.load("0010-mouse_invert_y")

        # this device has reports of size 9
        values = (0, 0, 0, y, 0, 0, 0, 0, 0)
        report = struct.pack("<3bh5b", *values)

        values = bpf.hid_bpf_device_event(report=report)
        values = struct.unpack("<3bh5b", values)
        y_out = values[3]
        assert y_out == -y


class TestRapooM50Plus:
    def test_rdesc_fixup(self):
        bpf = Bpf.load("0010-Rapoo__M50-Plus-Silent")
        rdesc = bytearray(4096)
        rdesc[17] = 0x03

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        rdesc[17] = 0x05
        assert data == rdesc


class TestXPPenDecoMini4:
    @pytest.mark.parametrize(
        "report,expected",
        [
            # Invalid report descriptor
            (b"\x02\x01\x02\x03\x04\x05\x06\x07", b"\x02\x01\x02\x03\x04\x05\x06\x07"),
            # Button 1
            (b"\x06\x00\x05\x00\x00\x00\x00\x00", b"\x06\x01\x00\x00\x00\x00\x00\x00"),
            # Button 2
            (b"\x06\x00\x08\x00\x00\x00\x00\x00", b"\x06\x02\x00\x00\x00\x00\x00\x00"),
            # Button 3
            (b"\x06\x04\x00\x00\x00\x00\x00\x00", b"\x06\x04\x00\x00\x00\x00\x00\x00"),
            # Button 4
            (b"\x06\x00\x2c\x00\x00\x00\x00\x00", b"\x06\x08\x00\x00\x00\x00\x00\x00"),
            # Button 5
            (b"\x06\x01\x16\x00\x00\x00\x00\x00", b"\x06\x10\x00\x00\x00\x00\x00\x00"),
            # Button 6
            (b"\x06\x01\x1d\x00\x00\x00\x00\x00", b"\x06\x20\x00\x00\x00\x00\x00\x00"),
            # Buttons 3 and 5
            (b"\x06\x05\x16\x00\x00\x00\x00\x00", b"\x06\x14\x00\x00\x00\x00\x00\x00"),
            # All buttons
            (b"\x06\x05\x05\x08\x2c\x16\x1d\x00", b"\x06\x3f\x00\x00\x00\x00\x00\x00"),
        ],
    )
    def test_button_events(self, report, expected):
        bpf = Bpf.load("0010-XPPen__DecoMini4")
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected
