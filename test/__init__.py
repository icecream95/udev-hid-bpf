#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

from ctypes import (
    c_int,
    c_ubyte,
    c_uint,
    c_uint32,
    c_int32,
    c_void_p,
    c_size_t,
)
from typing import Optional, Tuple, Type, Self
from dataclasses import dataclass
from pathlib import Path

import logging
import ctypes
import os
import json
import pytest


logger = logging.getLogger(__name__)


# see struct hid_probe_args
class HidProbeArgs(ctypes.Structure):
    _fields_ = [
        ("hid", c_uint),
        ("rdesc_size", c_uint),
        ("rdesc", c_ubyte * 4096),
        ("retval", c_int),
    ]


# see struct hid_bpf_ctx
class HidBpfCtx(ctypes.Structure):
    __fields__ = [
        ("index", c_uint32),
        ("hid", c_void_p),
        ("allocated_size", c_uint32),
        ("report_type", c_int),
        ("retval_or_size", c_int32),
    ]


# see struct test_callbacks
class Callbacks(ctypes.Structure):
    _fields_ = [
        ("hid_bpf_allocate_context", ctypes.CFUNCTYPE(c_void_p, c_uint)),
        ("hid_bpf_release_context", ctypes.CFUNCTYPE(None, c_void_p)),
        (
            "hid_bpf_hw_request",
            ctypes.CFUNCTYPE(c_int, c_void_p, c_void_p, c_size_t, c_int, c_int),
        ),
        ("hid_bpf_data", ctypes.POINTER(ctypes.c_uint8)),
        ("hid_bpf_data_sz", ctypes.c_size_t),
    ]


@dataclass
class Api:
    """
    Wrapper to make automatically loading functions from a .so file simpler.
    """

    name: str
    args: Tuple[Type[ctypes._SimpleCData | ctypes._Pointer], ...]
    return_type: Optional[Type[ctypes._SimpleCData | ctypes._Pointer]]

    @property
    def basename(self) -> str:
        return f"_{self.name}"


class Bpf:
    # Cached .so files
    _libs: dict[str, "Bpf"] = {}

    _api_prototypes: list[Api] = [
        Api(name="probe", args=(ctypes.POINTER(HidProbeArgs),), return_type=c_int),
        Api(name="set_callbacks", args=(ctypes.POINTER(Callbacks),), return_type=None),
    ]

    def __init__(self, lib):
        self.lib = lib
        self._callbacks = None

    @classmethod
    def _load(cls, name: str) -> Self:
        # Load the libtest-$BPF.so file first.o, map probe and set_callbacks which
        # have a fixed name.
        #
        # Then try to find the corresponding libtest-$BPF.json file that meson
        # should have generated.
        # Because our actual entry points have custom names we check the json for the
        # right section and then map those we want into fixed-name wrappers, i.e.
        # SEC(HID_BPF_RDESC_FIXUP) becomes self._hid_bpf_rdesc_fixup() which points
        # to the right ctypes function.
        try:
            lib = ctypes.CDLL(f"{name}.so", use_errno=True)
            assert lib is not None
        except OSError as e:
            pytest.exit(
                f"Error loading the library: {e}. Maybe export LD_LIBRARY_PATH=builddir/test"
            )
        for api in cls._api_prototypes:
            func = getattr(lib, api.name)
            func.argtypes = api.args
            func.restype = api.return_type
            setattr(lib, api.basename, func)

        try:
            # Our test setup guarantees this works, running things manually is
            # a bit more complicated.
            ld_path = os.environ.get("LD_LIBRARY_PATH")
            assert ld_path is not None

            # Only one entry per json file so we're good
            js = json.load(open(Path(ld_path) / f"{name}.json"))[0]
            for program in js["programs"]:
                if program["section"].endswith("/hid_bpf_rdesc_fixup"):
                    func = getattr(lib, program["name"])
                    func.argtypes = (ctypes.POINTER(HidBpfCtx),)
                    func.restype = c_int
                    setattr(lib, "_hid_bpf_rdesc_fixup", func)
                elif program["section"].endswith("/hid_bpf_device_event"):
                    func = getattr(lib, program["name"])
                    func.argtypes = (ctypes.POINTER(HidBpfCtx),)
                    func.restype = c_int
                    setattr(lib, "_hid_bpf_device_event", func)
        except OSError as e:
            pytest.exit(
                f"Error loading the JSON file: {e}. Unexpected LD_LIBRARY_PATH?"
            )

        return cls(lib)

    @classmethod
    def load(cls, name: str) -> Self:
        """
        Load the given bpf.o file from our tree
        """
        name = f"libtest-{name}"
        if name not in cls._libs:
            cls._libs[name] = cls._load(name)
        instance = cls._libs[name]
        assert instance is not None
        return instance

    def set_callbacks(self, callbacks: Callbacks):
        """
        Set the callbacks to use for the various hid_bpf_* functions that may be
        used by a BPF program. These need to have a matching implementation in
        test-wrapper.c

        For most tests this isn't needed and you can pass the rdesc/report bytes
        directly to hid_bpf_rdesc_fixup() or hid_bpf_device_event().
        """
        self.lib._set_callbacks(callbacks)

    def probe(self, probe_args: HidProbeArgs) -> HidProbeArgs:
        """Call the BPF program's probe() function"""
        # We copy so our caller's probe args are separate from
        # the ones we return after the BPF program modifies them.
        pa = HidProbeArgs()
        p1 = ctypes.byref(probe_args)
        p2 = ctypes.byref(pa)
        ctypes.memmove(p2, p1, ctypes.sizeof(HidProbeArgs))
        rc = self.lib._probe(ctypes.byref(pa))
        if rc != 0:
            raise OSError(rc)
        return pa

    def hid_bpf_device_event(
        self,
        report: bytes | None = None,
        ctx: HidBpfCtx | None = None,
    ) -> None | bytes:
        """
        Call the BPF program's hid_bpf_device_event function.

        If a report is given, it returns the (possibly modified) report.
        Otherwise it returns None.
        """
        if ctx is None:
            ctx = HidBpfCtx()

        if report is not None:
            data = (ctypes.c_uint8 * len(report))(*report)
            callbacks = Callbacks()
            callbacks.hid_bpf_data = data
            callbacks.hid_bpf_data_sz = len(report)
            self.set_callbacks(callbacks)
        else:
            data = None

        rc = self.lib._hid_bpf_device_event(ctypes.byref(ctx))
        if rc != 0:
            raise OSError(rc)

        if report is None:
            return None
        assert data is not None
        return bytes(data)

    def hid_bpf_rdesc_fixup(
        self,
        rdesc: bytes | None = None,
        ctx: HidBpfCtx | None = None,
    ) -> None | bytes:
        """
        Call the BPF program's hid_bpf_rdesc_fixup function.

        If an rdesc is given, it returns the (possibly modified) rdesc.
        Otherwise it returns None.
        """
        if ctx is None:
            ctx = HidBpfCtx()

        if rdesc is not None:
            data = (ctypes.c_uint8 * 4096)(*rdesc)
            callbacks = Callbacks()
            callbacks.hid_bpf_data = data
            callbacks.hid_bpf_data_sz = len(data)
            self.set_callbacks(callbacks)
        else:
            data = None

        rc = self.lib._hid_bpf_rdesc_fixup(ctypes.byref(ctx))
        if rc != 0:
            raise OSError(rc)

        if rdesc is None:
            return None
        assert data is not None
        return bytes(data)
