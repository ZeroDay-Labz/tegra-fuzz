"""Tegra X1 (T210) RCM protocol constants and message construction.

All of this is public, documented in the open-source fusee-launcher tooling and in
the Fusée Gelée write-ups (CVE-2018-6242). Only the parts needed to *frame* a
message are modelled here; nothing in this file performs an attack. Comments mark
which values are protocol-defined versus chosen seeds.
"""
from __future__ import annotations

import struct

from .model import TestCase

# --- USB identity / endpoints (protocol-defined) --------------------------------
VID = 0x0955
PID = 0x7321
INTERFACE = 0
EP_IN = 0x81          # bulk IN  (device -> host)
EP_OUT = 0x01         # bulk OUT (host -> device)

# The bootROM returns a 16-byte device identifier as the first read.
DEVICE_ID_LENGTH = 16

# Host-side USB write chunk size (convention from fusee-launcher; not a confirmed bootROM limit).
MAX_CHUNK = 0x1000

# The RCM message begins with a little-endian u32 "total message size": the number
# of bytes the bootROM expects to receive for the whole message. This single field
# is the heart of the length-handling bug class, so it is modelled explicitly.
LENGTH_FIELD = "<I"
LENGTH_FIELD_SIZE = 4


def build_message(declared_length: int, body: bytes) -> bytes:
    """Serialise an RCM message: 4-byte declared length followed by ``body``.

    Note: ``declared_length`` is what we *tell* the bootROM; it need not equal
    ``LENGTH_FIELD_SIZE + len(body)``. Deliberately diverging the two is exactly
    what the fuzzer explores.
    """
    return struct.pack(LENGTH_FIELD, declared_length & 0xFFFFFFFF) + body


def case_to_wire(case: TestCase) -> bytes:
    """Render an ``rcm`` test case to the exact bytes placed on the bulk OUT pipe."""
    if case.kind != "rcm":
        raise ValueError(f"not an rcm case: {case.kind}")
    declared = case.declared_length
    if declared is None:
        declared = LENGTH_FIELD_SIZE + len(case.payload)
    return build_message(declared, case.payload)


# --- Seed corpus ----------------------------------------------------------------
# A small set of well-formed and boundary starting points. Mutations grow from
# these. None of these is a working exploit; they are ordinary protocol framings.

def _rcm(name: str, declared: int | None, body: bytes) -> TestCase:
    return TestCase(kind="rcm", origin=f"seed:{name}",
                    declared_length=declared, payload=body)


def _ctrl(name: str, bmrt: int, breq: int, wval: int, widx: int,
          wlen: int | None, data: bytes = b"") -> TestCase:
    return TestCase(kind="control", origin=f"seed:{name}",
                    bmRequestType=bmrt, bRequest=breq, wValue=wval,
                    wIndex=widx, wLength=wlen, data=data)


def seed_cases() -> list[TestCase]:
    """Return the initial, hand-written seed corpus."""
    seeds: list[TestCase] = []

    # Well-formed-ish RCM framings of various sizes (declared == actual).
    for size in (0x10, 0x40, 0x200, MAX_CHUNK):
        body = bytes(size)
        seeds.append(_rcm(f"even_{size:#x}", LENGTH_FIELD_SIZE + size, body))

    # Boundary cases on the declared-length field, with a fixed small body.
    body = bytes(0x40)
    actual = LENGTH_FIELD_SIZE + len(body)
    seeds.append(_rcm("len_zero", 0, body))
    seeds.append(_rcm("len_short", actual - 1, body))
    seeds.append(_rcm("len_long", actual + 1, body))
    seeds.append(_rcm("len_max", 0xFFFFFFFF, body))

    # Standard USB control requests (benign baselines the fuzzer mutates).
    # GET_STATUS on an endpoint is the documented over-read surface; here it is a
    # *valid* 2-byte request as a seed — only mutation makes wLength oversized.
    seeds.append(_ctrl("get_status_ep", 0x82, 0x00, 0x0000, EP_IN, 2))
    # GET_DESCRIPTOR (device), a normal enumeration request.
    seeds.append(_ctrl("get_descriptor", 0x80, 0x06, 0x0100, 0x0000, 18))
    # GET_CONFIGURATION.
    seeds.append(_ctrl("get_config", 0x80, 0x08, 0x0000, 0x0000, 1))

    return seeds
