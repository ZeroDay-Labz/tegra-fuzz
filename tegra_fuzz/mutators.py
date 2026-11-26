"""Pure, deterministic mutation strategies.

Every function takes an explicit ``random.Random`` so a run is fully reproducible
from its seed. Low-level byte mutators are tested directly; the higher-level
``mutate`` dispatches to a strategy appropriate to the test case kind and returns
the new case together with the strategy name (recorded as provenance).
"""
from __future__ import annotations

import random
import struct
from dataclasses import replace

from .model import TestCase
from . import rcm

# Values that disproportionately trigger off-by-one / signedness / boundary bugs.
INTERESTING_8 = [0x00, 0x01, 0x02, 0x10, 0x20, 0x40, 0x7F, 0x80, 0xFE, 0xFF]
INTERESTING_32 = [
    0x00000000, 0x00000001, 0x00000040, 0x00000200, 0x00001000, 0x00008000,
    0x0000FFFF, 0x00010000, 0x00030298, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]
# USB wLength is a 16-bit field.
INTERESTING_16 = [0x0000, 0x0001, 0x0002, 0x0040, 0x0100, 0x0200,
                  0x0400, 0x1000, 0x7FFF, 0x8000, 0xFFFF]

MAX_PAYLOAD = 0x2000  # cap generated payload growth so runs stay bounded


# --- low-level byte mutators ----------------------------------------------------
def flip_bits(data: bytes, rng: random.Random, n: int = 1) -> bytes:
    if not data:
        return data
    b = bytearray(data)
    for _ in range(n):
        pos = rng.randrange(len(b))
        b[pos] ^= 1 << rng.randrange(8)
    return bytes(b)


def set_interesting_byte(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return bytes([rng.choice(INTERESTING_8)])
    b = bytearray(data)
    b[rng.randrange(len(b))] = rng.choice(INTERESTING_8)
    return bytes(b)


def set_interesting_u32(data: bytes, rng: random.Random) -> bytes:
    """Overwrite a 4-byte aligned dword with an interesting little-endian value."""
    if len(data) < 4:
        return struct.pack("<I", rng.choice(INTERESTING_32))
    b = bytearray(data)
    off = rng.randrange(0, len(b) - 3)
    b[off:off + 4] = struct.pack("<I", rng.choice(INTERESTING_32))
    return bytes(b)


def truncate(data: bytes, rng: random.Random) -> bytes:
    if len(data) <= 1:
        return data
    return data[: rng.randrange(0, len(data))]


def extend(data: bytes, rng: random.Random, max_len: int = MAX_PAYLOAD) -> bytes:
    if len(data) >= max_len:
        return data
    grow = rng.randrange(1, max(2, min(0x400, max_len - len(data) + 1)))
    filler = rng.choice(INTERESTING_8)
    return data + bytes([filler]) * grow


def duplicate_chunk(data: bytes, rng: random.Random, max_len: int = MAX_PAYLOAD) -> bytes:
    if not data:
        return data
    n = rng.randrange(1, len(data) + 1)
    start = rng.randrange(0, len(data) - n + 1)
    chunk = data[start:start + n]
    return (data + chunk)[:max_len]


def remove_chunk(data: bytes, rng: random.Random) -> bytes:
    if len(data) <= 1:
        return data
    n = rng.randrange(1, len(data))
    start = rng.randrange(0, len(data) - n + 1)
    return data[:start] + data[start + n:]


_BYTE_MUTATORS = [
    flip_bits, set_interesting_byte, set_interesting_u32,
    truncate, extend, duplicate_chunk, remove_chunk,
]


def havoc(data: bytes, rng: random.Random, rounds: int | None = None) -> bytes:
    """Stack several random byte mutations (AFL-style havoc)."""
    rounds = rounds if rounds is not None else rng.randrange(1, 6)
    out = data
    for _ in range(rounds):
        out = rng.choice(_BYTE_MUTATORS)(out, rng)
    return out[:MAX_PAYLOAD]


# --- case-level strategies ------------------------------------------------------
def _mutate_rcm(case: TestCase, rng: random.Random) -> tuple[TestCase, str]:
    choice = rng.random()
    actual_total = rcm.LENGTH_FIELD_SIZE + len(case.payload)
    if choice < 0.5:
        # Diverge the declared length from the bytes actually sent — the core lever.
        pick = rng.random()
        if pick < 0.6:
            declared = rng.choice(INTERESTING_32)
        elif pick < 0.8:
            declared = max(0, actual_total + rng.choice([-2, -1, 1, 2]))
        else:
            declared = rng.randrange(0, 0x40000)
        return replace(case, declared_length=declared,
                       origin="mut:declared_length"), "declared_length"
    else:
        new_payload = havoc(case.payload, rng)
        return replace(case, payload=new_payload,
                       origin="mut:payload"), "payload"


def _mutate_control(case: TestCase, rng: random.Random) -> tuple[TestCase, str]:
    choice = rng.randrange(5)
    if choice == 0:
        # Oversized/odd IN length — the documented GET_STATUS over-read surface.
        wlen = rng.choice(INTERESTING_16)
        bmrt = (case.bmRequestType or 0x80) | 0x80  # force device->host
        return replace(case, bmRequestType=bmrt, wLength=wlen, data=b"",
                       origin="mut:wlength"), "wlength"
    if choice == 1:
        return replace(case, bRequest=rng.randrange(0x100),
                       origin="mut:brequest"), "brequest"
    if choice == 2:
        return replace(case, bmRequestType=rng.randrange(0x100),
                       origin="mut:bmrequesttype"), "bmrequesttype"
    if choice == 3:
        return replace(case, wValue=rng.choice(INTERESTING_16),
                       wIndex=rng.choice(INTERESTING_16),
                       origin="mut:windex_wvalue"), "windex_wvalue"
    # OUT data-stage fuzzing: make it an OUT request with a mutated data payload.
    bmrt = (case.bmRequestType or 0x00) & 0x7F  # host->device
    new_data = havoc(case.data or bytes(8), rng)
    return replace(case, bmRequestType=bmrt, data=new_data,
                   wLength=len(new_data), origin="mut:out_data"), "out_data"


def mutate(case: TestCase, rng: random.Random) -> tuple[TestCase, str]:
    """Mutate ``case`` into a new case, returning (case, strategy_name)."""
    if case.kind == "rcm":
        return _mutate_rcm(case, rng)
    if case.kind == "control":
        return _mutate_control(case, rng)
    raise ValueError(f"unknown case kind: {case.kind}")
