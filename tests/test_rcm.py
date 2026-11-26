import struct

from tegra_fuzz import rcm
from tegra_fuzz.model import TestCase


def test_build_message_prefixes_declared_length():
    msg = rcm.build_message(0x1234, b"\xaa\xbb")
    assert msg[:4] == struct.pack("<I", 0x1234)
    assert msg[4:] == b"\xaa\xbb"


def test_build_message_masks_to_u32():
    msg = rcm.build_message(0x1_0000_0001, b"")
    assert msg == struct.pack("<I", 1)


def test_case_to_wire_default_declared_equals_actual():
    c = TestCase(kind="rcm", declared_length=None, payload=b"\x00" * 16)
    wire = rcm.case_to_wire(c)
    declared = struct.unpack("<I", wire[:4])[0]
    assert declared == rcm.LENGTH_FIELD_SIZE + 16
    assert len(wire) == 4 + 16


def test_case_to_wire_preserves_divergent_declared_length():
    c = TestCase(kind="rcm", declared_length=0xFFFF, payload=b"\x00" * 8)
    wire = rcm.case_to_wire(c)
    assert struct.unpack("<I", wire[:4])[0] == 0xFFFF
    assert len(wire) == 4 + 8  # actual bytes unchanged despite the big declared value


def test_case_to_wire_rejects_non_rcm():
    import pytest
    with pytest.raises(ValueError):
        rcm.case_to_wire(TestCase(kind="control"))


def test_seed_cases_are_valid_and_cover_both_domains():
    seeds = rcm.seed_cases()
    assert seeds
    kinds = {s.kind for s in seeds}
    assert kinds == {"rcm", "control"}
    for s in seeds:
        assert s.origin.startswith("seed:")
        if s.kind == "rcm":
            assert isinstance(s.payload, bytes)
        else:
            assert s.bmRequestType is not None and s.bRequest is not None
