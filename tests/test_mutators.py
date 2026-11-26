import random

from tegra_fuzz import mutators as m
from tegra_fuzz.model import TestCase
from tegra_fuzz import rcm


def _rng(seed=0):
    return random.Random(seed)


def test_flip_bits_changes_within_length():
    data = b"\x00" * 8
    out = m.flip_bits(data, _rng(1), n=3)
    assert len(out) == len(data)
    assert out != data


def test_set_interesting_u32_writes_known_value():
    out = m.set_interesting_u32(b"\x00" * 16, _rng(2))
    assert len(out) == 16


def test_truncate_and_extend_bounds():
    data = b"ABCD" * 4
    assert len(m.truncate(data, _rng(3))) < len(data)
    grown = m.extend(data, _rng(3), max_len=64)
    assert len(grown) >= len(data)
    assert len(grown) <= 64


def test_havoc_respects_max_payload():
    out = m.havoc(b"\x00" * 10, _rng(4))
    assert len(out) <= m.MAX_PAYLOAD


def test_byte_mutators_handle_empty_input():
    for fn in (m.flip_bits, m.set_interesting_byte, m.set_interesting_u32,
               m.truncate, m.remove_chunk, m.duplicate_chunk):
        fn(b"", _rng(5))  # must not raise


def test_mutate_is_deterministic_for_same_seed():
    base = rcm.seed_cases()[0]
    a, sa = m.mutate(base, _rng(99))
    b, sb = m.mutate(base, _rng(99))
    assert sa == sb
    assert a.to_dict() == b.to_dict()


def test_mutate_rcm_produces_rcm_case():
    base = TestCase(kind="rcm", declared_length=0x44, payload=b"\x00" * 0x40)
    out, strategy = m.mutate(base, _rng(7))
    assert out.kind == "rcm"
    assert strategy in ("declared_length", "payload")
    assert out.origin.startswith("mut:")


def test_mutate_control_produces_control_case_and_strategies():
    base = TestCase(kind="control", bmRequestType=0x82, bRequest=0,
                    wValue=0, wIndex=rcm.EP_IN, wLength=2)
    seen = set()
    for seed in range(50):
        out, strategy = m.mutate(base, _rng(seed))
        assert out.kind == "control"
        seen.add(strategy)
    # Over many seeds we should exercise several distinct control strategies.
    assert {"wlength", "brequest", "bmrequesttype"} & seen


def test_wlength_mutation_stays_16bit():
    base = TestCase(kind="control", bmRequestType=0x82, bRequest=0,
                    wValue=0, wIndex=rcm.EP_IN, wLength=2)
    for seed in range(200):
        out, strategy = m.mutate(base, _rng(seed))
        if strategy == "wlength":
            assert 0 <= out.wLength <= 0xFFFF
