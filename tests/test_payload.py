"""Tests for the Fusée Gelée payload builder."""
import struct
from tegra_fuzz.payload import (
    build_exploit,
    RCM_PAYLOAD_ADDR,
    INTERMEZZO_LOCATION,
    PAYLOAD_LOAD_BLOCK,
    EXPLOIT_HEADER_SIZE,
    EXPLOIT_MAX_LENGTH,
    _INTERMEZZO,
)


def test_intermezzo_is_92_bytes():
    assert len(_INTERMEZZO) == 92


def test_intermezzo_self_relocation_target():
    """The literal pool's first word should be the post_relocation address."""
    post_reloc = struct.unpack_from("<I", _INTERMEZZO, 0x4C)[0]
    assert post_reloc == INTERMEZZO_LOCATION + 0x20


def test_intermezzo_payload_addresses():
    """Literal pool should contain PAYLOAD_LOAD_BLOCK and RCM_PAYLOAD_ADDR."""
    load_block = struct.unpack_from("<I", _INTERMEZZO, 0x54)[0]
    payload_addr = struct.unpack_from("<I", _INTERMEZZO, 0x58)[0]
    assert load_block == PAYLOAD_LOAD_BLOCK
    assert payload_addr == RCM_PAYLOAD_ADDR


def test_exploit_header():
    payload = b"\xAA" * 256
    buf = build_exploit(payload)
    length_field = struct.unpack_from("<I", buf, 0)[0]
    assert length_field == EXPLOIT_MAX_LENGTH
    assert buf[4:EXPLOIT_HEADER_SIZE] == b"\x00" * (EXPLOIT_HEADER_SIZE - 4)


def test_exploit_stack_spray():
    payload = b"\xBB" * 256
    buf = build_exploit(payload)
    spray_start = EXPLOIT_HEADER_SIZE
    spray_count = (INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDR) // 4
    for i in range(spray_count):
        off = spray_start + i * 4
        val = struct.unpack_from("<I", buf, off)[0]
        assert val == INTERMEZZO_LOCATION, f"spray word {i} at offset {off}"


def test_exploit_payload_placement():
    payload = b"\xCC" * 512
    buf = build_exploit(payload)
    payload_offset = EXPLOIT_HEADER_SIZE + (PAYLOAD_LOAD_BLOCK - RCM_PAYLOAD_ADDR)
    assert buf[payload_offset:payload_offset + len(payload)] == payload


def test_exploit_aligned_to_0x1000():
    for size in (1, 255, 4096, 10000):
        buf = build_exploit(b"\x00" * size)
        assert len(buf) % 0x1000 == 0, f"payload size {size} -> buf len {len(buf)}"


def test_exploit_intermezzo_at_correct_offset():
    payload = b"\xDD" * 128
    buf = build_exploit(payload)
    intermezzo_offset = EXPLOIT_HEADER_SIZE + (INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDR)
    assert buf[intermezzo_offset:intermezzo_offset + len(_INTERMEZZO)] == _INTERMEZZO
