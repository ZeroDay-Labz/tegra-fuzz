"""Tests for device ID parsing."""
from tegra_fuzz.device_id import parse_device_id, ERISTA_PID, MARIKO_PID


REAL_DEVICE_ID = bytes.fromhex("40810205000000080047506401101062")


def test_parse_real_device_id():
    info = parse_device_id(REAL_DEVICE_ID, pid=ERISTA_PID, bcd_device=0x0102)
    assert info.chip == "T210 (Erista)"
    assert "A02" in info.revision
    assert info.uid == 0x05028140
    assert info.ecid == bytes.fromhex("000000080047506401101062")
    assert len(info.raw) == 16


def test_mariko_pid():
    fake = b"\x00" * 16
    info = parse_device_id(fake, pid=MARIKO_PID)
    assert "Mariko" in info.chip


def test_erista_pid():
    fake = b"\x00" * 16
    info = parse_device_id(fake, pid=ERISTA_PID)
    assert "Erista" in info.chip


def test_bcd_revisions():
    fake = b"\x00" * 16
    info = parse_device_id(fake, bcd_device=0x0102)
    assert "A02" in info.revision
    assert "production" in info.revision


def test_unknown_bcd():
    fake = b"\x00" * 16
    info = parse_device_id(fake, bcd_device=0x9999)
    assert "unknown" in info.revision


def test_summary_output():
    info = parse_device_id(REAL_DEVICE_ID, pid=ERISTA_PID, bcd_device=0x0102)
    s = info.summary()
    assert "T210" in s
    assert "A02" in s
    assert "0x05028140" in s.upper() or "0x05028140" in s


def test_rejects_wrong_length():
    import pytest
    with pytest.raises(ValueError):
        parse_device_id(b"\x00" * 8)
