"""Tests for the usbmon parsing module."""
from tegra_fuzz.usbmon import parse_usbmon_line


def test_parse_control_submit():
    line = "d5a4e300 3862934145 S Ci:3:028:0 s 80 06 0100 0000 0012 18 <"
    evt = parse_usbmon_line(line)
    assert evt is not None
    assert evt.timestamp_us == 3862934145
    assert evt.event_type == "S"
    assert evt.bus == 3
    assert evt.device == 28
    assert evt.endpoint == 0
    assert evt.setup_hex == "80 06 0100 0000 0012"


def test_parse_control_callback():
    line = "d5a4e300 3862934200 C Ci:3:028:0 0 18 = 12010002 ff000040 55090121 02000102 03010000"
    evt = parse_usbmon_line(line)
    assert evt is not None
    assert evt.event_type == "C"
    assert evt.status == 0
    assert evt.length == 18
    assert "12010002" in evt.data_hex


def test_parse_bulk_submit():
    line = "abcd1234 100000 S Bo:3:028:1 4096"
    evt = parse_usbmon_line(line)
    assert evt is not None
    assert evt.event_type == "S"
    assert evt.direction == "OUT"
    assert evt.endpoint == 1
    assert evt.length == 4096


def test_parse_bulk_callback():
    line = "abcd1234 100050 C Bi:3:028:1 0 16 = 40810205000000080047506401101062"
    evt = parse_usbmon_line(line)
    assert evt is not None
    assert evt.event_type == "C"
    assert evt.direction == "IN"
    assert evt.length == 16
    assert "4081020500" in evt.data_hex


def test_parse_malformed_returns_none():
    assert parse_usbmon_line("") is None
    assert parse_usbmon_line("not a valid line") is None
    assert parse_usbmon_line("short") is None


def test_parse_error_event():
    line = "deadbeef 200000 E Bi:3:028:1 -32 0"
    evt = parse_usbmon_line(line)
    assert evt is not None
    assert evt.event_type == "E"
