"""Tests for the bootROM control transfer probing module."""
from tegra_fuzz.probe import (
    ProbeResult, _make_result, STD_REQUESTS,
    BMRT_STD_DEV_IN, BMRT_VENDOR_DEV_IN,
)


def test_make_result_response():
    r = _make_result("A:pre_config", BMRT_STD_DEV_IN, 0x06, 0x0100, 0x0000, 18,
                     "response", b"\x12\x01\x00\x02", "", 1.5)
    assert r.outcome == "response"
    assert r.response_hex == "12010002"
    assert r.response_len == 4
    assert r.phase == "A:pre_config"


def test_make_result_stall():
    r = _make_result("B:post_config", BMRT_VENDOR_DEV_IN, 0xFF, 0, 0, 64,
                     "stall", b"", "EPIPE", 0.5)
    assert r.outcome == "stall"
    assert r.response_len == 0


def test_make_result_timeout():
    r = _make_result("C:post_handshake", BMRT_STD_DEV_IN, 0x00, 0, 0, 2,
                     "timeout", b"", "timed out", 500.0)
    assert r.outcome == "timeout"


def test_probe_result_to_dict():
    r = ProbeResult(
        phase="A:pre_config",
        bmRequestType=0xC0, bRequest=0x42, wValue=0, wIndex=0,
        wLength=64, outcome="response", response_hex="deadbeef",
        response_len=4, elapsed_ms=1.5,
    )
    d = r.to_dict()
    assert d["phase"] == "A:pre_config"
    assert d["bmRequestType"] == 0xC0
    assert d["bRequest"] == 0x42
    assert d["outcome"] == "response"
    assert d["response_hex"] == "deadbeef"


def test_std_requests_has_known_values():
    assert STD_REQUESTS[0x00] == "GET_STATUS"
    assert STD_REQUESTS[0x06] == "GET_DESCRIPTOR"
    assert STD_REQUESTS[0x08] == "GET_CONFIGURATION"
    assert STD_REQUESTS[0x09] == "SET_CONFIGURATION"


def test_make_result_empty_data():
    r = _make_result("A:pre_config", BMRT_STD_DEV_IN, 0x00, 0, 0, 2,
                     "error", b"", "generic error", 0.1)
    assert r.response_hex == ""
    assert r.response_len == 0
