import errno

import usb.core

from tegra_fuzz.transport import _map_usb_error, FakeTransport
from tegra_fuzz import rcm


def test_map_usb_error_kinds():
    assert _map_usb_error(usb.core.USBError("x", errno=errno.ETIMEDOUT)).kind == "timeout"
    assert _map_usb_error(usb.core.USBError("x", errno=errno.EPIPE)).kind == "stall"
    assert _map_usb_error(usb.core.USBError("x", errno=errno.ENODEV)).kind == "no_device"
    assert _map_usb_error(usb.core.USBError("x", errno=errno.EACCES)).kind == "permission"
    assert _map_usb_error(usb.core.USBError("x", errno=12345)).kind == "error"


def test_map_usb_timeout_error():
    if hasattr(usb.core, "USBTimeoutError"):
        assert _map_usb_error(usb.core.USBTimeoutError("t")).kind == "timeout"


def test_fake_transport_records_calls():
    t = FakeTransport()
    t.open()
    assert t.read_device_id() == b"\x00" * rcm.DEVICE_ID_LENGTH
    assert t.send_rcm(b"abcd") == 4
    assert t.sent == [b"abcd"]
    t.control(0x82, 0x00, 0, rcm.EP_IN, 2)
    assert t.controls and t.controls[0][0] == 0x82
    assert t.probe_alive() is True
    t.close()
    assert t.opened is False


def test_fake_transport_alive_sequence():
    t = FakeTransport()
    t.alive_sequence = [True, False, True]
    assert t.probe_alive() is True
    assert t.probe_alive() is False
    assert t.probe_alive() is True
    assert t.probe_alive() is True  # falls back to _alive once exhausted
