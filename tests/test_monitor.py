from tegra_fuzz import monitor
from tegra_fuzz.model import Outcome, TestCase


def test_base_outcome_mapping():
    assert monitor.base_outcome(None) is Outcome.OK
    assert monitor.base_outcome("timeout") is Outcome.TIMEOUT
    assert monitor.base_outcome("stall") is Outcome.STALL
    assert monitor.base_outcome("no_device") is Outcome.DISCONNECT
    assert monitor.base_outcome("permission") is Outcome.PERMISSION
    assert monitor.base_outcome("bogus") is Outcome.ERROR


def test_upgrade_reenumerate_wins():
    assert monitor.upgrade(Outcome.OK, responsive=True, reenumerated=True) is Outcome.REENUMERATE
    assert monitor.upgrade(Outcome.STALL, responsive=False, reenumerated=True) is Outcome.REENUMERATE


def test_upgrade_unresponsive_becomes_hang():
    assert monitor.upgrade(Outcome.OK, responsive=False, reenumerated=False) is Outcome.HANG
    assert monitor.upgrade(Outcome.TIMEOUT, responsive=False, reenumerated=False) is Outcome.HANG


def test_upgrade_keeps_disconnect_and_permission():
    assert monitor.upgrade(Outcome.DISCONNECT, responsive=False, reenumerated=False) is Outcome.DISCONNECT
    assert monitor.upgrade(Outcome.PERMISSION, responsive=False, reenumerated=False) is Outcome.PERMISSION


def test_upgrade_responsive_keeps_base():
    assert monitor.upgrade(Outcome.STALL, responsive=True, reenumerated=False) is Outcome.STALL
    assert monitor.upgrade(Outcome.OK, responsive=True, reenumerated=False) is Outcome.OK


def test_is_leak_only_for_control_in_overshoot():
    in_case = TestCase(kind="control", bmRequestType=0x82, wLength=2)
    assert monitor.is_leak(in_case, response_len=8) is True
    assert monitor.is_leak(in_case, response_len=2) is False
    out_case = TestCase(kind="control", bmRequestType=0x00, wLength=2)
    assert monitor.is_leak(out_case, response_len=99) is False
    assert monitor.is_leak(TestCase(kind="rcm"), response_len=99) is False
