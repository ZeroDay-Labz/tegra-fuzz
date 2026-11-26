from tegra_fuzz.model import TestCase, Outcome, Result


def test_testcase_roundtrip_rcm():
    c = TestCase(kind="rcm", origin="seed:x", declared_length=0x40,
                 payload=b"\xde\xad\xbe\xef")
    d = c.to_dict()
    assert d["payload"] == "deadbeef"
    back = TestCase.from_dict(d)
    assert back == c


def test_testcase_roundtrip_control():
    c = TestCase(kind="control", origin="mut:wlength", bmRequestType=0x82,
                 bRequest=0, wValue=1, wIndex=0x81, wLength=0xFFFF, data=b"\x01\x02")
    back = TestCase.from_dict(c.to_dict())
    assert back == c
    assert back.is_control_in() is True


def test_from_dict_ignores_unknown_keys():
    d = {"kind": "rcm", "payload": "00", "future_field": 123}
    c = TestCase.from_dict(d)
    assert c.kind == "rcm" and c.payload == b"\x00"


def test_is_control_in_direction():
    assert TestCase(kind="control", bmRequestType=0x00).is_control_in() is False
    assert TestCase(kind="control", bmRequestType=0x80).is_control_in() is True
    assert TestCase(kind="rcm").is_control_in() is False


def test_outcome_interesting_set():
    assert Outcome.HANG.interesting
    assert Outcome.DISCONNECT.interesting
    assert Outcome.REENUMERATE.interesting
    assert Outcome.LEAK.interesting
    assert not Outcome.OK.interesting
    assert not Outcome.STALL.interesting
    assert not Outcome.TIMEOUT.interesting


def test_result_to_dict():
    c = TestCase(kind="rcm", declared_length=4, payload=b"")
    r = Result(case=c, outcome=Outcome.OK, response=b"\xaa", iteration=7)
    d = r.to_dict()
    assert d["outcome"] == "ok" and d["iteration"] == 7
    assert d["response"] == "aa" and d["case"]["kind"] == "rcm"
