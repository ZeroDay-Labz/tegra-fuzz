"""Engine tests — every outcome path driven through FakeTransport, no hardware."""
from tegra_fuzz.engine import Fuzzer, FuzzConfig
from tegra_fuzz.corpus import Corpus
from tegra_fuzz.transport import FakeTransport, TransportError
from tegra_fuzz.model import TestCase, Outcome
from tegra_fuzz import rcm


def _fuzzer(tmp_path, transport, seeds=None, **cfg):
    corpus = Corpus(tmp_path, seeds=seeds if seeds is not None else rcm.seed_cases())
    return Fuzzer(transport, corpus, FuzzConfig(**cfg)), corpus


def test_execute_ok(tmp_path):
    t = FakeTransport()
    f, _ = _fuzzer(tmp_path, t)
    case = TestCase(kind="rcm", declared_length=4, payload=b"\x00" * 8)
    r = f.execute(case)
    assert r.outcome is Outcome.OK
    assert r.alive_after is True


def test_execute_stall(tmp_path):
    t = FakeTransport()
    t.on_send = lambda data: (_ for _ in ()).throw(TransportError("stall"))
    f, _ = _fuzzer(tmp_path, t)
    r = f.execute(TestCase(kind="rcm", declared_length=4, payload=b"\x00" * 8))
    assert r.outcome is Outcome.STALL


def test_execute_timeout(tmp_path):
    t = FakeTransport()
    t.on_send = lambda data: (_ for _ in ()).throw(TransportError("timeout"))
    f, _ = _fuzzer(tmp_path, t)
    r = f.execute(TestCase(kind="rcm", declared_length=4, payload=b"\x00"))
    assert r.outcome is Outcome.TIMEOUT


def test_execute_hang(tmp_path):
    t = FakeTransport()
    t.alive_sequence = [False]  # the post-case probe reports unresponsive
    f, _ = _fuzzer(tmp_path, t)
    r = f.execute(TestCase(kind="rcm", declared_length=4, payload=b"\x00"))
    assert r.outcome is Outcome.HANG
    assert r.outcome.interesting


def test_execute_reenumerate(tmp_path):
    t = FakeTransport()
    t._reenum = True
    f, _ = _fuzzer(tmp_path, t)
    r = f.execute(TestCase(kind="rcm", declared_length=4, payload=b"\x00"))
    assert r.outcome is Outcome.REENUMERATE


def test_execute_disconnect(tmp_path):
    t = FakeTransport()
    t.on_send = lambda data: (_ for _ in ()).throw(TransportError("no_device"))
    f, _ = _fuzzer(tmp_path, t)
    r = f.execute(TestCase(kind="rcm", declared_length=4, payload=b"\x00"))
    assert r.outcome is Outcome.DISCONNECT


def test_execute_permission(tmp_path):
    t = FakeTransport()
    t.on_send = lambda data: (_ for _ in ()).throw(TransportError("permission"))
    f, _ = _fuzzer(tmp_path, t)
    r = f.execute(TestCase(kind="rcm", declared_length=4, payload=b"\x00"))
    assert r.outcome is Outcome.PERMISSION


def test_execute_leak_on_control_in(tmp_path):
    t = FakeTransport()
    t.on_control = lambda *a: b"\xaa" * 8  # returns more than the requested 2 bytes
    f, _ = _fuzzer(tmp_path, t)
    case = TestCase(kind="control", bmRequestType=0x82, bRequest=0,
                    wValue=0, wIndex=rcm.EP_IN, wLength=2)
    r = f.execute(case)
    assert r.outcome is Outcome.LEAK
    assert len(r.response) == 8


def test_run_all_ok_completes(tmp_path):
    t = FakeTransport()
    f, corpus = _fuzzer(tmp_path, t, iterations=12, seed=1)
    summary = f.run()
    assert summary.iterations == 12
    assert summary.crashes == 0
    assert summary.stopped_reason == "completed"
    assert summary.counts.get("ok", 0) == 12


def test_run_saves_crashes_and_honours_max(tmp_path):
    t = FakeTransport()
    t.on_send = lambda data: (_ for _ in ()).throw(TransportError("no_device"))
    rcm_seeds = [s for s in rcm.seed_cases() if s.kind == "rcm"]
    f, corpus = _fuzzer(tmp_path, t, seeds=rcm_seeds, iterations=20, max_crashes=3)
    summary = f.run()
    assert summary.crashes == 3
    assert summary.stopped_reason == "max crashes reached"
    assert len(list(corpus.crash_dir.glob("*.json"))) == 3


def test_run_stops_on_permission(tmp_path):
    t = FakeTransport()
    t.on_send = lambda data: (_ for _ in ()).throw(TransportError("permission"))
    rcm_seeds = [s for s in rcm.seed_cases() if s.kind == "rcm"]
    f, _ = _fuzzer(tmp_path, t, seeds=rcm_seeds, iterations=20)
    summary = f.run()
    assert summary.iterations == 1
    assert "permission" in summary.stopped_reason


def test_run_writes_session_log(tmp_path):
    t = FakeTransport()
    corpus = Corpus(tmp_path, seeds=rcm.seed_cases())
    log = tmp_path / "session.jsonl"
    f = Fuzzer(t, corpus, FuzzConfig(iterations=5), log_path=log)
    f.run()
    assert log.exists()
    assert len(log.read_text().strip().splitlines()) == 5


def test_run_survives_failed_reopen_after_hang(tmp_path):
    """After a hang where reopen fails, the engine should stop gracefully
    instead of crashing with AttributeError on a None device handle."""
    t = FakeTransport()
    t.open()
    # True → _ensure_ready passes for case 0
    # False → post-case probe sees device as hung
    # False → next _ensure_ready fails, falls through to reopen
    t.alive_sequence = [True, False, False]
    t.reopen = lambda timeout_ms=2000: False

    rcm_seeds = [s for s in rcm.seed_cases() if s.kind == "rcm"]
    f, _ = _fuzzer(tmp_path, t, seeds=rcm_seeds, iterations=10)
    summary = f.run()
    assert summary.iterations == 1
    assert "device unavailable" in summary.stopped_reason
