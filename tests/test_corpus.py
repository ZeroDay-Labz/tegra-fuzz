import json

from tegra_fuzz.corpus import Corpus, load_case
from tegra_fuzz.model import TestCase, Result, Outcome


def test_seeds_default_nonempty(tmp_path):
    c = Corpus(tmp_path)
    assert len(c) > 0
    assert all(isinstance(s, TestCase) for s in c)


def test_save_crash_writes_file(tmp_path):
    c = Corpus(tmp_path)
    case = TestCase(kind="rcm", origin="mut:declared_length",
                    declared_length=0xFFFFFFFF, payload=b"\x00" * 4)
    r = Result(case=case, outcome=Outcome.DISCONNECT, iteration=42)
    path = c.save_crash(r)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["outcome"] == "disconnect"
    assert data["case"]["declared_length"] == 0xFFFFFFFF
    assert c.saved == 1


def test_append_log_jsonl(tmp_path):
    c = Corpus(tmp_path)
    log = tmp_path / "session.jsonl"
    for i in range(3):
        r = Result(case=TestCase(kind="rcm"), outcome=Outcome.OK, iteration=i)
        c.append_log(log, r)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["outcome"] == "ok"


def test_load_case_from_crash_and_bare(tmp_path):
    case = TestCase(kind="control", bmRequestType=0x82, bRequest=0,
                    wValue=0, wIndex=0x81, wLength=0xFFFF)
    # bare case file
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(case.to_dict()))
    assert load_case(bare) == case
    # crash-style file (wrapped in a Result)
    c = Corpus(tmp_path)
    p = c.save_crash(Result(case=case, outcome=Outcome.LEAK))
    assert load_case(p) == case
