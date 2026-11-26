"""Corpus management: seed cases plus persistence of interesting findings.

Interesting cases (hangs, resets, leaks) are written as individual JSON files so a
single finding can be replayed in isolation, and appended to a JSONL log for the
whole session.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .model import TestCase, Result
from . import rcm


class Corpus:
    """Holds seed cases and records interesting results to ``out_dir``."""

    def __init__(self, out_dir: Path | str, seeds: list[TestCase] | None = None):
        self.out_dir = Path(out_dir)
        self.crash_dir = self.out_dir / "crashes"
        self.seeds: list[TestCase] = list(seeds) if seeds is not None else rcm.seed_cases()
        self._saved = 0

    # -- seeds -------------------------------------------------------------------
    def __iter__(self):
        return iter(self.seeds)

    def __len__(self) -> int:
        return len(self.seeds)

    # -- persistence -------------------------------------------------------------
    def _ensure_dirs(self) -> None:
        self.crash_dir.mkdir(parents=True, exist_ok=True)

    def save_crash(self, result: Result) -> Path:
        """Write one interesting result to its own JSON file; return the path."""
        self._ensure_dirs()
        self._saved += 1
        name = f"{self._saved:04d}_{result.outcome.value}_{result.case.origin.replace(':', '-')}.json"
        path = self.crash_dir / name
        path.write_text(json.dumps(result.to_dict(), indent=2))
        return path

    def append_log(self, log_path: Path | str, result: Result) -> None:
        """Append a result as one JSON line to the session log."""
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a") as fh:
            fh.write(json.dumps({"t": time.time(), **result.to_dict()}) + "\n")

    @property
    def saved(self) -> int:
        return self._saved


def load_case(path: Path | str) -> TestCase:
    """Load a single saved case (from a crash file or a bare case JSON)."""
    data = json.loads(Path(path).read_text())
    if "case" in data:  # a saved Result
        data = data["case"]
    return TestCase.from_dict(data)
