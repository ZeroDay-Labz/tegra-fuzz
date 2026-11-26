"""The fuzz loop: scheduling, execution, classification, logging, stop conditions.

The engine is transport-agnostic (it is handed a :class:`Transport`), so the whole
loop is exercised in tests with ``FakeTransport`` and never needs hardware.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from .model import Outcome, Result, TestCase
from .transport import Transport, TransportError
from .corpus import Corpus
from .mutators import mutate
from . import rcm, monitor


@dataclass
class FuzzConfig:
    iterations: int = 1000
    seed: int = 0
    timeout_ms: int = 1000
    probe_timeout_ms: int = 500
    delay_ms: float = 0.0
    max_crashes: int = 0            # 0 = unlimited
    reopen: bool = True             # try to re-acquire the device after a reset
    read_rcm_response: bool = False  # read EP_IN after an rcm send (may add latency)
    stop_on_disconnect: bool = False
    skip_seeds: bool = False        # jump straight to mutations


@dataclass
class FuzzSummary:
    iterations: int = 0
    crashes: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    stopped_reason: str = ""


class Fuzzer:
    def __init__(
        self,
        transport: Transport,
        corpus: Corpus,
        config: FuzzConfig | None = None,
        log_path: Path | str | None = None,
        on_result: Callable[[Result], None] | None = None,
    ):
        import random
        self.transport = transport
        self.corpus = corpus
        self.config = config or FuzzConfig()
        self.log_path = Path(log_path) if log_path else None
        self.on_result = on_result
        self.rng = random.Random(self.config.seed)
        self.stats: Counter[Outcome] = Counter()
        self.crashes = 0

    # -- scheduling --------------------------------------------------------------
    def _schedule(self) -> Iterator[TestCase]:
        pool = list(self.corpus.seeds)
        if not pool:
            pool = rcm.seed_cases()
        if not self.config.skip_seeds:
            for case in pool:
                yield case
        while True:
            base = self.rng.choice(pool)
            case, _strategy = mutate(base, self.rng)
            yield case

    # -- execution ---------------------------------------------------------------
    def execute(self, case: TestCase) -> Result:
        start = time.perf_counter()
        response = b""
        kind: str | None = None
        detail = ""
        try:
            if case.kind == "rcm":
                self.transport.send_rcm(rcm.case_to_wire(case), self.config.timeout_ms)
                if self.config.read_rcm_response:
                    try:
                        response = self.transport.read_device_id(self.config.timeout_ms)
                    except TransportError:
                        pass
            elif case.kind == "control":
                if case.is_control_in():
                    response = self.transport.control(
                        case.bmRequestType, case.bRequest, case.wValue,
                        case.wIndex, case.wLength or 0, self.config.timeout_ms)
                else:
                    self.transport.control(
                        case.bmRequestType, case.bRequest, case.wValue,
                        case.wIndex, case.data, self.config.timeout_ms)
            else:
                raise ValueError(f"unknown case kind: {case.kind}")
        except TransportError as exc:
            kind = exc.kind
            detail = str(exc)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        base = monitor.base_outcome(kind)

        responsive, reenum = True, False
        if base != Outcome.PERMISSION:
            try:
                responsive = self.transport.probe_alive(self.config.probe_timeout_ms)
                reenum = self.transport.reenumerated()
            except TransportError:
                responsive = False

        outcome = monitor.upgrade(base, responsive=responsive, reenumerated=reenum)
        if outcome == Outcome.OK and monitor.is_leak(case, len(response)):
            outcome = Outcome.LEAK

        return Result(
            case=case, outcome=outcome, detail=detail, response=response,
            elapsed_ms=elapsed_ms, alive_after=responsive, reenumerated=reenum,
        )

    # -- driver ------------------------------------------------------------------
    def _handshake(self) -> bool:
        """Read the RCM device ID so the bootROM advances to the receive state."""
        try:
            self._device_id = self.transport.read_device_id(self.config.timeout_ms)
            return True
        except TransportError:
            return False

    def _ensure_ready(self) -> bool:
        try:
            if self.transport.probe_alive(self.config.probe_timeout_ms):
                return True
        except TransportError:
            pass
        if self.config.reopen:
            if self.transport.reopen():
                self._needs_handshake = True
                return True
            return False
        return False

    def run(self) -> FuzzSummary:
        self._needs_handshake = True
        self._device_id = b""
        gen = self._schedule()
        summary = FuzzSummary()
        reason = "completed"
        for i in range(self.config.iterations):
            if not self._ensure_ready():
                reason = "device unavailable"
                break

            case = next(gen)

            if self._needs_handshake and case.kind == "rcm":
                if not self._handshake():
                    reason = "device unavailable (handshake failed)"
                    break
                self._needs_handshake = False

            result = self.execute(case)
            result.iteration = i
            summary.iterations = i + 1

            self.stats[result.outcome] += 1
            if self.log_path is not None:
                self.corpus.append_log(self.log_path, result)
            if self.on_result is not None:
                self.on_result(result)

            if result.outcome.interesting:
                self.corpus.save_crash(result)
                self.crashes += 1
                if self.config.max_crashes and self.crashes >= self.config.max_crashes:
                    reason = "max crashes reached"
                    break

            if result.outcome == Outcome.PERMISSION:
                reason = "permission denied (try sudo / udev group)"
                break

            if result.outcome in (Outcome.DISCONNECT, Outcome.REENUMERATE, Outcome.HANG):
                if self.config.stop_on_disconnect:
                    reason = f"stopped on {result.outcome.value}"
                    break
                if self.config.reopen:
                    self.transport.reopen()
                    self._needs_handshake = True

            if self.config.delay_ms:
                time.sleep(self.config.delay_ms / 1000.0)

        summary.crashes = self.crashes
        summary.counts = {o.value: c for o, c in self.stats.items()}
        summary.stopped_reason = reason
        return summary
