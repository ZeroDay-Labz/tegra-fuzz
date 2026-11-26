"""Core data model: a fuzz test case, the possible outcomes, and a result.

Everything here is pure and JSON-serialisable so that any interesting case can be
written to disk and replayed byte-for-byte later. No hardware dependency.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, ClassVar


class Outcome(enum.Enum):
    """Classification of what happened when a case was applied to the device."""

    OK = "ok"                    # device accepted input and stayed responsive
    STALL = "stall"              # endpoint stalled (EPIPE) but device still live
    TIMEOUT = "timeout"          # a transfer timed out
    HANG = "hang"                # device present but no longer answers liveness probe
    DISCONNECT = "disconnect"    # device vanished / reset off the bus
    REENUMERATE = "reenumerate"  # device re-appeared at a new address (reset)
    LEAK = "leak"                # an IN transfer returned more/other data than expected
    PERMISSION = "permission"    # access denied (need sudo / udev group)
    ERROR = "error"              # other USB/backend error

    @property
    def interesting(self) -> bool:
        """Outcomes worth saving to the crash corpus for follow-up."""
        return self in _INTERESTING


_INTERESTING = frozenset(
    {Outcome.HANG, Outcome.DISCONNECT, Outcome.REENUMERATE, Outcome.LEAK}
)


@dataclass
class TestCase:
    """One concrete thing to send to the device.

    kind == "rcm":     write ``payload`` to the bulk OUT endpoint, having told the
                       bootROM the message is ``declared_length`` bytes. The whole
                       point of the RCM bug class is the mismatch between the
                       declared length and the number of bytes actually sent.
    kind == "control": issue a USB control transfer (``bmRequestType`` .. ``wLength``).
                       For an IN request, ``wLength`` bytes are requested; for an OUT
                       request, ``data`` is sent.
    """

    __test__: ClassVar[bool] = False  # not a pytest test class despite the name

    kind: str                       # "rcm" | "control"
    origin: str = "seed"            # provenance, e.g. "seed:valid" or "mut:declared_length"

    # rcm fields
    declared_length: int | None = None
    payload: bytes = b""

    # control fields
    bmRequestType: int | None = None
    bRequest: int | None = None
    wValue: int = 0
    wIndex: int = 0
    wLength: int | None = None      # IN request length (<= 0xFFFF)
    data: bytes = b""               # OUT control data stage

    def is_control_in(self) -> bool:
        return self.kind == "control" and bool((self.bmRequestType or 0) & 0x80)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["payload"] = self.payload.hex()
        d["data"] = self.data.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TestCase":
        d = dict(d)
        d["payload"] = bytes.fromhex(d.get("payload", "") or "")
        d["data"] = bytes.fromhex(d.get("data", "") or "")
        # tolerate unknown/extra keys from newer formats
        allowed = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in allowed})

    def summary(self) -> str:
        if self.kind == "rcm":
            wire_len = 4 + len(self.payload)
            return (
                f"rcm declared={self.declared_length} "
                f"wire={wire_len} [{self.origin}]"
            )
        dir_ = "IN" if self.is_control_in() else "OUT"
        return (
            f"ctrl {dir_} bmRequestType=0x{(self.bmRequestType or 0):02x} "
            f"bRequest=0x{(self.bRequest or 0):02x} wValue=0x{self.wValue:04x} "
            f"wIndex=0x{self.wIndex:04x} wLength={self.wLength} [{self.origin}]"
        )


@dataclass
class Result:
    """Outcome of applying one :class:`TestCase`."""

    case: TestCase
    outcome: Outcome
    detail: str = ""
    response: bytes = b""       # any IN data captured
    elapsed_ms: float = 0.0
    alive_after: bool = True
    reenumerated: bool = False
    iteration: int = -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "alive_after": self.alive_after,
            "reenumerated": self.reenumerated,
            "response": self.response.hex(),
            "case": self.case.to_dict(),
        }
