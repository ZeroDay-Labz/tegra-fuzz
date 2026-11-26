"""Outcome classification — pure functions that turn transport behaviour and a
post-case liveness probe into an :class:`Outcome`. No hardware, no I/O.
"""
from __future__ import annotations

from .model import Outcome, TestCase

# Transfer-level transport error -> base outcome.
_KIND_TO_OUTCOME = {
    "timeout": Outcome.TIMEOUT,
    "stall": Outcome.STALL,
    "no_device": Outcome.DISCONNECT,
    "permission": Outcome.PERMISSION,
    "error": Outcome.ERROR,
}


def base_outcome(kind: str | None) -> Outcome:
    """Outcome implied by the transfer itself (``None`` kind == it succeeded)."""
    if kind is None:
        return Outcome.OK
    return _KIND_TO_OUTCOME.get(kind, Outcome.ERROR)


def upgrade(base: Outcome, *, responsive: bool, reenumerated: bool) -> Outcome:
    """Refine the base outcome using the post-case liveness probe.

    A device that re-appeared at a new address was reset; a device that stopped
    answering (without the transfer itself reporting it gone) has hung. A transfer
    that already reported the device gone stays a DISCONNECT.
    """
    if reenumerated:
        return Outcome.REENUMERATE
    if base in (Outcome.DISCONNECT, Outcome.PERMISSION):
        return base
    if not responsive:
        return Outcome.HANG
    return base


def is_leak(case: TestCase, response_len: int) -> bool:
    """True if an IN control transfer returned more data than it was asked for."""
    if not case.is_control_in():
        return False
    requested = case.wLength if case.wLength is not None else 0
    return response_len > requested
