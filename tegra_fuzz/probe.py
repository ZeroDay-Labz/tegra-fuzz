"""Systematic USB control transfer probing for the Tegra X1 bootROM.

Probes the bootROM's control transfer surface at each stage of the RCM
protocol state machine:
  - Phase A: Before set_configuration (raw device, as the kernel sees it)
  - Phase B: After set_configuration + claim, before device ID read
  - Phase C: After device ID read (RCM handshake complete)

The bootROM's USB implementation is minimal and state-dependent. Control
transfers that work in one state may fail in another, revealing the internal
state machine structure.

Usage:
    sudo python -m tegra_fuzz.probe [--out findings/probe_results.json]
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from . import rcm
from .transport import TransportError


@dataclass
class ProbeResult:
    phase: str
    bmRequestType: int
    bRequest: int
    wValue: int
    wIndex: int
    wLength: int
    outcome: str          # "response", "stall", "timeout", "no_device", "error"
    response_hex: str = ""
    response_len: int = 0
    detail: str = ""
    elapsed_ms: float = 0.0

    def to_dict(self):
        return asdict(self)


def _ctrl(dev, bmrt, breq, wval, widx, wlen, timeout_ms=500):
    """Issue a control transfer via raw pyusb device handle."""
    import usb.core
    t0 = time.monotonic()
    try:
        ret = dev.ctrl_transfer(bmrt, breq, wval, widx, wlen, timeout_ms)
        elapsed = (time.monotonic() - t0) * 1000
        data = bytes(ret) if ret is not None and not isinstance(ret, int) else b""
        return "response", data, "", round(elapsed, 2)
    except usb.core.USBTimeoutError:
        elapsed = (time.monotonic() - t0) * 1000
        return "timeout", b"", "timeout", round(elapsed, 2)
    except usb.core.USBError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        errno = getattr(exc, "errno", None)
        if errno == 32:  # EPIPE = stall
            return "stall", b"", str(exc), round(elapsed, 2)
        if errno in (19, 6):  # ENODEV, ENXIO
            return "no_device", b"", str(exc), round(elapsed, 2)
        return "error", b"", str(exc), round(elapsed, 2)


def _make_result(phase, bmrt, breq, wval, widx, wlen, outcome, data, detail, elapsed):
    return ProbeResult(
        phase=phase, bmRequestType=bmrt, bRequest=breq, wValue=wval,
        wIndex=widx, wLength=wlen, outcome=outcome,
        response_hex=data.hex() if data else "",
        response_len=len(data) if data else 0,
        detail=detail, elapsed_ms=elapsed,
    )


# Standard USB request types
BMRT_STD_DEV_IN    = 0x80
BMRT_STD_IF_IN     = 0x81
BMRT_STD_EP_IN     = 0x82
BMRT_VENDOR_DEV_IN = 0xC0
BMRT_VENDOR_IF_IN  = 0xC1
BMRT_CLASS_DEV_IN  = 0xA0
BMRT_STD_DEV_OUT   = 0x00
BMRT_VENDOR_DEV_OUT = 0x40

STD_REQUESTS = {
    0x00: "GET_STATUS", 0x01: "CLEAR_FEATURE", 0x03: "SET_FEATURE",
    0x05: "SET_ADDRESS", 0x06: "GET_DESCRIPTOR", 0x07: "SET_DESCRIPTOR",
    0x08: "GET_CONFIGURATION", 0x09: "SET_CONFIGURATION",
    0x0A: "GET_INTERFACE", 0x0B: "SET_INTERFACE", 0x0C: "SYNCH_FRAME",
}

DESC_TYPES = {
    0x01: "DEVICE", 0x02: "CONFIGURATION", 0x03: "STRING",
    0x06: "DEVICE_QUALIFIER", 0x07: "OTHER_SPEED_CONFIG", 0x0F: "BOS",
}


def _probe_standard(dev, phase: str) -> list[ProbeResult]:
    """Probe standard requests and descriptors."""
    results = []

    # GET_STATUS on device
    for bmrt, widx, label in [
        (BMRT_STD_DEV_IN, 0, "device"),
        (BMRT_STD_IF_IN, 0, "iface0"),
        (BMRT_STD_EP_IN, rcm.EP_IN, "EP_IN"),
        (BMRT_STD_EP_IN, rcm.EP_OUT, "EP_OUT"),
    ]:
        o, d, det, ms = _ctrl(dev, bmrt, 0x00, 0, widx, 2)
        r = _make_result(phase, bmrt, 0x00, 0, widx, 2, o, d, det, ms)
        results.append(r)
        resp = f" → {d.hex()}" if d else ""
        print(f"  GET_STATUS ({label}): {o}{resp}", file=sys.stderr)

    # GET_DESCRIPTOR for each type
    for dtype, name in DESC_TYPES.items():
        wval = (dtype << 8)
        o, d, det, ms = _ctrl(dev, BMRT_STD_DEV_IN, 0x06, wval, 0, 255)
        r = _make_result(phase, BMRT_STD_DEV_IN, 0x06, wval, 0, 255, o, d, det, ms)
        results.append(r)
        status = o
        if len(d) > 0:
            status += f" ({len(d)}B)"
        print(f"  GET_DESCRIPTOR {name}: {status}", file=sys.stderr)

    # String descriptors
    for idx in range(4):
        wval = (0x03 << 8) | idx
        o, d, det, ms = _ctrl(dev, BMRT_STD_DEV_IN, 0x06, wval, 0, 255)
        r = _make_result(phase, BMRT_STD_DEV_IN, 0x06, wval, 0, 255, o, d, det, ms)
        results.append(r)
        if d:
            print(f"  STRING[{idx}]: {o} ({len(d)}B) → {d.hex()[:60]}", file=sys.stderr)

    # GET_CONFIGURATION
    o, d, det, ms = _ctrl(dev, BMRT_STD_DEV_IN, 0x08, 0, 0, 1)
    r = _make_result(phase, BMRT_STD_DEV_IN, 0x08, 0, 0, 1, o, d, det, ms)
    results.append(r)
    print(f"  GET_CONFIGURATION: {o}{' → ' + d.hex() if d else ''}", file=sys.stderr)

    return results


def _probe_vendor_sweep(dev, phase: str) -> list[ProbeResult]:
    """Sweep bRequest 0x00–0xFF for vendor and class request types."""
    results = []

    request_types = [
        (BMRT_STD_DEV_IN, "std:dev:IN"),
        (BMRT_VENDOR_DEV_IN, "vendor:dev:IN"),
        (BMRT_VENDOR_IF_IN, "vendor:if:IN"),
        (BMRT_CLASS_DEV_IN, "class:dev:IN"),
    ]

    for bmrt, label in request_types:
        print(f"\n  Sweep {label} (0x00–0xFF):", file=sys.stderr)
        non_stall = 0
        for breq in range(256):
            o, d, det, ms = _ctrl(dev, bmrt, breq, 0, 0, 64, timeout_ms=200)
            r = _make_result(phase, bmrt, breq, 0, 0, 64, o, d, det, ms)
            results.append(r)

            if o not in ("stall", "error"):
                non_stall += 1
                name = STD_REQUESTS.get(breq, f"0x{breq:02X}")
                resp = f" → {d.hex()[:40]}" if d else ""
                print(f"    *** {name}: {o} ({len(d)}B, {ms:.0f}ms){resp}",
                      file=sys.stderr)

            if o == "no_device":
                print(f"    DISCONNECT at 0x{breq:02X}!", file=sys.stderr)
                return results

        print(f"  → {non_stall}/256 non-stall non-error for {label}", file=sys.stderr)

    return results


def _probe_get_status_lengths(dev, phase: str) -> list[ProbeResult]:
    """GET_STATUS with escalating wLength — the CVE-2018-6242 trigger surface."""
    results = []
    lengths = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
               0x1000, 0x2000, 0x4000, 0x7FFF, 0xFFFF]

    print(f"\n  GET_STATUS wLength sweep (EP 0x81):", file=sys.stderr)
    for wlen in lengths:
        o, d, det, ms = _ctrl(dev, BMRT_STD_EP_IN, 0x00, 0, rcm.EP_IN,
                               wlen, timeout_ms=1000)
        r = _make_result(phase, BMRT_STD_EP_IN, 0x00, 0, rcm.EP_IN, wlen,
                          o, d, det, ms)
        results.append(r)
        print(f"    wLen=0x{wlen:04X}: {o} ({len(d)}B, {ms:.0f}ms)", file=sys.stderr)

        if o == "no_device":
            print(f"    DISCONNECT!", file=sys.stderr)
            break
        if len(d) > 2:
            print(f"    *** OVER-READ: got {len(d)}B for 2B status!", file=sys.stderr)

    return results


def run_probe(out_path: str | None = None) -> int:
    import usb.core
    import usb.util

    print("tegra_fuzz bootROM state-aware control transfer probe", file=sys.stderr)
    print("=" * 55, file=sys.stderr)
    print(file=sys.stderr)

    dev = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    if dev is None:
        print("error: Tegra APX device not found.", file=sys.stderr)
        return 2

    print(f"  Device: bus {dev.bus}, addr {dev.address}", file=sys.stderr)
    print(f"  PID: 0x{dev.idProduct:04X}, bcdDevice: 0x{dev.bcdDevice:04X}",
          file=sys.stderr)
    print(file=sys.stderr)

    all_results: dict[str, list[dict]] = {}

    # =========================================================================
    # PHASE A: Before set_configuration — raw device, as kernel enumerated it
    # The bootROM should still be in its initial USB state.
    # =========================================================================
    print("PHASE A: Before set_configuration (initial USB state)", file=sys.stderr)
    print("-" * 55, file=sys.stderr)

    phase_a_std = _probe_standard(dev, "A:pre_config")
    all_results["phase_a_standard"] = [r.to_dict() for r in phase_a_std]

    # Quick vendor sweep in this state
    phase_a_vendor = _probe_vendor_sweep(dev, "A:pre_config")
    all_results["phase_a_vendor_sweep"] = [r.to_dict() for r in phase_a_vendor]

    # GET_STATUS length sweep in pre-config state
    phase_a_lengths = _probe_get_status_lengths(dev, "A:pre_config")
    all_results["phase_a_get_status_lengths"] = [r.to_dict() for r in phase_a_lengths]

    # Check if device survived
    dev2 = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    if dev2 is None:
        print("\nDevice disconnected during Phase A. Saving partial results.",
              file=sys.stderr)
        _save(all_results, out_path)
        return 1

    # =========================================================================
    # PHASE B: After set_configuration + claim, before device ID read
    # =========================================================================
    print(f"\n\nPHASE B: After set_configuration, before device ID read",
          file=sys.stderr)
    print("-" * 55, file=sys.stderr)

    try:
        try:
            if dev.is_kernel_driver_active(rcm.INTERFACE):
                dev.detach_kernel_driver(rcm.INTERFACE)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, rcm.INTERFACE)
        print("  set_configuration + claim_interface: OK", file=sys.stderr)
    except usb.core.USBError as exc:
        print(f"  set_configuration failed: {exc}", file=sys.stderr)
        print("  Trying Phase B probes anyway...", file=sys.stderr)

    phase_b_std = _probe_standard(dev, "B:post_config")
    all_results["phase_b_standard"] = [r.to_dict() for r in phase_b_std]

    # =========================================================================
    # PHASE C: After device ID read (RCM handshake initiated)
    # =========================================================================
    print(f"\n\nPHASE C: After device ID read (RCM handshake started)",
          file=sys.stderr)
    print("-" * 55, file=sys.stderr)

    try:
        raw_id = bytes(dev.read(rcm.EP_IN, rcm.DEVICE_ID_LENGTH, timeout=2000))
        print(f"  Device ID: {raw_id.hex()}", file=sys.stderr)
    except usb.core.USBError as exc:
        print(f"  Device ID read failed: {exc}", file=sys.stderr)
        raw_id = None

    phase_c_std = _probe_standard(dev, "C:post_handshake")
    all_results["phase_c_standard"] = [r.to_dict() for r in phase_c_std]

    # Vendor sweep in post-handshake state
    phase_c_vendor = _probe_vendor_sweep(dev, "C:post_handshake")
    all_results["phase_c_vendor_sweep"] = [r.to_dict() for r in phase_c_vendor]

    # GET_STATUS lengths post-handshake
    phase_c_lengths = _probe_get_status_lengths(dev, "C:post_handshake")
    all_results["phase_c_get_status_lengths"] = [r.to_dict() for r in phase_c_lengths]

    # =========================================================================
    # Summary
    # =========================================================================
    print(f"\n{'=' * 55}", file=sys.stderr)
    print("SUMMARY BY PHASE", file=sys.stderr)
    for phase_name, key in [
        ("A (pre-config)", "phase_a_standard"),
        ("B (post-config)", "phase_b_standard"),
        ("C (post-handshake)", "phase_c_standard"),
    ]:
        items = all_results.get(key, [])
        responses = sum(1 for r in items if r["outcome"] == "response")
        stalls = sum(1 for r in items if r["outcome"] == "stall")
        timeouts = sum(1 for r in items if r["outcome"] == "timeout")
        errors = sum(1 for r in items if r["outcome"] == "error")
        print(f"  {phase_name}: {responses} responses, {stalls} stalls, "
              f"{timeouts} timeouts, {errors} errors", file=sys.stderr)

    for phase_name, key in [
        ("A (pre-config)", "phase_a_vendor_sweep"),
        ("C (post-handshake)", "phase_c_vendor_sweep"),
    ]:
        items = all_results.get(key, [])
        responses = sum(1 for r in items if r["outcome"] == "response")
        if responses > 0:
            print(f"\n  *** {phase_name} vendor sweep: {responses} RESPONSES ***",
                  file=sys.stderr)

    usb.util.dispose_resources(dev)
    _save(all_results, out_path)
    return 0


def _save(results: dict, out_path: str | None):
    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(results, indent=2) + "\n")
        print(f"\nResults saved to {p}", file=sys.stderr)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Probe Tegra X1 bootROM USB control surface at each protocol state")
    parser.add_argument("--out", default="findings/probe_results.json",
                        help="Output JSON path")
    args = parser.parse_args()
    raise SystemExit(run_probe(args.out))


if __name__ == "__main__":
    main()
