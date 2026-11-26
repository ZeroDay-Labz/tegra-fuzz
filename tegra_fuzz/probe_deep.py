"""Deep-dive probe: fine-grained GET_STATUS over-read analysis.

Runs against a fresh RCM session to:
1. Fine-grained wLength sweep (1–512) to find exact over-read boundary
2. Capture full over-read data at key sizes
3. Send some bulk OUT data, then re-read to see if IRAM contents change
4. Compare data consistency across repeated reads

Usage:
    sudo python -m tegra_fuzz.probe_deep [--out findings/probe_deep.json]
"""
from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

from . import rcm


def _ctrl(dev, bmrt, breq, wval, widx, wlen, timeout_ms=500):
    import usb.core
    t0 = time.monotonic()
    try:
        ret = dev.ctrl_transfer(bmrt, breq, wval, widx, wlen, timeout_ms)
        elapsed = (time.monotonic() - t0) * 1000
        data = bytes(ret) if ret is not None and not isinstance(ret, int) else b""
        return "response", data, round(elapsed, 2)
    except usb.core.USBTimeoutError:
        elapsed = (time.monotonic() - t0) * 1000
        return "timeout", b"", round(elapsed, 2)
    except usb.core.USBError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        errno = getattr(exc, "errno", None)
        if errno == 32:
            return "stall", b"", round(elapsed, 2)
        if errno in (19, 6):
            return "no_device", b"", round(elapsed, 2)
        return "error", b"", round(elapsed, 2)


def run(out_path: str | None = None) -> int:
    import usb.core
    import usb.util

    dev = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    if dev is None:
        print("error: Tegra APX device not found.", file=sys.stderr)
        return 2

    print(f"Device: bus {dev.bus}, addr {dev.address}", file=sys.stderr)
    print(file=sys.stderr)

    results: dict = {"device": {"bus": dev.bus, "address": dev.address,
                                 "pid": f"0x{dev.idProduct:04X}"}}

    # =================================================================
    # TEST 1: Fine-grained wLength sweep on GET_STATUS EP 0x81
    # Find exact boundary where over-read stops
    # =================================================================
    print("TEST 1: Fine-grained wLength sweep (GET_STATUS EP 0x81)", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    sweep = []
    last_responding = 0
    for wlen in list(range(0, 260, 1)) + [512, 1024, 2048, 4096]:
        o, d, ms = _ctrl(dev, 0x82, 0x00, 0x0000, rcm.EP_IN, wlen, timeout_ms=300)
        sweep.append({"wLength": wlen, "outcome": o, "response_len": len(d),
                       "response_hex": d.hex(), "elapsed_ms": ms})
        if len(d) > 0:
            last_responding = wlen
        if wlen <= 10 or len(d) != wlen or len(d) == 0 or wlen in (128, 129, 255, 256, 512):
            marker = ""
            if len(d) > 2:
                marker = " *** OVER-READ"
            if len(d) == 0 and wlen > 2:
                marker = " (empty)"
            print(f"  wLen={wlen:4d} (0x{wlen:04X}): {o:8s} {len(d):4d}B {ms:6.1f}ms{marker}",
                  file=sys.stderr)

    print(f"\n  Last wLength with data: {last_responding}", file=sys.stderr)
    results["fine_sweep"] = sweep

    # =================================================================
    # TEST 2: Capture max over-read data and check consistency
    # Read 128 bytes 5 times — does the data change between reads?
    # =================================================================
    print(f"\nTEST 2: Consistency check — 5 reads at wLength=128", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    reads_128 = []
    for i in range(5):
        o, d, ms = _ctrl(dev, 0x82, 0x00, 0x0000, rcm.EP_IN, 128)
        reads_128.append(d.hex())
        print(f"  Read {i+1}: {len(d)}B, {ms:.1f}ms", file=sys.stderr)

    all_same = all(r == reads_128[0] for r in reads_128)
    print(f"  All identical: {all_same}", file=sys.stderr)
    if not all_same:
        for i, r in enumerate(reads_128):
            if r != reads_128[0]:
                print(f"  Read {i+1} differs!", file=sys.stderr)
                # Find first differing byte
                for j in range(min(len(r), len(reads_128[0])) // 2):
                    if r[j*2:j*2+2] != reads_128[0][j*2:j*2+2]:
                        print(f"    First diff at byte {j}", file=sys.stderr)
                        break
    results["consistency_128"] = {"reads": reads_128, "all_identical": all_same}

    # =================================================================
    # TEST 3: Over-read on other endpoints and recipients
    # Does GET_STATUS over-read work on device/interface too?
    # =================================================================
    print(f"\nTEST 3: GET_STATUS over-read on other recipients", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    other_targets = [
        (0x80, 0x0000, "device"),        # GET_STATUS device
        (0x81, 0x0000, "interface 0"),    # GET_STATUS interface
        (0x82, rcm.EP_OUT, "EP OUT 0x01"), # GET_STATUS on bulk OUT endpoint
    ]
    other_overreads = {}
    for bmrt, widx, label in other_targets:
        o, d, ms = _ctrl(dev, bmrt, 0x00, 0x0000, widx, 128)
        other_overreads[label] = {"outcome": o, "response_len": len(d),
                                   "response_hex": d.hex()}
        over = " *** OVER-READ" if len(d) > 2 else ""
        print(f"  {label}: {o} {len(d)}B{over}", file=sys.stderr)
        if len(d) > 2:
            # Show the first few 32-bit values
            for off in range(0, min(len(d), 32), 4):
                val = struct.unpack_from('<I', d, off)[0]
                print(f"    [{off:3d}] 0x{val:08X}", file=sys.stderr)
    results["other_recipients"] = other_overreads

    # =================================================================
    # TEST 4: GET_DESCRIPTOR over-reads
    # Can we get more than the descriptor by asking for more?
    # =================================================================
    print(f"\nTEST 4: GET_DESCRIPTOR over-read check", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    desc_tests = [
        (0x0100, "DEVICE (18B nominal)"),
        (0x0200, "CONFIG (32B nominal)"),
        (0x0600, "DEVICE_QUALIFIER (10B nominal)"),
    ]
    desc_overreads = {}
    for wval, label in desc_tests:
        for ask_len in [64, 128, 255]:
            o, d, ms = _ctrl(dev, 0x80, 0x06, wval, 0, ask_len)
            key = f"{label} @{ask_len}"
            desc_overreads[key] = {"outcome": o, "response_len": len(d),
                                    "response_hex": d.hex()}
            over = " *** OVER-READ" if len(d) > 32 else ""
            print(f"  {label} wLen={ask_len}: {len(d)}B{over}", file=sys.stderr)
    results["descriptor_overreads"] = desc_overreads

    # =================================================================
    # TEST 5: Send bulk OUT data, then re-read over-read
    # Does the IRAM content (especially 0x40009000 area) change?
    # =================================================================
    print(f"\nTEST 5: Over-read before/after bulk OUT write", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Capture baseline
    o, d_before, ms = _ctrl(dev, 0x82, 0x00, 0x0000, rcm.EP_IN, 128)
    print(f"  Before bulk write: {len(d_before)}B", file=sys.stderr)
    results["before_bulk_write"] = d_before.hex()

    # Claim interface and send some data
    try:
        try:
            if dev.is_kernel_driver_active(rcm.INTERFACE):
                dev.detach_kernel_driver(rcm.INTERFACE)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, rcm.INTERFACE)
        print("  Claimed interface", file=sys.stderr)
    except usb.core.USBError as exc:
        print(f"  Claim: {exc}", file=sys.stderr)

    # Read device ID (required by RCM protocol)
    try:
        dev_id = bytes(dev.read(rcm.EP_IN, rcm.DEVICE_ID_LENGTH, timeout=2000))
        print(f"  Device ID: {dev_id.hex()}", file=sys.stderr)
        results["device_id"] = dev_id.hex()
    except usb.core.USBError as exc:
        print(f"  Device ID read: {exc}", file=sys.stderr)
        dev_id = None

    # Send a recognizable pattern via bulk OUT
    # Use 0xDEADBEEF pattern so we can search for it in the over-read
    pattern = b"\xDE\xAD\xBE\xEF" * 256  # 1024 bytes
    try:
        written = dev.write(rcm.EP_OUT, pattern, timeout=1000)
        print(f"  Wrote {written}B pattern to bulk OUT", file=sys.stderr)
    except usb.core.USBError as exc:
        print(f"  Bulk write: {exc}", file=sys.stderr)
        written = 0

    # Small delay for DMA to complete
    time.sleep(0.01)

    # Re-read over-read
    o, d_after, ms = _ctrl(dev, 0x82, 0x00, 0x0000, rcm.EP_IN, 128)
    print(f"  After bulk write: {o} {len(d_after)}B", file=sys.stderr)
    results["after_bulk_write"] = d_after.hex() if d_after else ""

    if d_before and d_after:
        if d_before == d_after:
            print("  Data UNCHANGED after bulk write", file=sys.stderr)
        else:
            print("  Data CHANGED after bulk write!", file=sys.stderr)
            for off in range(0, min(len(d_before), len(d_after)), 4):
                v1 = struct.unpack_from('<I', d_before, off)[0] if off + 4 <= len(d_before) else 0
                v2 = struct.unpack_from('<I', d_after, off)[0] if off + 4 <= len(d_after) else 0
                if v1 != v2:
                    print(f"    [{off:3d}] 0x{v1:08X} → 0x{v2:08X}", file=sys.stderr)

        # Check if DEADBEEF pattern appears anywhere
        if b"\xDE\xAD\xBE\xEF" in d_after:
            print("  *** DEADBEEF pattern found in over-read! ***", file=sys.stderr)
    elif not d_after:
        print("  EP0 no longer responding after bulk write + handshake", file=sys.stderr)

    usb.util.dispose_resources(dev)

    # Save
    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(results, indent=2) + "\n")
        print(f"\nResults saved to {p}", file=sys.stderr)

    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Deep-dive GET_STATUS over-read analysis")
    parser.add_argument("--out", default="findings/probe_deep.json", help="Output path")
    args = parser.parse_args()
    raise SystemExit(run(args.out))


if __name__ == "__main__":
    main()
