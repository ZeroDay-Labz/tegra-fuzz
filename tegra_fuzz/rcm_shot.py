"""Single-shot RCM message probe — one test per RCM session.

The bootROM stalls the bulk endpoint after the first message exchange,
so we get exactly ONE shot per RCM boot. This tool sends one carefully
crafted message and captures the full response.

Usage:
    sudo python -m tegra_fuzz.rcm_shot <case> [--out findings/rcm_shot_<case>.json]

Cases:
    len0_read64     — Send len=0 body, read back up to 64 bytes
    len0_read4096   — Send len=0 body, read back up to 4096 bytes
    len0_nobody     — Send ONLY the 4-byte len=0 header (no padding)
    len0_tiny       — Send len=0 + 4 bytes of body only
    len0_then_write — Send len=0, read response, try writing again
    len8            — Send len=8 (the response value we got back)
    len0_pattern    — Send len=0 with DEADBEEF body, check response
    raw_read        — Skip write, just try to read (what does bootROM send first?)
    multi_read      — Send len=0, then do multiple reads
"""
from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

from . import rcm


def _bulk_write(dev, data, timeout_ms=5000):
    import usb.core
    try:
        written = dev.write(rcm.EP_OUT, data, timeout=timeout_ms)
        return "ok", written
    except usb.core.USBTimeoutError:
        return "timeout", 0
    except usb.core.USBError as exc:
        errno = getattr(exc, "errno", None)
        if errno == 32:
            return "stall", 0
        if errno in (19, 6):
            return "no_device", 0
        return "error", 0


def _bulk_read(dev, size, timeout_ms=2000):
    import usb.core
    try:
        data = bytes(dev.read(rcm.EP_IN, size, timeout=timeout_ms))
        return "ok", data
    except usb.core.USBTimeoutError:
        return "timeout", b""
    except usb.core.USBError as exc:
        errno = getattr(exc, "errno", None)
        if errno == 32:
            return "stall", 0
        if errno in (19, 6):
            return "no_device", b""
        return "error", b""


def _ctrl_read(dev, wlen=128):
    import usb.core
    try:
        ret = dev.ctrl_transfer(0x82, 0x00, 0, rcm.EP_IN, wlen, 500)
        return bytes(ret)
    except usb.core.USBError:
        return None


def _setup(dev):
    import usb.core
    import usb.util
    try:
        if dev.is_kernel_driver_active(rcm.INTERFACE):
            dev.detach_kernel_driver(rcm.INTERFACE)
    except (NotImplementedError, usb.core.USBError):
        pass
    try:
        dev.set_configuration()
        usb.util.claim_interface(dev, rcm.INTERFACE)
    except usb.core.USBError:
        pass

    o, dev_id = _bulk_read(dev, rcm.DEVICE_ID_LENGTH, timeout_ms=2000)
    if o == "ok":
        print(f"  Device ID: {dev_id.hex()}", file=sys.stderr)
        return dev_id
    else:
        print(f"  Device ID: {o}", file=sys.stderr)
        return None


def run_case(case: str, out_path: str | None = None) -> int:
    import usb.core

    dev = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    if dev is None:
        print("error: device not found", file=sys.stderr)
        return 2

    print(f"Device: bus {dev.bus}, addr {dev.address}", file=sys.stderr)
    results = {"case": case, "device": {"bus": dev.bus, "address": dev.address},
               "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}

    # Pre-handshake EP0 over-read
    ep0_pre = _ctrl_read(dev, 128)
    if ep0_pre:
        results["ep0_pre_handshake"] = ep0_pre.hex()

    dev_id = _setup(dev)
    if not dev_id:
        return 1
    results["device_id"] = dev_id.hex()

    print(f"\n  Case: {case}", file=sys.stderr)
    print(f"  {'=' * 50}", file=sys.stderr)

    if case == "len0_read64":
        msg = struct.pack('<I', 0) + b"\x00" * 0xFFC
        o, w = _bulk_write(dev, msg)
        print(f"  Write: {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read 64: {o} ({len(d)}B)", file=sys.stderr)
        if d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "len0_read4096":
        msg = struct.pack('<I', 0) + b"\x00" * 0xFFC
        o, w = _bulk_write(dev, msg)
        print(f"  Write: {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 4096, timeout_ms=3000)
        print(f"  Read 4096: {o} ({len(d) if isinstance(d, bytes) else 0}B)", file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "len0_nobody":
        msg = struct.pack('<I', 0)
        o, w = _bulk_write(dev, msg)
        print(f"  Write (4B only): {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read: {o} ({len(d) if isinstance(d, bytes) else 0}B)", file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "len0_tiny":
        msg = struct.pack('<I', 0) + b"\xAA\xBB\xCC\xDD"
        o, w = _bulk_write(dev, msg)
        print(f"  Write (8B): {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read: {o} ({len(d) if isinstance(d, bytes) else 0}B)", file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "len0_then_write":
        msg = struct.pack('<I', 0) + b"\x00" * 0xFFC
        o, w = _bulk_write(dev, msg)
        print(f"  Write 1 (len=0): {o} ({w}B)", file=sys.stderr)
        results["write1"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read: {o} ({len(d) if isinstance(d, bytes) else 0}B)", file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read1"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        # Try writing again
        msg2 = struct.pack('<I', 0x1000) + b"\x41" * 0xFFC
        o2, w2 = _bulk_write(dev, msg2)
        print(f"  Write 2 (len=0x1000): {o2} ({w2}B)", file=sys.stderr)
        results["write2"] = {"outcome": o2, "bytes": w2}
        if o2 == "ok":
            o3, d3 = _bulk_read(dev, 64, timeout_ms=3000)
            print(f"  Read 2: {o3} ({len(d3) if isinstance(d3, bytes) else 0}B)",
                  file=sys.stderr)
            if isinstance(d3, bytes) and d3:
                print(f"  Data: {d3.hex()}", file=sys.stderr)

    elif case == "len8":
        msg = struct.pack('<I', 8) + b"\x00" * 0xFFC
        o, w = _bulk_write(dev, msg)
        print(f"  Write (len=8): {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read: {o} ({len(d) if isinstance(d, bytes) else 0}B)", file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "len0_pattern":
        msg = struct.pack('<I', 0) + (b"\xDE\xAD\xBE\xEF" * 0x3FF)
        o, w = _bulk_write(dev, msg)
        print(f"  Write (len=0 + DEADBEEF): {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read: {o} ({len(d) if isinstance(d, bytes) else 0}B)", file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "raw_read":
        # Don't write anything — just try reading
        o, d = _bulk_read(dev, 64, timeout_ms=3000)
        print(f"  Read (no write): {o} ({len(d) if isinstance(d, bytes) else 0}B)",
              file=sys.stderr)
        if isinstance(d, bytes) and d:
            print(f"  Data: {d.hex()}", file=sys.stderr)
            results["read"] = {"outcome": o, "length": len(d), "hex": d.hex()}
        else:
            results["read"] = {"outcome": o, "length": 0}

    elif case == "multi_read":
        msg = struct.pack('<I', 0) + b"\x00" * 0xFFC
        o, w = _bulk_write(dev, msg)
        print(f"  Write: {o} ({w}B)", file=sys.stderr)
        results["write"] = {"outcome": o, "bytes": w}
        reads = []
        for i in range(5):
            o, d = _bulk_read(dev, 4096, timeout_ms=2000)
            rlen = len(d) if isinstance(d, bytes) else 0
            print(f"  Read {i}: {o} ({rlen}B)", file=sys.stderr)
            entry = {"outcome": o, "length": rlen}
            if isinstance(d, bytes) and d:
                print(f"    Data: {d[:64].hex()}", file=sys.stderr)
                entry["hex"] = d.hex()
            reads.append(entry)
            if o in ("stall", "no_device", "error"):
                break
        results["reads"] = reads

    else:
        print(f"  Unknown case: {case}", file=sys.stderr)
        return 1

    # Post-test: check EP0 and bus presence
    ep0_post = _ctrl_read(dev, 128)
    results["ep0_post"] = ep0_post.hex() if ep0_post else "none"
    dev2 = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    results["device_alive"] = dev2 is not None
    print(f"\n  EP0 post: {'alive' if ep0_post else 'dead'}", file=sys.stderr)
    print(f"  Bus: {'present' if dev2 else 'GONE'}", file=sys.stderr)

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(results, indent=2) + "\n")
        print(f"  Saved to {p}", file=sys.stderr)

    return 0


def main():
    import argparse
    p = argparse.ArgumentParser(description="Single-shot RCM message probe")
    p.add_argument("case", help="Test case name")
    p.add_argument("--out", help="Output JSON path")
    args = p.parse_args()
    out = args.out or f"findings/rcm_shot_{args.case}.json"
    raise SystemExit(run_case(args.case, out))


if __name__ == "__main__":
    main()
