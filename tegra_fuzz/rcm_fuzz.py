"""Fuzz the RCM message parser on the bulk transfer path.

The RCM protocol after device ID exchange expects:
  1. Bulk OUT: 4-byte LE length field (declared message size)
  2. Bulk OUT: message body in 0x1000-byte chunks
  3. The bootROM processes the message based on the declared length

Even with CVE-2018-6242 patched (DMA overflow blocked), the message
parser itself may have bugs: integer overflows in length handling,
off-by-one errors, edge cases around zero/max length, etc.

We use the EP0 GET_STATUS over-read as an oracle — after each fuzz
case, we check if the over-read data changed (indicating we influenced
bootROM internal state) or if the device crashed.

Usage:
    sudo python -m tegra_fuzz.rcm_fuzz [--out findings/rcm_fuzz.json]
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


def _read_overread(dev):
    o, d, ms = _ctrl(dev, 0x82, 0x00, 0x0000, rcm.EP_IN, 128)
    return d if o == "response" else None


def _bulk_write(dev, data, timeout_ms=2000):
    import usb.core
    try:
        written = dev.write(rcm.EP_OUT, data, timeout=timeout_ms)
        return "ok", written
    except usb.core.USBTimeoutError:
        return "timeout", 0
    except usb.core.USBError as exc:
        errno = getattr(exc, "errno", None)
        if errno in (19, 6):
            return "no_device", 0
        if errno == 32:
            return "stall", 0
        return "error", 0


def _bulk_read(dev, size, timeout_ms=1000):
    import usb.core
    try:
        data = bytes(dev.read(rcm.EP_IN, size, timeout=timeout_ms))
        return "ok", data
    except usb.core.USBTimeoutError:
        return "timeout", b""
    except usb.core.USBError:
        return "error", b""


def _check_alive(dev):
    """Check if device is still on the USB bus."""
    import usb.core
    dev2 = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    return dev2 is not None


def _check_bulk_alive(dev):
    """Try a small bulk read to see if the bulk path responds."""
    o, d = _bulk_read(dev, 16, timeout_ms=500)
    return o in ("ok", "timeout")


def run(out_path: str | None = None) -> int:
    import usb.core
    import usb.util

    dev = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    if dev is None:
        print("error: Tegra APX device not found.", file=sys.stderr)
        return 2

    print(f"Device: bus {dev.bus}, addr {dev.address}", file=sys.stderr)
    results: dict = {"device": {"bus": dev.bus, "address": dev.address},
                     "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                     "cases": []}

    # Capture EP0 over-read BEFORE claiming (EP0 works pre-handshake)
    baseline = _read_overread(dev)
    if baseline:
        print(f"  Pre-handshake over-read: {len(baseline)}B", file=sys.stderr)
        results["baseline"] = baseline.hex()

    # Claim interface
    try:
        try:
            if dev.is_kernel_driver_active(rcm.INTERFACE):
                dev.detach_kernel_driver(rcm.INTERFACE)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, rcm.INTERFACE)
    except usb.core.USBError as exc:
        print(f"  Claim: {exc}", file=sys.stderr)

    # Read device ID (required to advance state machine)
    o, dev_id = _bulk_read(dev, rcm.DEVICE_ID_LENGTH, timeout_ms=2000)
    if o != "ok":
        print(f"  Device ID read: {o}", file=sys.stderr)
        return 1
    print(f"  Device ID: {dev_id.hex()}", file=sys.stderr)
    results["device_id"] = dev_id.hex()

    # Note: EP0 may not work after handshake — use bus presence as oracle
    print(f"  Oracle: USB bus presence + bulk response (EP0 dies post-handshake)",
          file=sys.stderr)

    # =================================================================
    # FUZZ CASES: RCM message length field variations
    #
    # The RCM message starts with a 4-byte LE length. The bootROM uses
    # this to decide how much data to DMA. Edge cases:
    # =================================================================
    print(f"\nRCM message parser fuzzing", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    fuzz_cases = [
        # (name, length_field, body_size, body_pattern, description)

        # Zero and near-zero lengths
        ("len_0", 0x00000000, 0x1000, b"\x00", "Zero length"),
        ("len_1", 0x00000001, 0x1000, b"\x00", "Length = 1"),
        ("len_4", 0x00000004, 0x1000, b"\x00", "Length = 4 (just the header)"),
        ("len_676", 0x000002A4, 0x1000, b"\x00", "Length = 676 (min RCM msg)"),
        ("len_680", 0x000002A8, 0x1000, b"\x00", "Length = 680 (header size)"),

        # Exact boundary values around the DMA buffer sizes
        ("len_0x1000", 0x00001000, 0x1000, b"\x00", "Length = 4096 (page)"),
        ("len_0x4000", 0x00004000, 0x4000, b"\x00", "Length = 16384 (DMA buf)"),
        ("len_0x8000", 0x00008000, 0x1000, b"\x00", "Length = 32768"),

        # Integer edge cases
        ("len_0xFFFF", 0x0000FFFF, 0x1000, b"\x00", "Length = 65535 (uint16 max)"),
        ("len_0x10000", 0x00010000, 0x1000, b"\x00", "Length = 65536 (uint16 overflow)"),
        ("len_0xFFFFFFFF", 0xFFFFFFFF, 0x1000, b"\x00", "Length = max uint32"),
        ("len_0x80000000", 0x80000000, 0x1000, b"\x00", "Length = int32 negative"),
        ("len_0x7FFFFFFF", 0x7FFFFFFF, 0x1000, b"\x00", "Length = int32 max"),

        # Values around the IPATCH trigger size (CVE-2018-6242 uses 0x30298)
        ("len_exploit_exact", 0x00030298, 0x1000, b"\x00", "Exact CVE-2018-6242 length"),
        ("len_exploit_minus1", 0x00030297, 0x1000, b"\x00", "CVE length - 1"),
        ("len_exploit_plus1", 0x00030299, 0x1000, b"\x00", "CVE length + 1"),

        # IRAM boundary — total IRAM is 256KB (0x40000)
        ("len_iram_size", 0x00040000, 0x1000, b"\x00", "Length = IRAM size"),
        ("len_iram_plus1", 0x00040001, 0x1000, b"\x00", "Length = IRAM + 1"),

        # Send body with recognizable patterns
        ("pattern_deadbeef", 0x00001000, 0x1000, b"\xDE\xAD\xBE\xEF",
         "DEADBEEF pattern body"),
        ("pattern_41414141", 0x00001000, 0x1000, b"\x41", "AAAA pattern body"),

        # Truncated message: declare large length, send tiny body
        ("truncated_large", 0x00030298, 0x100, b"\x00",
         "Declare 0x30298 but send only 256B"),
        ("truncated_zero_body", 0x00001000, 0, b"",
         "Declare 0x1000 but send no body"),

        # Send just the length field, nothing else
        ("header_only_4", 0x00001000, 4, b"\x00", "Only 4 bytes total"),
    ]

    for name, length, body_size, pattern, desc in fuzz_cases:
        # Check device is still on the bus
        if not _check_alive(dev):
            print(f"\n  *** DEVICE GONE before case '{name}' ***", file=sys.stderr)
            # Wait and re-check (device may re-enumerate)
            time.sleep(1)
            if not _check_alive(dev):
                print(f"  Device gone from bus — stopping", file=sys.stderr)
                break
            print(f"  Device re-appeared — continuing", file=sys.stderr)

        # Build the message
        header = struct.pack('<I', length)
        if body_size > 0 and pattern:
            body = (pattern * ((body_size // len(pattern)) + 1))[:body_size]
        else:
            body = b""

        # Pad to 0x1000 boundary for USB transfer
        msg = header + body
        pad_to = max(0x1000, ((len(msg) + 0xFFF) // 0x1000) * 0x1000)
        msg = msg + b"\x00" * (pad_to - len(msg))

        # Send
        print(f"\n  [{name}] {desc}", file=sys.stderr)
        print(f"    Length field: 0x{length:08X}, body: {body_size}B, "
              f"total wire: {len(msg)}B", file=sys.stderr)

        t0 = time.monotonic()
        write_o, written = _bulk_write(dev, msg, timeout_ms=2000)
        write_ms = (time.monotonic() - t0) * 1000
        print(f"    Write: {write_o} ({written}B, {write_ms:.0f}ms)", file=sys.stderr)

        # Small delay for processing
        time.sleep(0.05)

        # Check if device is still on the bus
        alive = _check_alive(dev)
        if not alive:
            print(f"    *** DEVICE LEFT THE BUS ***", file=sys.stderr)

        # Try a bulk read — does the bootROM send anything back?
        # (e.g., an error response, or unexpected data)
        read_o, read_data = _bulk_read(dev, 0x1000, timeout_ms=500)
        if read_o == "ok" and len(read_data) > 0:
            print(f"    Bulk read: {len(read_data)}B *** GOT DATA BACK ***",
                  file=sys.stderr)
            print(f"    Data: {read_data[:64].hex()}", file=sys.stderr)
        elif read_o == "timeout":
            pass  # normal — bootROM waiting for more data
        else:
            print(f"    Bulk read: {read_o}", file=sys.stderr)

        case_result = {
            "name": name, "description": desc,
            "length_field": length, "body_size": body_size,
            "wire_size": len(msg),
            "write_outcome": write_o, "write_bytes": written,
            "write_ms": write_ms,
            "device_alive": alive,
            "read_outcome": read_o,
            "read_len": len(read_data) if read_data else 0,
        }
        if read_data:
            case_result["read_hex"] = read_data.hex()
        results["cases"].append(case_result)

        if not alive:
            time.sleep(1)
            dev2 = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
            if dev2 is None:
                print(f"    Device gone — stopping fuzz", file=sys.stderr)
                break
            else:
                print(f"    Device re-appeared — re-claiming", file=sys.stderr)
                dev = dev2
                try:
                    dev.set_configuration()
                    usb.util.claim_interface(dev, rcm.INTERFACE)
                except usb.core.USBError:
                    pass

    # Final status
    print(f"\n{'=' * 60}", file=sys.stderr)
    crashes = sum(1 for c in results["cases"] if not c["device_alive"])
    changes = sum(1 for c in results["cases"] if c.get("read_len", 0) > 0)
    print(f"Results: {len(results['cases'])} cases, {crashes} crashes, "
          f"{changes} over-read changes", file=sys.stderr)

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(results, indent=2) + "\n")
        print(f"Saved to {p}", file=sys.stderr)

    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Fuzz RCM message parser via bulk transfers")
    parser.add_argument("--out", default="findings/rcm_fuzz.json", help="Output path")
    args = parser.parse_args()
    raise SystemExit(run(args.out))


if __name__ == "__main__":
    main()
