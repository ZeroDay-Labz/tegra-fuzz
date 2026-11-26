"""Scan EP0 with varied wValue and wIndex to find different memory windows.

We know GET_STATUS with standard wIndex values all return the same 255B.
This scanner tries unusual combinations to discover alternate windows:
- High endpoint indices (0x83-0x8F, 0x03-0x0F)
- Non-zero wValue in GET_STATUS
- GET_DESCRIPTOR with various descriptor types
- Vendor-specific requests (bmRequestType 0xC0/0xC1/0xC2)
- Class-specific requests

Pre-handshake only: does NOT consume the RCM session.

Usage:
    sudo python -m tegra_fuzz.ep0_window_scan
"""
import struct, sys, json, os
import usb.core

VID, PID = 0x0955, 0x7321
FORBIDDEN = {(0x00, 0x05)}

BASELINE_HASH = None


def try_read(dev, bmrt, breq, wval, widx, wlen=255, timeout=500):
    if (bmrt & 0x7F, breq) in FORBIDDEN:
        return None
    try:
        data = bytes(dev.ctrl_transfer(bmrt, breq, wval, widx, wlen, timeout))
        return data
    except usb.core.USBTimeoutError:
        return "TIMEOUT"
    except usb.core.USBError as e:
        errno = getattr(e, 'errno', None)
        if errno == 32:
            return "STALL"
        return f"ERR:{errno}"


def data_hash(data):
    if not isinstance(data, bytes):
        return data
    return hash(data)


def summarize(data, baseline_data):
    if not isinstance(data, bytes):
        return data
    if baseline_data and isinstance(baseline_data, bytes) and data == baseline_data:
        return f"SAME({len(data)}B)"
    nonzero = sum(1 for b in data if b != 0)
    if nonzero == 0:
        return f"ZEROS({len(data)}B)"
    # Check how many bytes differ from baseline
    if baseline_data and isinstance(baseline_data, bytes):
        diffs = sum(1 for a, b in zip(data, baseline_data) if a != b)
        if diffs <= 8:
            diff_offsets = [i for i, (a, b) in enumerate(zip(data, baseline_data)) if a != b]
            return f"NEAR({len(data)}B diffs={diffs} at {diff_offsets})"
    return f"NEW({len(data)}B nz={nonzero})"


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device"); return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # Get baseline (standard GET_STATUS on EP1_IN)
    baseline = try_read(dev, 0x82, 0x00, 0, 0x81)
    if isinstance(baseline, bytes):
        print(f"baseline: {len(baseline)}B nonzero={sum(1 for b in baseline if b != 0)}", flush=True)
    else:
        print(f"baseline: {baseline}", flush=True)
        baseline = None

    results = {}

    # === 1. GET_STATUS with high endpoint indices ===
    print("\n=== GET_STATUS high endpoints ===", flush=True)
    for ep in range(0x82, 0x90):
        d = try_read(dev, 0x82, 0x00, 0, ep)
        s = summarize(d, baseline)
        if s != f"SAME({len(baseline)}B)" if baseline else True:
            print(f"  ep=0x{ep:02X}: {s}", flush=True)
        results[f"status_ep_0x{ep:02X}"] = s
    for ep in range(0x02, 0x10):
        d = try_read(dev, 0x82, 0x00, 0, ep)
        s = summarize(d, baseline)
        if s != f"SAME({len(baseline)}B)" if baseline else True:
            print(f"  ep=0x{ep:02X}: {s}", flush=True)
        results[f"status_ep_0x{ep:02X}"] = s

    # === 2. GET_STATUS with non-zero wValue ===
    print("\n=== GET_STATUS varied wValue ===", flush=True)
    for wval in [1, 2, 0xFF, 0x100, 0x1000, 0xFFFF]:
        d = try_read(dev, 0x82, 0x00, wval, 0x81)
        s = summarize(d, baseline)
        if s != f"SAME({len(baseline)}B)" if baseline else True:
            print(f"  wval=0x{wval:04X}: {s}", flush=True)
        results[f"status_wval_0x{wval:04X}"] = s

    # === 3. GET_DESCRIPTOR with various types ===
    print("\n=== GET_DESCRIPTOR types ===", flush=True)
    desc_types = [
        (0x0100, "device"),
        (0x0200, "config"),
        (0x0300, "string0"),
        (0x0301, "string1"),
        (0x0302, "string2"),
        (0x0303, "string3"),
        (0x0600, "device_qualifier"),
        (0x0700, "other_speed"),
        (0x0F00, "BOS"),
    ]
    for wval, label in desc_types:
        d = try_read(dev, 0x80, 0x06, wval, 0)
        s = summarize(d, baseline)
        print(f"  {label:20s} (0x{wval:04X}): {s}", flush=True)
        if isinstance(d, bytes) and len(d) > 0:
            print(f"    {d[:32].hex()}", flush=True)
        results[f"desc_{label}"] = s

    # === 4. Vendor-specific requests ===
    print("\n=== Vendor requests ===", flush=True)
    for bmrt in [0xC0, 0xC1, 0xC2]:
        for breq in range(0, 16):
            d = try_read(dev, bmrt, breq, 0, 0, timeout=300)
            if isinstance(d, bytes) and len(d) > 0:
                s = summarize(d, baseline)
                print(f"  bmrt=0x{bmrt:02X} breq=0x{breq:02X}: {s}", flush=True)
                print(f"    {d[:32].hex()}", flush=True)
                results[f"vendor_{bmrt:02X}_{breq:02X}"] = s

    # === 5. Class-specific requests ===
    print("\n=== Class requests ===", flush=True)
    for bmrt in [0xA0, 0xA1, 0xA2]:
        for breq in range(0, 8):
            d = try_read(dev, bmrt, breq, 0, 0, timeout=300)
            if isinstance(d, bytes) and len(d) > 0:
                s = summarize(d, baseline)
                print(f"  bmrt=0x{bmrt:02X} breq=0x{breq:02X}: {s}", flush=True)
                results[f"class_{bmrt:02X}_{breq:02X}"] = s

    # === 6. Standard requests with endpoint recipient (0x82) but different bRequest ===
    print("\n=== Endpoint-recipient varied bRequest ===", flush=True)
    for breq in range(0, 16):
        if breq == 5:
            continue  # FORBIDDEN SET_ADDRESS
        d = try_read(dev, 0x82, breq, 0, 0x81, timeout=300)
        s = summarize(d, baseline)
        if isinstance(d, bytes) and len(d) > 0 and s != f"SAME({len(baseline)}B)":
            print(f"  breq=0x{breq:02X}: {s}", flush=True)
            if isinstance(d, bytes):
                print(f"    {d[:32].hex()}", flush=True)
        results[f"ep_breq_0x{breq:02X}"] = s

    # === 7. Try reading with different wLength values ===
    print("\n=== Varied wLength ===", flush=True)
    for wlen in [1, 2, 4, 8, 16, 64, 128, 254, 255]:
        d = try_read(dev, 0x82, 0x00, 0, 0x81, wlen=wlen)
        if isinstance(d, bytes):
            # Check if truncated baseline or different data
            if baseline and d == baseline[:len(d)]:
                pass  # expected truncation
            else:
                print(f"  wlen={wlen}: {len(d)}B DIFFERENT from truncated baseline!", flush=True)
                print(f"    {d[:32].hex()}", flush=True)

    # Device still alive?
    alive = usb.core.find(idVendor=VID, idProduct=PID) is not None
    print(f"\nalive={alive}", flush=True)

    outfile = "findings/ep0_window_scan.json"
    os.makedirs("findings", exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Saved {len(results)} results to {outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
