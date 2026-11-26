#!/usr/bin/env python3
"""
DHCP probing against the Switch AP's DHCP server.

The Switch runs its own DHCP server on 192.168.0.1.
This tests DHCP option handling, lease behavior, and
option injection that might affect the Switch's network stack.

Usage:
    1. Connect to the switch_F3DCDB* WiFi AP
    2. Run: sudo python3 -I dhcp_probe.py --iface <wifi-interface>

Evidence saved to ../evidence/dhcp_probe/
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

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "dhcp_probe"
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def random_mac() -> bytes:
    """Generate a random MAC with locally-administered bit set."""
    mac = bytearray(6)
    mac[0] = 0x02  # locally administered, unicast
    for i in range(1, 6):
        mac[i] = random.randint(0, 255)
    return bytes(mac)


def mac_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def build_dhcp_discover(mac: bytes, options: list[tuple[int, bytes]] | None = None,
                        hostname: str = "probe") -> bytes:
    """Build a DHCP DISCOVER packet."""
    xid = random.randint(0, 0xFFFFFFFF)

    # BOOTP header
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)  # op, htype, hlen, hops
    pkt += struct.pack("!I", xid)              # xid
    pkt += struct.pack("!HH", 0, 0)           # secs, flags
    pkt += b"\x00" * 4                         # ciaddr
    pkt += b"\x00" * 4                         # yiaddr
    pkt += b"\x00" * 4                         # siaddr
    pkt += b"\x00" * 4                         # giaddr
    pkt += mac + b"\x00" * 10                  # chaddr (16 bytes)
    pkt += b"\x00" * 64                        # sname
    pkt += b"\x00" * 128                       # file

    # Magic cookie
    pkt += b"\x63\x82\x53\x63"

    # Option 53: DHCP Message Type = DISCOVER
    pkt += bytes([53, 1, 1])

    # Option 61: Client Identifier
    pkt += bytes([61, 7, 1]) + mac

    # Option 12: Hostname
    hostname_bytes = hostname.encode()[:255]
    pkt += bytes([12, len(hostname_bytes)]) + hostname_bytes

    # Option 55: Parameter Request List
    param_list = bytes([1, 2, 3, 6, 15, 26, 28, 42, 121])
    pkt += bytes([55, len(param_list)]) + param_list

    # Additional options
    if options:
        for opt_code, opt_data in options:
            if len(opt_data) <= 255:
                pkt += bytes([opt_code, len(opt_data)]) + opt_data

    # End
    pkt += bytes([255])

    # Pad to minimum 300 bytes
    if len(pkt) < 300:
        pkt += b"\x00" * (300 - len(pkt))

    return pkt, xid


def send_dhcp(iface: str, pkt: bytes, timeout: float = 5) -> bytes | None:
    """Send DHCP packet and wait for response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
    except PermissionError:
        print(f"  ⚠ Need sudo for SO_BINDTODEVICE on {iface}")
        sock.close()
        return None
    sock.settimeout(timeout)
    try:
        sock.bind(("0.0.0.0", DHCP_CLIENT_PORT))
        sock.sendto(pkt, ("255.255.255.255", DHCP_SERVER_PORT))
        try:
            data, addr = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
    finally:
        sock.close()


def parse_dhcp_options(data: bytes) -> dict:
    """Parse DHCP options from response."""
    # Find magic cookie
    cookie_pos = data.find(b"\x63\x82\x53\x63")
    if cookie_pos < 0:
        return {}

    options = {}
    pos = cookie_pos + 4
    while pos < len(data):
        opt = data[pos]
        if opt == 255:  # End
            break
        if opt == 0:  # Pad
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        length = data[pos + 1]
        if pos + 2 + length > len(data):
            break
        value = data[pos + 2:pos + 2 + length]
        options[opt] = value
        pos += 2 + length

    return options


def parse_dhcp_response(data: bytes) -> dict:
    """Parse full DHCP response."""
    if len(data) < 236:
        return {"error": "too short"}

    result = {
        "op": data[0],
        "xid": struct.unpack("!I", data[4:8])[0],
        "yiaddr": socket.inet_ntoa(data[16:20]),
        "siaddr": socket.inet_ntoa(data[20:24]),
    }

    options = parse_dhcp_options(data)
    opt_names = {
        1: "subnet_mask", 3: "router", 6: "dns", 12: "hostname",
        15: "domain", 28: "broadcast", 42: "ntp", 51: "lease_time",
        53: "msg_type", 54: "server_id", 58: "renewal_time",
        59: "rebinding_time",
    }

    for code, value in options.items():
        name = opt_names.get(code, f"opt_{code}")
        if code in (1, 3, 6, 28, 42, 54):
            if len(value) == 4:
                result[name] = socket.inet_ntoa(value)
            else:
                result[name] = value.hex()
        elif code == 51:
            result[name] = struct.unpack("!I", value)[0] if len(value) == 4 else value.hex()
        elif code == 53:
            types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                     5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
            result[name] = types.get(value[0], f"unknown({value[0]})")
        elif code == 12:
            result[name] = value.decode("ascii", errors="replace")
        else:
            result[name] = value.hex()

    return result


def test_basic_discover(iface: str):
    """Normal DHCP DISCOVER to baseline the server."""
    print("\n[1] Basic DHCP DISCOVER")
    mac = random_mac()
    pkt, xid = build_dhcp_discover(mac, hostname="baseline")
    print(f"  MAC: {mac_str(mac)}, XID: 0x{xid:08x}")

    resp = send_dhcp(iface, pkt)
    if resp is None:
        print("  ✗ No response (timeout)")
        return None

    parsed = parse_dhcp_response(resp)
    print(f"  ✓ Response: {parsed.get('msg_type', '?')}")
    print(f"    Offered IP: {parsed.get('yiaddr', '?')}")
    print(f"    Server: {parsed.get('server_id', '?')}")
    print(f"    Subnet: {parsed.get('subnet_mask', '?')}")
    print(f"    Lease: {parsed.get('lease_time', '?')}s")

    save_result("basic_discover", {"mac": mac_str(mac), "xid": xid, "response": parsed})
    return parsed


def test_many_discovers(iface: str, count: int = 10):
    """Exhaust DHCP pool to see limits."""
    print(f"\n[2] DHCP Pool Exhaustion ({count} discovers)")
    results = []
    for i in range(count):
        mac = random_mac()
        pkt, xid = build_dhcp_discover(mac, hostname=f"probe{i:03d}")
        resp = send_dhcp(iface, pkt, timeout=3)
        if resp:
            parsed = parse_dhcp_response(resp)
            ip = parsed.get("yiaddr", "?")
            results.append({"mac": mac_str(mac), "offered_ip": ip})
            print(f"  {i+1:3d}. {mac_str(mac)} → {ip}")
        else:
            results.append({"mac": mac_str(mac), "offered_ip": None})
            print(f"  {i+1:3d}. {mac_str(mac)} → no response")
        time.sleep(0.2)

    unique_ips = set(r["offered_ip"] for r in results if r["offered_ip"])
    print(f"\n  Unique IPs offered: {len(unique_ips)}")
    save_result("pool_exhaustion", {"count": count, "results": results,
                                    "unique_ips": list(unique_ips)})
    return results


def test_oversized_options(iface: str):
    """Test DHCP options with oversized values."""
    print("\n[3] Oversized DHCP Options")
    tests = [
        ("hostname_255", [(12, b"A" * 255)]),
        ("hostname_200", [(12, b"B" * 200)]),
        ("vendor_class_255", [(60, b"C" * 255)]),
        ("client_id_long", [(61, b"\x01" + b"D" * 254)]),
        ("many_params", [(55, bytes(range(1, 256)))]),
        ("user_class_255", [(77, b"E" * 255)]),
    ]
    results = {}
    for name, options in tests:
        mac = random_mac()
        pkt, xid = build_dhcp_discover(mac, options=options, hostname="oversized")
        resp = send_dhcp(iface, pkt, timeout=3)
        if resp:
            parsed = parse_dhcp_response(resp)
            results[name] = {"responded": True, "msg_type": parsed.get("msg_type"),
                             "yiaddr": parsed.get("yiaddr")}
            print(f"  ✓ {name:20s} → {parsed.get('msg_type', '?')} IP={parsed.get('yiaddr', '?')}")
        else:
            results[name] = {"responded": False}
            print(f"  ✗ {name:20s} → no response")
        time.sleep(0.3)

    save_result("oversized_options", results)
    return results


def test_malformed_packets(iface: str):
    """Send malformed DHCP packets."""
    print("\n[4] Malformed DHCP Packets")
    mac = random_mac()
    normal_pkt, _ = build_dhcp_discover(mac)

    tests = {
        "truncated_236": normal_pkt[:236],  # Min BOOTP size, no options
        "truncated_240": normal_pkt[:240],  # Just cookie
        "truncated_100": normal_pkt[:100],  # Way too short
        "wrong_cookie": normal_pkt[:236] + b"\x00\x00\x00\x00" + normal_pkt[240:],
        "wrong_htype": bytes([1, 6, 6, 0]) + normal_pkt[4:],  # htype=6 (IEEE 802)
        "wrong_hlen": bytes([1, 1, 20, 0]) + normal_pkt[4:],  # hlen=20
        "broadcast_flag": normal_pkt[:10] + b"\x80\x00" + normal_pkt[12:],
    }
    results = {}
    for name, pkt in tests.items():
        resp = send_dhcp(iface, pkt, timeout=3)
        if resp:
            parsed = parse_dhcp_response(resp)
            results[name] = {"responded": True, "msg_type": parsed.get("msg_type")}
            print(f"  ✓ {name:20s} → {parsed.get('msg_type', '?')}")
        else:
            results[name] = {"responded": False}
            print(f"  ✗ {name:20s} → no response")
        time.sleep(0.3)

    save_result("malformed_packets", results)
    return results


def save_result(name: str, data):
    path = evidence_dir() / f"{name}.json"
    with open(path, "w") as f:
        json.dump({"test": name, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "results": data}, f, indent=2, default=str)
    print(f"  → saved {path.name}")


def main():
    parser = argparse.ArgumentParser(description="Switch DHCP server probing")
    parser.add_argument("--iface", required=True, help="WiFi interface connected to Switch AP")
    parser.add_argument("--test", choices=["basic", "pool", "oversized", "malformed", "all"],
                        default="all")
    args = parser.parse_args()

    print("Switch DHCP Server Probe")
    print(f"Interface: {args.iface}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("-" * 50)
    print("⚠ Requires sudo for raw socket binding")

    if args.test in ("basic", "all"):
        test_basic_discover(args.iface)
    if args.test in ("pool", "all"):
        test_many_discovers(args.iface)
    if args.test in ("oversized", "all"):
        test_oversized_options(args.iface)
    if args.test in ("malformed", "all"):
        test_malformed_packets(args.iface)

    print("\n" + "=" * 50)
    print("All probes complete. Check evidence/dhcp_probe/")


if __name__ == "__main__":
    main()
