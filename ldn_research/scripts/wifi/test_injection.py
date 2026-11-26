#!/usr/bin/env -S python3 -u -I
"""Test which injection method works on this hardware.

Tries three approaches in order:
1. Monitor-mode raw TX injection (radiotap)
2. AP-mode raw TX injection (radiotap on __ap interface)
3. P2P-GO nl80211 CMD_FRAME

Run BEFORE the main experiment to determine which method can actually transmit.

Usage:
  sudo python3 -I test_injection.py --iface wlp5s0 --channel 1

NOTE: This will briefly disconnect WiFi. NetworkManager should reconnect after.
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time


def run(cmd, quiet=False):
    if not quiet:
        print(f"    $ {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r


def get_mac(iface):
    r = run(f"cat /sys/class/net/{iface}/address", quiet=True)
    return r.stdout.strip()


def build_test_frame(src_mac, channel):
    """Build a minimal beacon-like frame for TX testing."""
    dst = b"\xff\xff\xff\xff\xff\xff"  # broadcast
    src = bytes.fromhex(src_mac.replace(":", ""))
    bssid = src

    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Action frame
    frame += b"\x00\x00"               # Duration
    frame += dst                        # DA (broadcast)
    frame += src                        # SA
    frame += bssid                     # BSSID
    frame += struct.pack('<H', 0x0000) # Seq

    # Vendor-specific action body (minimal, safe)
    frame += bytes([0x7f])              # category: vendor-specific
    frame += bytes([0x00, 0x22, 0xaa])  # OUI
    frame += bytes([0x04])              # OUI type
    frame += bytes([0x01, 0x00, 0x00])  # minimal payload
    frame += bytes(32)                  # padding

    return bytes(frame)


def test_monitor_mode(iface, channel):
    """Test monitor-mode TX injection."""
    print("\n[1/3] Testing monitor-mode TX injection...")

    mac = get_mac(iface)
    if not mac:
        print("  SKIP: Could not get MAC address")
        return False

    run(f"ip link set {iface} down")
    r = run(f"iw dev {iface} set type monitor")
    if r.returncode != 0:
        print(f"  FAIL: Cannot set monitor mode: {r.stderr.strip()[:100]}")
        run(f"ip link set {iface} up")
        return False

    run(f"ip link set {iface} up")
    run(f"iw dev {iface} set channel {channel}")
    time.sleep(0.5)

    radiotap = bytes([0x00, 0x00, 0x0d, 0x00, 0x00, 0x80, 0x02, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00])
    frame = build_test_frame(mac, channel)
    pkt = radiotap + frame

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((iface, 0))

        sent = 0
        errors = 0
        for _ in range(5):
            try:
                sock.send(pkt)
                sent += 1
            except OSError as e:
                errors += 1
                if errors == 1:
                    print(f"  TX error: {e}")
            time.sleep(0.01)

        sock.close()
        print(f"  Result: {sent}/5 sent, {errors}/5 errors")

        if sent > 0 and errors == 0:
            print("  STATUS: send() succeeded — but iwlwifi may silently drop TX")
            print("  VERDICT: MAYBE (need external monitor to confirm OTA)")
            return "maybe"
        elif errors > 0:
            print("  STATUS: send() returned errors — TX not supported")
            return False
        return sent > 0

    except OSError as e:
        print(f"  FAIL: Socket error: {e}")
        return False
    finally:
        run(f"ip link set {iface} down", quiet=True)
        run(f"iw dev {iface} set type managed", quiet=True)
        run(f"ip link set {iface} up", quiet=True)


def test_ap_mode(iface, channel):
    """Test AP-mode raw TX injection."""
    print("\n[2/3] Testing AP-mode raw TX injection...")

    ap_iface = f"{iface}-test-ap"
    r = run(f"iw dev {iface} interface add {ap_iface} type __ap")
    if r.returncode != 0:
        print(f"  FAIL: Cannot create AP interface: {r.stderr.strip()[:100]}")
        return False

    run(f"ip link set {ap_iface} up")
    run(f"iw dev {ap_iface} set channel {channel}")
    time.sleep(0.5)

    mac = get_mac(ap_iface)
    radiotap = bytes([0x00, 0x00, 0x0d, 0x00, 0x00, 0x80, 0x02, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00])
    frame = build_test_frame(mac, channel)
    pkt = radiotap + frame

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((ap_iface, 0))

        sent = 0
        errors = 0
        for _ in range(5):
            try:
                sock.send(pkt)
                sent += 1
            except OSError as e:
                errors += 1
                if errors == 1:
                    print(f"  TX error: {e}")
            time.sleep(0.01)

        sock.close()
        print(f"  Result: {sent}/5 sent, {errors}/5 errors")

        if sent > 0 and errors == 0:
            print("  STATUS: send() succeeded on AP interface")
            return "maybe"
        return False

    except OSError as e:
        print(f"  FAIL: Socket error: {e}")
        return False
    finally:
        run(f"ip link set {ap_iface} down", quiet=True)
        run(f"iw dev {ap_iface} del", quiet=True)


def test_p2p_go(iface, channel):
    """Test P2P-GO nl80211 CMD_FRAME."""
    print("\n[3/3] Testing P2P-GO CMD_FRAME...")

    try:
        from pyroute2.netlink.nl80211 import NL80211, nl80211cmd
        from pyroute2.netlink import NLM_F_REQUEST, NLM_F_ACK
    except ImportError:
        print("  SKIP: pyroute2 not available (install: pip install pyroute2)")
        return False

    p2p_iface = f"{iface}-test-p2p"
    r = run(f"iw dev {iface} interface add {p2p_iface} type __ap")
    if r.returncode != 0:
        print(f"  FAIL: Cannot create P2P-GO interface")
        return False

    run(f"ip link set {p2p_iface} up")
    run(f"iw dev {p2p_iface} set channel {channel}")
    time.sleep(0.5)

    mac = get_mac(p2p_iface)
    dst = bytes.fromhex("ffffffffffff")
    src = bytes.fromhex(mac.replace(":", ""))

    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Action
    frame += b"\x00\x00"
    frame += dst
    frame += src
    frame += src
    frame += struct.pack('<H', 0x0000)
    frame += bytes([0x7f, 0x00, 0x22, 0xaa, 0x04, 0x01, 0x00, 0x00])
    frame += bytes(24)

    ifindex = int(run(f"cat /sys/class/net/{p2p_iface}/ifindex", quiet=True).stdout.strip())

    try:
        with NL80211() as nl:
            msg = nl80211cmd()
            msg['cmd'] = 55  # NL80211_CMD_FRAME
            msg['version'] = 0
            msg['attrs'] = [
                ('NL80211_ATTR_IFINDEX', ifindex),
                ('NL80211_ATTR_FRAME', bytes(frame)),
            ]
            resp = nl.nlm_request(msg, msg_type=nl.prid, msg_flags=NLM_F_REQUEST | NLM_F_ACK)
            print("  Result: CMD_FRAME succeeded!")
            return True
    except Exception as e:
        err_str = str(e)
        print(f"  Result: CMD_FRAME failed: {err_str[:100]}")
        if "107" in err_str:
            print("  Diagnosis: ENOTCONN — same STA-mode issue even on AP interface")
        return False
    finally:
        run(f"ip link set {p2p_iface} down", quiet=True)
        run(f"iw dev {p2p_iface} del", quiet=True)


def main():
    parser = argparse.ArgumentParser(description="Test WiFi injection capabilities")
    parser.add_argument("--iface", default="wlp5s0")
    parser.add_argument("--channel", type=int, default=1)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root")
        sys.exit(1)

    print(f"Testing injection capabilities on {args.iface}, channel {args.channel}")
    print(f"Interface: {get_mac(args.iface)}")

    # Get driver info
    r = run(f"ethtool -i {args.iface}", quiet=True)
    for line in r.stdout.splitlines():
        if "driver" in line or "firmware" in line:
            print(f"  {line.strip()}")

    results = {}

    results["monitor"] = test_monitor_mode(args.iface, args.channel)
    time.sleep(1)

    results["ap_raw"] = test_ap_mode(args.iface, args.channel)
    time.sleep(1)

    results["p2p_cmd_frame"] = test_p2p_go(args.iface, args.channel)

    # Reconnect
    print("\nReconnecting WiFi...")
    run("nmcli device connect wlp5s0", quiet=True)

    print("\n" + "="*60)
    print("INJECTION CAPABILITY SUMMARY")
    print("="*60)
    for method, result in results.items():
        status = "YES" if result is True else ("MAYBE" if result == "maybe" else "NO")
        print(f"  {method:20s}: {status}")

    working = [k for k, v in results.items() if v is True]
    maybe = [k for k, v in results.items() if v == "maybe"]

    if working:
        print(f"\nRECOMMENDATION: Use {working[0]} method")
    elif maybe:
        print(f"\nRECOMMENDATION: {maybe[0]} might work — need external monitor to confirm")
        print("  iwlwifi send() can succeed even when firmware drops the frame")
    else:
        print("\nRECOMMENDATION: Get a USB WiFi adapter with TX injection support")
        print("  Options: Alfa AWUS036ACH (rtl8812au), Alfa AWUS1900 (rtl8814au)")
        print("  Or: TP-Link TL-WN722N v1 (ath9k_htc)")


if __name__ == "__main__":
    main()
