#!/usr/bin/env python3
"""
NM Local AP Test — Test NM's DHCP behavior against a LOCAL AP.

Creates a temporary WiFi AP using hostapd+dnsmasq on a secondary interface,
then tests NM connections at vendor=221,222,223 from the primary interface.
This isolates whether the DHCP boundary issue is in NM or in the Switch.

If NM successfully connects at vendor=222 against a local AP, the bug is
in the Switch (ldn or WiFi driver). If it fails, the bug is in NM.

Requirements:
  - Two WiFi interfaces (one for AP, one for client)
  - hostapd and dnsmasq installed
  - Run as root

Usage:
    sudo python3 -I nm_local_ap_test.py --ap-iface wlp5s0 --client-iface wlp3s0

If you only have ONE WiFi interface, use --single-iface mode:
    sudo python3 -I nm_local_ap_test.py --single-iface wlp5s0

Single-iface mode skips the AP and uses NM's internal client to connect
to any existing AP (you provide --ssid and --psk), capturing the DHCP
exchange to see if NM sends the packet correctly at different vendor sizes.
"""

import subprocess
import time
import os
import signal
import json
import sys
import argparse
import tempfile
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "crash_isolator"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def test_nm_dhcp_capture(iface, ssid, psk, vendor_len, label):
    """Test NM DHCP behavior by capturing the actual packets sent."""
    result = {
        "label": label,
        "vendor_len": vendor_len,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    conn_name = f"nmtest_{label}"
    hostname = "H" * 255
    vendor = "V" * vendor_len
    pcap_path = str(evidence_dir() / f"nm_dhcp_{label}.pcap")

    print(f"\n{'='*60}")
    print(f"NM DHCP Capture: {label} (vendor={vendor_len})")
    print(f"{'='*60}")

    # Cleanup
    run(f"nmcli connection delete {conn_name}", timeout=5)
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)

    # Create connection
    print(f"  Creating NM connection with vendor={vendor_len}...")
    rc, out, err = run(
        f"nmcli connection add type wifi con-name {conn_name} ssid {ssid} "
        f"wifi-sec.key-mgmt wpa-psk wifi-sec.psk {psk} "
        f"ipv4.method auto connection.autoconnect no "
        f"ipv4.dhcp-hostname {hostname}",
        timeout=10)

    if rc != 0:
        print(f"  ERROR: {err}")
        result["error"] = err
        return result

    run(f"nmcli connection modify {conn_name} "
        f"ipv4.dhcp-vendor-class-identifier {vendor}", timeout=5)

    # Start tcpdump BEFORE connecting
    print(f"  Starting packet capture...")
    cap_proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", pcap_path, "-U",
         "port", "67", "or", "port", "68"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1)

    # Connect
    print(f"  Connecting via NM...")
    journal_start = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    rc, out, err = run(f"nmcli connection up {conn_name}", timeout=35)
    elapsed = time.monotonic() - t0

    result["nm_rc"] = rc
    result["nm_elapsed"] = round(elapsed, 2)
    result["nm_out"] = out[:200]
    result["nm_err"] = err[:200]
    print(f"  NM result: rc={rc}, elapsed={elapsed:.1f}s")

    time.sleep(3)

    # Check IP
    rc_ip, out_ip, _ = run(f"ip -4 addr show {iface} | grep inet")
    result["got_ip"] = "inet" in out_ip
    if result["got_ip"]:
        result["ip"] = out_ip.split()[1].split("/")[0]
    print(f"  Got IP: {result['got_ip']}")

    # Stop capture
    cap_proc.send_signal(signal.SIGINT)
    try:
        cap_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cap_proc.kill()
    time.sleep(1)

    # Analyze pcap — count DHCP packets and get sizes
    print(f"  Analyzing capture...")
    rc, out, _ = run(
        f"tcpdump -r {pcap_path} -nn -v 2>/dev/null",
        timeout=10)
    result["pcap_lines"] = out.count("\n") + 1 if out else 0
    result["pcap_summary"] = out[:2000]

    # Count DHCP DISCOVER and REQUEST packets
    discovers = out.lower().count("dhcp discover") if out else 0
    requests_count = out.lower().count("dhcp request") if out else 0
    offers = out.lower().count("dhcp offer") if out else 0
    acks = out.lower().count("dhcp ack") if out else 0
    result["discovers"] = discovers
    result["requests"] = requests_count
    result["offers"] = offers
    result["acks"] = acks
    print(f"  DHCP: {discovers} DISCOVER, {offers} OFFER, {requests_count} REQUEST, {acks} ACK")

    # Get raw packet sizes from pcap
    rc, out, _ = run(
        f"tcpdump -r {pcap_path} -nn 2>/dev/null | grep -i 'bootp\\|dhcp'",
        timeout=10)
    if out:
        for line in out.split("\n")[:5]:
            print(f"    {line}")

    # Get exact DISCOVER packet size
    rc, out, _ = run(
        f"tcpdump -r {pcap_path} -nn -x 2>/dev/null | head -50",
        timeout=10)
    result["raw_hex_preview"] = out[:1000]

    # Journal for DHCP client messages
    rc, out, _ = run(
        f"journalctl --since '{journal_start}' -u NetworkManager "
        f"--no-pager -q 2>/dev/null | grep -i 'dhcp\\|vendor\\|option' | head -20",
        timeout=5)
    result["nm_dhcp_journal"] = out[:1000]
    if out:
        print(f"\n  NM DHCP journal:")
        for line in out.split("\n")[:10]:
            print(f"    {line}")

    # Cleanup
    run(f"nmcli connection delete {conn_name}", timeout=5)
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)

    result["status"] = "OK" if result["got_ip"] else "FAIL"
    print(f"\n  STATUS: {result['status']}")

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="WiFi interface")
    parser.add_argument("--ssid", required=True, help="AP SSID to connect to")
    parser.add_argument("--psk", required=True, help="AP password")
    parser.add_argument("--vendor-sizes", default="221,222,223,255",
                        help="Comma-separated vendor class sizes to test")
    args = parser.parse_args()

    sizes = [int(x) for x in args.vendor_sizes.split(",")]

    print("NM LOCAL AP TEST — DHCP Client Behavior at Different Vendor Sizes")
    print(f"Interface: {args.iface}, SSID: {args.ssid}")
    print(f"Testing vendor sizes: {sizes}")

    results = []
    for size in sizes:
        r = test_nm_dhcp_capture(
            args.iface, args.ssid, args.psk, size,
            f"v{size}"
        )
        results.append(r)
        time.sleep(5)

    # Save
    output = {
        "test": "nm_local_ap_dhcp",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ssid": args.ssid,
        "results": results,
    }
    path = evidence_dir() / "nm_local_ap_results.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {path}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        print(f"  vendor={r['vendor_len']:3d}: {r.get('status','ERROR'):4s} "
              f"| discovers={r.get('discovers','?')} "
              f"| requests={r.get('requests','?')} "
              f"| offers={r.get('offers','?')} "
              f"| acks={r.get('acks','?')}")

    # Key comparison
    print("\n  KEY QUESTION: Does NM send DHCP DISCOVER at vendor=222?")
    for r in results:
        if r["vendor_len"] == 222:
            if r.get("discovers", 0) > 0:
                print("  → YES: NM sends DISCOVER at vendor=222.")
                print("    The crash is in the Switch (ldn/wlan), not NM.")
            else:
                print("  → NO: NM does NOT send DISCOVER at vendor=222.")
                print("    The crash is in NM's DHCP client configuration path.")


if __name__ == "__main__":
    main()
