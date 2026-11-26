#!/usr/bin/env python3
"""
Crash Monitor — Capture WiFi traffic during NM reconnection to Switch AP.

Records a pcap of ALL traffic on the WiFi interface while NM connects
at both vendor=221 (control) and vendor=222 (crash). The pcap shows
exactly what DHCP packets are sent and when the connection fails.

Usage:
    sudo python3 -I crash_monitor.py --iface wlp5s0 --ssid switch_F3DCDB0100S --psk <PSK_FROM_QR>
"""

import subprocess
import time
import os
import signal
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "crash_isolator"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def start_capture(iface, pcap_path):
    """Start tcpdump capture on the interface."""
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", pcap_path, "-U",
         "port", "67", "or", "port", "68", "or", "ether", "proto", "0x888e"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1)
    return proc


def stop_capture(proc):
    """Stop tcpdump capture."""
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def analyze_pcap(pcap_path):
    """Extract DHCP info from pcap."""
    rc, out, _ = run(
        f"tcpdump -r {pcap_path} -vvn 2>/dev/null | head -100",
        timeout=10
    )
    return out


def run_monitor_test(iface, ssid, psk, vendor_len, label):
    """Run one monitored NM connection test."""
    result = {
        "label": label,
        "vendor_len": vendor_len,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    conn_name = f"monitor_{label}"
    hostname = "H" * 255
    vendor = "V" * vendor_len
    pcap_path = str(evidence_dir() / f"capture_{label}.pcap")

    print(f"\n{'='*60}")
    print(f"Monitor Test: {label} (vendor={vendor_len})")
    print(f"{'='*60}")

    # Cleanup old connection
    run(f"nmcli connection delete {conn_name}", timeout=5)
    time.sleep(1)

    # First establish a baseline connection (no vendor class)
    print("  Phase 1: Establish baseline connection...")
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)

    rc, out, err = run(
        f"nmcli device wifi connect {ssid} password {psk} ifname {iface}",
        timeout=30
    )
    if rc != 0:
        print(f"  ERROR: Baseline connection failed: {err}")
        result["error"] = "baseline_failed"
        return result

    time.sleep(3)

    # Check baseline IP
    rc, out, _ = run(f"ip -4 addr show {iface} | grep inet")
    result["baseline_ip"] = out.split()[1].split("/")[0] if "inet" in out else "none"
    print(f"  Baseline IP: {result['baseline_ip']}")

    # Create the test connection with vendor class
    print(f"  Phase 2: Create connection with vendor={vendor_len}...")
    run(f"nmcli connection add type wifi con-name {conn_name} ssid {ssid} "
        f"wifi-sec.key-mgmt wpa-psk wifi-sec.psk {psk} "
        f"ipv4.method auto connection.autoconnect no "
        f"ipv4.dhcp-hostname {hostname}", timeout=10)

    run(f"nmcli connection modify {conn_name} "
        f"ipv4.dhcp-vendor-class-identifier {vendor}", timeout=5)

    # Disconnect baseline
    print("  Phase 3: Disconnect baseline...")
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)

    # Start capture BEFORE reconnection
    print(f"  Phase 4: Starting packet capture → {pcap_path}")
    cap_proc = start_capture(iface, pcap_path)
    time.sleep(1)

    # Also capture journal for NM and wpa_supplicant
    journal_start = datetime.now(timezone.utc).isoformat()

    # Reconnect with test config
    print(f"  Phase 5: Connecting with vendor={vendor_len}...")
    t0 = time.monotonic()
    rc, out, err = run(f"nmcli connection up {conn_name}", timeout=35)
    elapsed = time.monotonic() - t0
    result["nm_rc"] = rc
    result["nm_elapsed"] = round(elapsed, 2)
    result["nm_out"] = out[:200]
    result["nm_err"] = err[:200]
    print(f"  NM result: rc={rc}, elapsed={elapsed:.1f}s")
    if out:
        print(f"  NM stdout: {out[:100]}")
    if err:
        print(f"  NM stderr: {err[:100]}")

    # Wait and check
    time.sleep(3)

    # Check IP
    rc, out, _ = run(f"ip -4 addr show {iface} | grep inet")
    result["post_ip"] = out.split()[1].split("/")[0] if "inet" in out else "none"
    print(f"  Post IP: {result['post_ip']}")

    # Check HTTP
    import http.client
    try:
        c = http.client.HTTPConnection("192.168.0.1", timeout=3)
        c.request("GET", "/data.json")
        r = c.getresponse()
        result["post_http"] = r.status
        c.close()
    except Exception:
        result["post_http"] = 0
    print(f"  Post HTTP: {result['post_http']}")

    # Stop capture
    stop_capture(cap_proc)
    time.sleep(1)

    # Check if AP is still visible
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)
    rc, out, _ = run(f"nmcli -t device wifi list ifname {iface} --rescan yes", timeout=10)
    result["ap_up"] = ssid in out
    print(f"  AP visible: {result['ap_up']}")

    # Analyze pcap
    print(f"\n  Phase 6: Analyzing capture...")
    pcap_analysis = analyze_pcap(pcap_path)
    result["pcap_summary"] = pcap_analysis[:1000]
    if pcap_analysis:
        print(f"  Packets captured:")
        for line in pcap_analysis.split("\n")[:20]:
            print(f"    {line}")
    else:
        print("  NO packets captured")

    # Get pcap stats
    rc, out, _ = run(f"tcpdump -r {pcap_path} -c 0 2>&1 | tail -1", timeout=5)
    result["pcap_stats"] = out
    print(f"  Stats: {out}")

    # Get journal entries
    rc, out, _ = run(
        f"journalctl --since '{journal_start}' -u NetworkManager -u wpa_supplicant "
        f"--no-pager -q 2>/dev/null | head -30",
        timeout=5
    )
    result["journal"] = out[:2000]
    if out:
        print(f"\n  Journal entries:")
        for line in out.split("\n")[:15]:
            print(f"    {line}")

    # Determine status
    if not result["ap_up"]:
        result["status"] = "CRASH"
    elif result["nm_rc"] == 0:
        result["status"] = "OK"
    else:
        result["status"] = f"FAIL_BUT_AP_UP(rc={rc})"

    print(f"\n  STATUS: {result['status']}")

    # Cleanup
    run(f"nmcli connection delete {conn_name}", timeout=5)
    time.sleep(3)

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--psk", required=True)
    args = parser.parse_args()

    print("CRASH MONITOR — Packet Capture During NM Reconnection")
    print(f"Interface: {args.iface}, SSID: {args.ssid}")

    results = []

    # Test 1: Control (vendor=221, should work)
    r = run_monitor_test(args.iface, args.ssid, args.psk, 221, "control_v221")
    results.append(r)

    time.sleep(10)  # Wait for AP to recover if needed

    # Test 2: Crash (vendor=222)
    r = run_monitor_test(args.iface, args.ssid, args.psk, 222, "crash_v222")
    results.append(r)

    # Save results
    output = {
        "test": "crash_monitor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    path = evidence_dir() / "crash_monitor_results.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {path}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        print(f"  {r['label']:25s}: {r.get('status', 'ERROR')} "
              f"(http={r.get('post_http','?')}, ap={r.get('ap_up','?')}, "
              f"elapsed={r.get('nm_elapsed','?')}s)")


if __name__ == "__main__":
    main()
