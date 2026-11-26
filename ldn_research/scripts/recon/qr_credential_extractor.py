#!/usr/bin/env python3
"""
QR code credential extractor for Switch "Send to Smartphone" flow.

The Switch displays a QR code containing WiFi connection credentials
(SSID + WPA2-PSK passphrase). Analyzing the QR format may reveal:
  - PSK generation algorithm (is it static? derived from console serial?)
  - Any additional protocol metadata embedded
  - Whether the PSK rotates per session

This tool decodes a captured QR code image and extracts credentials.
If a screenshot of the QR code exists, it can extract the WiFi password
needed for direct AP connection during fuzzing.

Usage:
    python3 -I qr_credential_extractor.py <qr_image.png>
    python3 -I qr_credential_extractor.py --analyze-psk  # analyze known PSK patterns
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "qr_analysis"

KNOWN_SSID = "switch_F3DCDB0100S"
KNOWN_BSSID = "EC:C4:0D:F3:DC:DB"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def decode_qr(image_path):
    """Decode a QR code from an image file."""
    try:
        from pyzbar import pyzbar
        from PIL import Image
    except ImportError:
        print("Install dependencies: pip install pyzbar Pillow")
        print("Also need system package: sudo dnf install zbar")
        sys.exit(1)

    img = Image.open(image_path)
    decoded = pyzbar.decode(img)
    if not decoded:
        print(f"No QR code found in {image_path}")
        return None

    results = []
    for obj in decoded:
        data = obj.data.decode("utf-8", errors="replace")
        results.append({
            "type": obj.type,
            "data": data,
            "rect": {"x": obj.rect.left, "y": obj.rect.top,
                     "w": obj.rect.width, "h": obj.rect.height},
        })
        print(f"QR [{obj.type}]: {data}")
    return results


def parse_wifi_qr(data):
    """Parse a WiFi QR code string.

    Standard format: WIFI:T:WPA;S:<ssid>;P:<password>;H:<hidden>;;
    Nintendo may use a custom format.
    """
    result = {"raw": data, "format": "unknown"}

    # Standard WiFi QR format
    wifi_match = re.match(
        r"WIFI:(?:T:(?P<type>[^;]*);)?S:(?P<ssid>[^;]*);P:(?P<password>[^;]*);(?:H:(?P<hidden>[^;]*);)?;?",
        data
    )
    if wifi_match:
        result["format"] = "standard_wifi"
        result["auth_type"] = wifi_match.group("type") or "WPA"
        result["ssid"] = wifi_match.group("ssid")
        result["password"] = wifi_match.group("password")
        result["hidden"] = wifi_match.group("hidden") or "false"
        return result

    # Nintendo-specific: might be a URL
    if data.startswith("http"):
        result["format"] = "url"
        result["url"] = data
        return result

    # Raw data — might be binary/hex
    if all(c in "0123456789abcdefABCDEF" for c in data):
        result["format"] = "hex"
        result["hex_data"] = data
        try:
            result["decoded_bytes"] = bytes.fromhex(data).hex()
        except ValueError:
            pass
        return result

    return result


def analyze_psk_patterns():
    """Analyze PSK generation patterns from known Switch data.

    If we can determine how the PSK is generated, we may be able to:
    1. Connect without scanning the QR code
    2. Understand session key rotation
    3. Identify whether the PSK contains console-specific data
    """
    print("\n" + "=" * 50)
    print("PSK Pattern Analysis")
    print("=" * 50)

    analysis = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "known_data": {
            "ssid": KNOWN_SSID,
            "bssid": KNOWN_BSSID,
            "ssid_format": "switch_<serial_suffix>",
        },
        "ssid_analysis": {},
        "psk_theories": [],
    }

    # Analyze SSID format
    # SSID: switch_F3DCDB0100S
    # BSSID: EC:C4:0D:F3:DC:DB
    suffix = KNOWN_SSID.replace("switch_", "")
    bssid_clean = KNOWN_BSSID.replace(":", "").upper()

    analysis["ssid_analysis"]["suffix"] = suffix
    analysis["ssid_analysis"]["suffix_hex"] = suffix.encode().hex()

    # Check if SSID suffix relates to BSSID
    # BSSID: ECC40DF3DCDB
    # Suffix: F3DCDB0100S
    # F3DCDB appears in both! First 6 chars of suffix = last 3 octets of BSSID
    bssid_last3 = bssid_clean[-6:]  # F3DCDB
    ssid_first6 = suffix[:6]        # F3DCDB

    if bssid_last3 == ssid_first6:
        analysis["ssid_analysis"]["bssid_correlation"] = (
            f"SSID suffix starts with last 3 BSSID octets: "
            f"{ssid_first6} == BSSID[-6:] {bssid_last3}"
        )
        analysis["ssid_analysis"]["remaining_suffix"] = suffix[6:]  # "0100S"
        # 0100S — could be: model type (HAC-001 → 01), region (00), type (S=Switch)
        analysis["ssid_analysis"]["suffix_decode_theory"] = {
            "bssid_tail": suffix[:6],
            "model_code": suffix[6:8],  # "01"
            "region_or_zero": suffix[8:10],  # "00"
            "device_type": suffix[10:],  # "S" = Switch
        }

    print(f"  SSID: {KNOWN_SSID}")
    print(f"  BSSID: {KNOWN_BSSID}")
    print(f"  Suffix: {suffix}")
    if "bssid_correlation" in analysis["ssid_analysis"]:
        print(f"  SSID-BSSID correlation: {analysis['ssid_analysis']['bssid_correlation']}")
        print(f"  Decoded: MAC_tail={suffix[:6]}, model={suffix[6:8]}, "
              f"region={suffix[8:10]}, type={suffix[10:]}")

    # PSK theories
    theories = [
        {
            "theory": "PSK derived from console serial number",
            "evidence": "SSID contains device-specific data (MAC tail). PSK likely similarly derived.",
            "test": "Capture QR code from two different sessions; if PSK changes, it's session-based.",
        },
        {
            "theory": "Static PSK per console",
            "evidence": "Simpler implementation. Many embedded devices use static PSK.",
            "test": "Compare PSK across sessions.",
        },
        {
            "theory": "PSK derived from BSSID + timestamp",
            "evidence": "Would explain per-session rotation while being deterministic.",
            "test": "If PSK format is numeric/hex, check SHA256(BSSID+timestamp) truncation.",
        },
        {
            "theory": "PSK is random per session",
            "evidence": "Most secure option. Requires QR scan for every connection.",
            "test": "Capture multiple QR codes; if no pattern, random.",
        },
    ]
    analysis["psk_theories"] = theories

    for t in theories:
        print(f"\n  Theory: {t['theory']}")
        print(f"    Evidence: {t['evidence']}")
        print(f"    Test: {t['test']}")

    # Key observation: If we can extract even one PSK, we can connect
    # directly to the Switch AP without needing the phone flow
    print("\n  KEY: Once a PSK is known, direct WiFi association is possible.")
    print("  This enables association-level frame injection (not just monitor-mode).")
    print("  Associated clients can send data frames that reach the LDN stack.")

    path = evidence_dir() / "psk_analysis.json"
    with open(path, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"\n  Saved: {path}")
    return analysis


def main():
    parser = argparse.ArgumentParser(description="Switch QR credential extractor")
    parser.add_argument("image", nargs="?", help="QR code image file")
    parser.add_argument("--analyze-psk", action="store_true",
                        help="Analyze PSK generation patterns from known data")
    args = parser.parse_args()

    if args.analyze_psk:
        analyze_psk_patterns()
        return

    if not args.image:
        parser.print_help()
        print("\nRun --analyze-psk for offline PSK pattern analysis")
        sys.exit(1)

    path = Path(args.image)
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    results = decode_qr(str(path))
    if results:
        for r in results:
            parsed = parse_wifi_qr(r["data"])
            r["parsed"] = parsed
            if parsed.get("password"):
                print(f"\n  SSID: {parsed['ssid']}")
                print(f"  Password: {parsed['password']}")
                print(f"  Auth: {parsed['auth_type']}")

                # Save for later use
                creds = evidence_dir() / "wifi_credentials.json"
                with open(creds, "w") as f:
                    json.dump(parsed, f, indent=2)
                print(f"  Saved: {creds}")

        all_results = evidence_dir() / "qr_decode.json"
        with open(all_results, "w") as f:
            json.dump(results, f, indent=2, default=str)


if __name__ == "__main__":
    main()
