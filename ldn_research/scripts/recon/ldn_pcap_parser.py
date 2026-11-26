#!/usr/bin/env python3
"""
LDN protocol parser for pcap captures.

Parses Nintendo Switch LDN frames from existing pcap files:
- Advertisement frames (vendor-specific action frames, category 127, OUI 00:22:AA)
- Auth frames (data frames, ethertype 0x88B7)
- Disconnect frames (data frames, ethertype 0x88B7)

Also extracts and decodes Nintendo vendor Information Elements from beacons.

Usage:
    # Parse the monitor mode capture:
    python3 -I ldn_pcap_parser.py ../evidence/ldn_monitor_20261120_011044.pcap

    # Parse with verbose hex dumps:
    python3 -I ldn_pcap_parser.py ../evidence/ldn_monitor_20261120_011044.pcap --verbose

    # Parse the full baseline capture:
    python3 -I ldn_pcap_parser.py ../evidence/ldn_baseline_20261120_010339.pcap

    # Output JSON:
    python3 -I ldn_pcap_parser.py ../evidence/ldn_monitor_20261120_011044.pcap --json

Evidence saved to ../evidence/ldn_parsed/
"""

import struct
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, raw, Dot11ProbeResp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

LDN_OUI = b"\x00\x22\xaa"
LDN_OUI_HEX = "00:22:aa"
NINTENDO_OUI = b"\x00\x22\xaa"
BROADCOM_OUI = b"\x00\x10\x18"

LDN_PROTOCOL_ID = 4
LDN_PKT_ADVERTISEMENT = 257
LDN_PKT_AUTH = 258
LDN_PKT_DISCONNECT = 259

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "ldn_parsed"


def parse_session_info(data):
    """Parse 32-byte session info."""
    if len(data) < 32:
        return {"error": f"too short ({len(data)} < 32)"}
    title_id = struct.unpack(">Q", data[0:8])[0]
    game_mode = struct.unpack(">H", data[0xA:0xC])[0]
    ssid = data[0x10:0x20].hex()
    return {
        "local_comm_id": f"0x{title_id:016X}",
        "game_mode": game_mode,
        "ssid_hex": ssid,
    }


def parse_participant_plain(data):
    """Parse 56-byte participant entry (plain/CTR format)."""
    if len(data) < 56:
        return {"error": f"too short ({len(data)} < 56)"}
    ip = f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"
    mac = ":".join(f"{b:02x}" for b in data[4:10])
    connected = data[10]
    platform = data[11]
    username = data[12:44].rstrip(b"\x00").decode("utf-8", errors="replace")
    app_ver = struct.unpack(">H", data[44:46])[0]
    return {
        "ip": ip,
        "mac": mac,
        "connected": bool(connected),
        "platform": "Switch" if platform == 0 else "Switch 2" if platform == 1 else f"unknown({platform})",
        "username": username,
        "app_comm_version": app_ver,
    }


def parse_advert_payload(data, verbose=False):
    """Parse advertisement frame payload."""
    result = {}

    if len(data) < 40:
        return {"error": f"payload too short ({len(data)} < 40)"}

    # Session info (32 bytes)
    result["session_info"] = parse_session_info(data[0:32])

    # Payload header
    result["ldn_version"] = data[32]
    result["encryption_type"] = data[33]
    enc_names = {1: "plain", 2: "AES-CTR", 3: "AES-GCM"}
    result["encryption_name"] = enc_names.get(data[33], f"unknown({data[33]})")
    result["advert_data_size"] = struct.unpack(">H", data[34:36])[0]
    result["aes_nonce"] = struct.unpack(">I", data[36:40])[0]

    offset = 40
    if result["encryption_type"] in (1, 2):  # Plain or AES-CTR
        if len(data) < offset + 32:
            result["advert_data_error"] = "truncated before hash"
            return result
        result["sha256_hash"] = data[offset:offset+32].hex()
        offset += 32

        # Advertisement data
        advert_data = data[offset:]
        claimed_size = result["advert_data_size"]
        result["actual_advert_data_size"] = len(advert_data)

        if claimed_size != len(advert_data):
            result["size_mismatch"] = True
            result["claimed_vs_actual"] = f"{claimed_size} vs {len(advert_data)}"

        if len(advert_data) >= 0x18:
            result["server_random"] = advert_data[0:16].hex()
            result["security_level"] = struct.unpack(">H", advert_data[16:18])[0]
            result["accept_policy"] = advert_data[18]
            policy_names = {0: "open", 1: "closed", 2: "blacklist", 3: "whitelist"}
            result["accept_policy_name"] = policy_names.get(advert_data[18], f"unknown({advert_data[18]})")

        if len(advert_data) >= 0x1A:
            ch_band = struct.unpack(">H", advert_data[0x14:0x16])[0]
            result["channel"] = ch_band & 0x03FF
            band_val = (ch_band >> 10) & 0x3F
            band_names = {2: "2.4 GHz", 5: "5 GHz", 6: "6 GHz"}
            result["band"] = band_names.get(band_val, f"unknown({band_val})")
            result["max_participants"] = advert_data[0x16]
            result["current_participants"] = advert_data[0x17]

        if len(advert_data) >= 0x1D8:
            # Parse participants
            participants = []
            num_p = min(result.get("current_participants", 0), 8)
            for i in range(num_p):
                p_offset = 0x18 + i * 56
                if p_offset + 56 <= len(advert_data):
                    p = parse_participant_plain(advert_data[p_offset:p_offset+56])
                    participants.append(p)
            result["participants"] = participants

        if len(advert_data) >= 0x1DC:
            app_data_size = struct.unpack(">H", advert_data[0x1DA:0x1DC])[0]
            result["app_data_size"] = app_data_size
            if verbose and len(advert_data) >= 0x1DC + app_data_size:
                result["app_data_hex"] = advert_data[0x1DC:0x1DC+min(app_data_size, 64)].hex()

        if len(advert_data) >= 0x500:
            result["auth_token"] = struct.unpack(">Q", advert_data[0x4F8:0x500])[0]

    elif result["encryption_type"] == 3:  # AES-GCM
        if len(data) >= offset + 16:
            result["gcm_mac"] = data[offset:offset+16].hex()
            result["encrypted_data_size"] = len(data) - offset - 16
        else:
            result["advert_data_error"] = "truncated GCM data"

    return result


def parse_auth_frame(data, verbose=False):
    """Parse auth/disconnect frame payload (after ethertype)."""
    result = {}

    if len(data) < 6:
        return {"error": f"frame too short ({len(data)} < 6)"}

    # Header: OUI (3) + packet type (2) + pad (1)
    oui = data[0:3]
    result["oui"] = ":".join(f"{b:02x}" for b in oui)
    result["oui_match"] = (oui == LDN_OUI)
    pkt_type = struct.unpack(">H", data[3:5])[0]
    result["packet_type"] = pkt_type

    pkt_names = {257: "advertisement", 258: "auth", 259: "disconnect"}
    result["packet_type_name"] = pkt_names.get(pkt_type, f"unknown({pkt_type})")

    if pkt_type == LDN_PKT_DISCONNECT:
        if len(data) >= 7:
            result["reason"] = data[6]
            reason_names = {3: "network_destroyed", 4: "destroyed_forcefully", 5: "rejected"}
            result["reason_name"] = reason_names.get(data[6], f"unknown({data[6]})")
        return result

    if pkt_type != LDN_PKT_AUTH:
        return result

    # Auth data header (0x48 bytes starting at offset 6)
    offset = 6
    if len(data) < offset + 0x48:
        result["error"] = f"auth header truncated ({len(data)} < {offset + 0x48})"
        return result

    auth_hdr = data[offset:offset + 0x48]
    result["ldn_version"] = auth_hdr[0]
    payload_size_low = auth_hdr[1]
    result["status_code"] = auth_hdr[2]
    result["is_response"] = bool(auth_hdr[3])
    payload_size_high = auth_hdr[4]
    result["payload_size"] = payload_size_low | (payload_size_high << 8)

    result["session_info"] = parse_session_info(auth_hdr[8:40])
    result["server_random"] = auth_hdr[0x28:0x38].hex()
    result["client_random"] = auth_hdr[0x38:0x48].hex()

    # Auth payload
    payload_offset = offset + 0x48
    actual_payload_size = len(data) - payload_offset
    result["actual_payload_size"] = actual_payload_size

    if result["payload_size"] != actual_payload_size:
        result["payload_size_mismatch"] = True

    if not result["is_response"] and actual_payload_size >= 32:
        # Auth request
        payload = data[payload_offset:]
        result["username"] = payload[0:32].rstrip(b"\x00").decode("utf-8", errors="replace")
        if actual_payload_size >= 35:
            result["app_comm_version"] = struct.unpack(">H", payload[32:34])[0]
            result["platform"] = payload[34]

        if result["ldn_version"] >= 3 and actual_payload_size >= 0x64 + 0x300:
            result["has_challenge"] = True
            if verbose:
                challenge = payload[0x64:0x64+0x300]
                result["challenge_hmac"] = challenge[4:36].hex()
                result["challenge_p"] = challenge[0x32]
                result["challenge_q"] = challenge[0x33]
                result["challenge_flags"] = challenge[0x34]
        elif result["ldn_version"] >= 3:
            result["has_challenge"] = False
            result["challenge_note"] = "v3+ but challenge data missing/truncated"

    return result


def parse_nintendo_vendor_ie(data):
    """Parse Nintendo vendor Information Element from beacon."""
    result = {}
    if len(data) < 4:
        return {"raw_hex": data.hex()}
    result["oui"] = ":".join(f"{b:02x}" for b in data[0:3])
    result["type"] = data[3]
    if len(data) > 4:
        result["data_hex"] = data[4:].hex()
        result["data_len"] = len(data) - 4
    return result


def analyze_pcap(pcap_path, verbose=False):
    """Parse all LDN-related frames from a pcap file."""
    if not HAS_SCAPY:
        print("[!] scapy required. Install: pip install scapy")
        sys.exit(1)

    print(f"[*] Loading {pcap_path}...")
    packets = rdpcap(str(pcap_path))
    print(f"[*] Loaded {len(packets)} packets")

    results = {
        "file": str(pcap_path),
        "total_packets": len(packets),
        "beacons": [],
        "probe_responses": [],
        "action_frames": [],
        "ldn_data_frames": [],
        "summary": {},
    }

    beacon_count = 0
    probe_resp_count = 0
    action_count = 0
    ldn_data_count = 0

    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]

        # Beacons and probe responses — extract Nintendo vendor IEs
        if dot11.type == 0 and dot11.subtype in (8, 5):  # Beacon or ProbeResp
            frame_info = {
                "frame_num": i + 1,
                "type": "beacon" if dot11.subtype == 8 else "probe_response",
                "bssid": dot11.addr3,
                "src": dot11.addr2,
                "dst": dot11.addr1,
                "vendor_ies": [],
            }

            # Walk Information Elements
            elt_layer = dot11.payload.payload if dot11.subtype == 8 else dot11.payload.payload
            while elt_layer and isinstance(elt_layer, Dot11Elt):
                if elt_layer.ID == 0:  # SSID
                    frame_info["ssid"] = elt_layer.info.decode("utf-8", errors="replace")
                elif elt_layer.ID == 221:  # Vendor Specific
                    ie_data = elt_layer.info
                    if len(ie_data) >= 3:
                        oui = ie_data[0:3]
                        if oui == NINTENDO_OUI:
                            parsed_ie = parse_nintendo_vendor_ie(ie_data)
                            parsed_ie["label"] = "Nintendo"
                            frame_info["vendor_ies"].append(parsed_ie)
                        elif oui == BROADCOM_OUI:
                            frame_info["vendor_ies"].append({
                                "oui": ":".join(f"{b:02x}" for b in oui),
                                "label": "Broadcom",
                                "data_hex": ie_data[3:].hex() if len(ie_data) > 3 else "",
                            })
                elt_layer = elt_layer.payload if hasattr(elt_layer, 'payload') else None
                if elt_layer and not isinstance(elt_layer, Dot11Elt):
                    break

            if dot11.subtype == 8:
                beacon_count += 1
                if beacon_count <= 5 or verbose:
                    results["beacons"].append(frame_info)
            else:
                probe_resp_count += 1
                results["probe_responses"].append(frame_info)

        # Action frames (type 0, subtype 13) — LDN advertisements
        elif dot11.type == 0 and dot11.subtype == 13:
            action_count += 1
            payload = bytes(dot11.payload)
            if len(payload) > 0 and payload[0] == 127:  # Category vendor-specific
                if len(payload) >= 5 and payload[1:4] == LDN_OUI:
                    frame_info = {
                        "frame_num": i + 1,
                        "src": dot11.addr2,
                        "dst": dot11.addr1,
                        "bssid": dot11.addr3,
                        "raw_size": len(payload),
                    }
                    # Skip the 12-byte action header
                    if len(payload) >= 12:
                        pkt_type = struct.unpack(">H", payload[6:8])[0]
                        frame_info["ldn_packet_type"] = pkt_type
                        if pkt_type == LDN_PKT_ADVERTISEMENT and len(payload) > 12:
                            frame_info["advert"] = parse_advert_payload(
                                payload[12:], verbose=verbose)
                    results["action_frames"].append(frame_info)

        # Data frames with ethertype 0x88B7 — LDN auth/disconnect
        elif dot11.type == 2:
            frame_bytes = raw(pkt)
            # Look for ethertype 0x88B7 in the frame
            idx = frame_bytes.find(b"\x88\xb7")
            if idx >= 0 and idx + 2 < len(frame_bytes):
                ldn_data_count += 1
                ldn_payload = frame_bytes[idx + 2:]
                frame_info = {
                    "frame_num": i + 1,
                    "src": dot11.addr2,
                    "dst": dot11.addr1,
                    "ethertype_offset": idx,
                    "payload_size": len(ldn_payload),
                }
                if len(ldn_payload) >= 6:
                    frame_info["parsed"] = parse_auth_frame(ldn_payload, verbose=verbose)
                results["ldn_data_frames"].append(frame_info)

    results["summary"] = {
        "beacons": beacon_count,
        "probe_responses": probe_resp_count,
        "action_frames": action_count,
        "ldn_data_frames": ldn_data_count,
    }

    return results


def print_results(results, verbose=False):
    """Pretty-print analysis results."""
    print(f"\n{'='*60}")
    print(f"LDN Protocol Analysis: {results['file']}")
    print(f"Total packets: {results['total_packets']}")
    print(f"{'='*60}")

    s = results["summary"]
    print(f"\nFrame counts:")
    print(f"  Beacons:          {s['beacons']}")
    print(f"  Probe responses:  {s['probe_responses']}")
    print(f"  Action frames:    {s['action_frames']}")
    print(f"  LDN data frames:  {s['ldn_data_frames']}")

    if results["beacons"]:
        print(f"\n--- Beacons (first {len(results['beacons'])}) ---")
        for b in results["beacons"]:
            print(f"  Frame #{b['frame_num']}: BSSID={b['bssid']} SSID={b.get('ssid', '?')}")
            for ie in b["vendor_ies"]:
                print(f"    Vendor IE [{ie['label']}]: OUI={ie['oui']}"
                      f" type={ie.get('type', '?')}"
                      f" data={ie.get('data_hex', '')[:40]}")

    if results["probe_responses"]:
        print(f"\n--- Probe Responses ({len(results['probe_responses'])}) ---")
        for p in results["probe_responses"]:
            print(f"  Frame #{p['frame_num']}: src={p['src']} dst={p['dst']}")
            for ie in p["vendor_ies"]:
                print(f"    Vendor IE [{ie['label']}]: OUI={ie['oui']}"
                      f" type={ie.get('type', '?')}")

    if results["action_frames"]:
        print(f"\n--- LDN Action Frames ({len(results['action_frames'])}) ---")
        for af in results["action_frames"]:
            print(f"  Frame #{af['frame_num']}: src={af['src']} -> {af['dst']}"
                  f" size={af['raw_size']}")
            if "advert" in af:
                a = af["advert"]
                if "error" not in a:
                    print(f"    LDN version:    {a.get('ldn_version', '?')}")
                    print(f"    Encryption:     {a.get('encryption_name', '?')}")
                    print(f"    Advert size:    {a.get('advert_data_size', '?')}"
                          f" (actual: {a.get('actual_advert_data_size', '?')})")
                    si = a.get("session_info", {})
                    print(f"    Title ID:       {si.get('local_comm_id', '?')}")
                    print(f"    Game mode:      {si.get('game_mode', '?')}")
                    print(f"    Participants:   {a.get('current_participants', '?')}"
                          f"/{a.get('max_participants', '?')}")
                    if a.get("participants"):
                        for p in a["participants"]:
                            print(f"      - {p.get('username', '?')} @ {p.get('ip', '?')}"
                                  f" ({p.get('platform', '?')})")
                else:
                    print(f"    Error: {a['error']}")

    if results["ldn_data_frames"]:
        print(f"\n--- LDN Data Frames ({len(results['ldn_data_frames'])}) ---")
        for df in results["ldn_data_frames"]:
            print(f"  Frame #{df['frame_num']}: src={df['src']} -> {df['dst']}"
                  f" size={df['payload_size']}")
            if "parsed" in df:
                p = df["parsed"]
                print(f"    Packet type: {p.get('packet_type_name', '?')}")
                if p.get("packet_type_name") == "auth":
                    print(f"    LDN version: {p.get('ldn_version', '?')}")
                    print(f"    Is response: {p.get('is_response', '?')}")
                    print(f"    Payload size: {p.get('payload_size', '?')}"
                          f" (actual: {p.get('actual_payload_size', '?')})")
                    if "username" in p:
                        print(f"    Username: {p['username']}")
                elif p.get("packet_type_name") == "disconnect":
                    print(f"    Reason: {p.get('reason_name', '?')}")


def main():
    parser = argparse.ArgumentParser(
        description="Parse LDN protocol frames from pcap captures"
    )
    parser.add_argument("pcap", help="Path to pcap file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Include hex dumps and full details")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output JSON instead of text")
    parser.add_argument("--output", "-o",
                        help="Output file (default: stdout or evidence dir)")

    args = parser.parse_args()
    pcap_path = Path(args.pcap)

    if not pcap_path.exists():
        print(f"[!] File not found: {pcap_path}")
        sys.exit(1)

    results = analyze_pcap(pcap_path, verbose=args.verbose)

    if args.json or args.output:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        output_path = args.output or str(
            EVIDENCE_DIR / f"parsed_{pcap_path.stem}.json"
        )
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[*] Results saved to {output_path}")
    else:
        print_results(results, verbose=args.verbose)

    return results


if __name__ == "__main__":
    main()
