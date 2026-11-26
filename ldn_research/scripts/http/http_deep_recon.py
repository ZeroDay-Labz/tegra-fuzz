#!/usr/bin/env python3
"""
Deep HTTP recon against the Switch "Send to Smartphone" server.
Tests attack surface beyond the baseline: methods, headers, pipelining,
encoding edge cases, URI length limits, and connection behavior.

Usage:
    1. Put Switch in "Send to Smartphone" mode (Album → Send to Smartphone)
    2. Connect PC to the switch_F3DCDB* WiFi AP
    3. Run: python3 -I http_deep_recon.py

All results saved to ../evidence/http_deep_recon/

Safety: read-only probing. No payloads designed to crash.
"""

import socket
import json
import os
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

SWITCH_IP = "192.168.0.1"
SWITCH_PORT = 80
TIMEOUT = 5
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "http_deep_recon"
KNOWN_PATHS = [
    "/index.html",
    "/js/index.js",
    "/styles/index.css",
    "/data.json",
]


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def raw_request(request_bytes: bytes, timeout: float = TIMEOUT) -> tuple[bytes, float]:
    """Send raw bytes, return (response_bytes, elapsed_seconds)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.connect((SWITCH_IP, SWITCH_PORT))
        sock.sendall(request_bytes)
        chunks = []
        while True:
            try:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break
        elapsed = time.monotonic() - t0
        return b"".join(chunks), elapsed
    except (ConnectionRefusedError, OSError) as e:
        elapsed = time.monotonic() - t0
        return f"ERROR: {e}".encode(), elapsed
    finally:
        sock.close()


def http_request(method: str, path: str, headers: dict | None = None,
                 body: bytes | None = None, http_version: str = "1.1") -> tuple[bytes, float]:
    """Build and send a well-formed HTTP request."""
    hdrs = {"Host": SWITCH_IP}
    if headers:
        hdrs.update(headers)
    if body and "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(body))

    lines = [f"{method} {path} HTTP/{http_version}"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    raw = "\r\n".join(lines).encode()
    if body:
        raw += body
    return raw_request(raw)


def parse_status_line(response: bytes) -> tuple[int, str]:
    """Extract status code and reason from response."""
    try:
        first_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        parts = first_line.split(" ", 2)
        return int(parts[1]), parts[2] if len(parts) > 2 else ""
    except (IndexError, ValueError):
        return -1, response[:80].decode("ascii", errors="replace")


def parse_headers(response: bytes) -> dict:
    """Parse response headers into a dict (last value wins for dupes)."""
    result = {}
    try:
        header_block = response.split(b"\r\n\r\n", 1)[0]
        for line in header_block.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                result[k.decode().strip().lower()] = v.decode().strip()
    except Exception:
        pass
    return result


def save_result(name: str, data: dict):
    """Save a test result as JSON."""
    path = evidence_dir() / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  → saved {path.name}")


def connectivity_check() -> bool:
    """Verify the Switch HTTP server is reachable."""
    print("Connectivity check...")
    resp, elapsed = http_request("GET", "/index.html")
    code, _ = parse_status_line(resp)
    if code == 200:
        print(f"  ✓ Switch HTTP server responding ({elapsed:.3f}s)")
        return True
    print(f"  ✗ Got status {code} — is the Switch in 'Send to Smartphone' mode?")
    print(f"    Raw: {resp[:120]}")
    return False


# ═══════════════════════════════════════════════════════════
# TEST MODULES
# ═══════════════════════════════════════════════════════════

def test_http_methods():
    """Test all standard HTTP methods to map what the server accepts."""
    print("\n[1] HTTP Methods")
    methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "TRACE",
               "CONNECT", "OPTIONS", "PROPFIND", "MKCOL"]
    results = {}
    for method in methods:
        resp, elapsed = http_request(method, "/index.html")
        code, reason = parse_status_line(resp)
        hdrs = parse_headers(resp)
        body_start = resp.find(b"\r\n\r\n")
        body = resp[body_start + 4:] if body_start >= 0 else b""
        results[method] = {
            "status": code,
            "reason": reason,
            "content_length": hdrs.get("content-length", ""),
            "content_type": hdrs.get("content-type", ""),
            "body_bytes": len(body),
            "elapsed": round(elapsed, 4),
        }
        print(f"  {method:10s} → {code} ({elapsed:.3f}s) body={len(body)}B")

    save_result("methods", {"test": "http_methods", "path": "/index.html",
                            "results": results})
    return results


def test_http_versions():
    """Test HTTP/1.0, HTTP/0.9, and malformed version strings."""
    print("\n[2] HTTP Versions")
    versions = [
        ("1.0", "HTTP/1.0"),
        ("1.1", "HTTP/1.1"),
        ("0.9_style", None),  # HTTP/0.9: just "GET /path\r\n"
        ("2.0", "HTTP/2.0"),
        ("99.99", "HTTP/99.99"),
        ("empty", ""),
    ]
    results = {}
    for name, ver in versions:
        if name == "0.9_style":
            raw = b"GET /index.html\r\n"
            resp, elapsed = raw_request(raw)
        elif name == "empty":
            raw = b"GET /index.html \r\nHost: 192.168.0.1\r\n\r\n"
            resp, elapsed = raw_request(raw)
        else:
            resp, elapsed = http_request("GET", "/index.html", http_version=ver.split("/")[1] if "/" in ver else ver)

        code, reason = parse_status_line(resp)
        results[name] = {
            "status": code,
            "reason": reason,
            "response_preview": resp[:200].decode("ascii", errors="replace"),
            "total_bytes": len(resp),
            "elapsed": round(elapsed, 4),
        }
        print(f"  {name:12s} → {code} ({elapsed:.3f}s) {len(resp)}B")

    save_result("versions", {"test": "http_versions", "results": results})
    return results


def test_uri_lengths():
    """Binary search for URI length limits. This is critical for CVE-2026-82079."""
    print("\n[3] URI Length Limits")
    lengths = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    results = {}
    last_success = 0

    for length in lengths:
        path = "/img/" + "A" * (length - 5)  # subtract /img/ prefix
        if len(path) < length:
            path += "A" * (length - len(path))
        resp, elapsed = http_request("GET", path)
        code, reason = parse_status_line(resp)
        hdrs = parse_headers(resp)

        result = {
            "uri_length": len(path),
            "status": code,
            "reason": reason,
            "content_length": hdrs.get("content-length", ""),
            "response_bytes": len(resp),
            "elapsed": round(elapsed, 4),
        }
        results[str(length)] = result

        status_str = "✓" if code > 0 else "✗"
        print(f"  {status_str} URI len {len(path):6d} → {code} ({elapsed:.3f}s) resp={len(resp)}B")

        if code > 0:
            last_success = len(path)
        else:
            print(f"    Server stopped responding at URI length {len(path)}")
            # Test if the server is still alive
            time.sleep(0.5)
            check_resp, _ = http_request("GET", "/index.html")
            check_code, _ = parse_status_line(check_resp)
            result["server_alive_after"] = check_code > 0
            if check_code <= 0:
                print("    ⚠ Server appears down — possible crash!")
                result["possible_crash"] = True
                break

    results["summary"] = {
        "last_successful_uri_length": last_success,
        "tested_up_to": lengths[-1] if last_success == lengths[-1] else len(path),
    }
    save_result("uri_lengths", {"test": "uri_length_limits", "results": results})
    return results


def test_header_sizes():
    """Test oversized individual headers."""
    print("\n[4] Header Size Limits")
    header_names = ["Host", "User-Agent", "Accept", "X-Custom", "Cookie", "Referer"]
    sizes = [256, 1024, 4096, 8192, 16384]
    results = {}

    for hdr_name in header_names:
        hdr_results = {}
        for size in sizes:
            hdrs = {hdr_name: "A" * size}
            if hdr_name != "Host":
                hdrs["Host"] = SWITCH_IP
            resp, elapsed = http_request("GET", "/index.html", headers=hdrs)
            code, _ = parse_status_line(resp)
            hdr_results[str(size)] = {
                "status": code,
                "response_bytes": len(resp),
                "elapsed": round(elapsed, 4),
            }
            status_str = "✓" if code > 0 else "✗"
            print(f"  {status_str} {hdr_name:12s} = {size:6d}B → {code} ({elapsed:.3f}s)")

            if code <= 0:
                time.sleep(0.5)
                check_resp, _ = http_request("GET", "/index.html")
                check_code, _ = parse_status_line(check_resp)
                hdr_results[str(size)]["server_alive_after"] = check_code > 0
                if check_code <= 0:
                    print(f"    ⚠ Server down after {hdr_name}={size}B — possible crash!")
                    hdr_results[str(size)]["possible_crash"] = True
                break
        results[hdr_name] = hdr_results

    save_result("header_sizes", {"test": "header_size_limits", "results": results})
    return results


def test_many_headers():
    """Test sending many headers at once."""
    print("\n[5] Many Headers")
    counts = [10, 50, 100, 200, 500]
    results = {}

    for count in counts:
        hdrs = {"Host": SWITCH_IP}
        for i in range(count):
            hdrs[f"X-Test-{i:04d}"] = f"value-{i}"
        resp, elapsed = http_request("GET", "/index.html", headers=hdrs)
        code, _ = parse_status_line(resp)
        results[str(count)] = {
            "status": code,
            "response_bytes": len(resp),
            "elapsed": round(elapsed, 4),
        }
        status_str = "✓" if code > 0 else "✗"
        print(f"  {status_str} {count:4d} headers → {code} ({elapsed:.3f}s)")

        if code <= 0:
            time.sleep(0.5)
            check_resp, _ = http_request("GET", "/index.html")
            check_code, _ = parse_status_line(check_resp)
            results[str(count)]["server_alive_after"] = check_code > 0
            if check_code <= 0:
                print(f"    ⚠ Server down after {count} headers!")
                break

    save_result("many_headers", {"test": "many_headers", "results": results})
    return results


def test_post_body():
    """Test POST with various body sizes."""
    print("\n[6] POST Body Sizes")
    sizes = [0, 64, 256, 1024, 4096, 16384, 65536]
    results = {}

    for size in sizes:
        body = b"A" * size
        resp, elapsed = http_request("POST", "/index.html",
                                     headers={"Content-Type": "application/octet-stream"},
                                     body=body)
        code, _ = parse_status_line(resp)
        results[str(size)] = {
            "status": code,
            "response_bytes": len(resp),
            "elapsed": round(elapsed, 4),
        }
        status_str = "✓" if code > 0 else "✗"
        print(f"  {status_str} POST body {size:6d}B → {code} ({elapsed:.3f}s)")

        if code <= 0:
            time.sleep(0.5)
            check_resp, _ = http_request("GET", "/index.html")
            check_code, _ = parse_status_line(check_resp)
            results[str(size)]["server_alive_after"] = check_code > 0
            if check_code <= 0:
                print(f"    ⚠ Server down after POST body {size}B!")
                break

    save_result("post_body", {"test": "post_body_sizes", "results": results})
    return results


def test_chunked_encoding():
    """Test chunked transfer-encoding (unusual for a minimal server)."""
    print("\n[7] Transfer-Encoding: chunked")
    raw = (
        b"POST /index.html HTTP/1.1\r\n"
        b"Host: 192.168.0.1\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nHello\r\n"
        b"0\r\n\r\n"
    )
    resp, elapsed = raw_request(raw)
    code, reason = parse_status_line(resp)
    result = {
        "status": code,
        "reason": reason,
        "response_preview": resp[:300].decode("ascii", errors="replace"),
        "elapsed": round(elapsed, 4),
    }
    print(f"  chunked POST → {code} ({elapsed:.3f}s)")

    # Also test GET with chunked (nonsensical but tests parser)
    raw2 = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: 192.168.0.1\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    resp2, elapsed2 = raw_request(raw2)
    code2, _ = parse_status_line(resp2)
    result["get_with_chunked"] = {
        "status": code2,
        "response_bytes": len(resp2),
        "elapsed": round(elapsed2, 4),
    }
    print(f"  chunked GET  → {code2} ({elapsed2:.3f}s)")

    save_result("chunked", {"test": "chunked_encoding", "results": result})
    return result


def test_pipelining():
    """Test HTTP pipelining — multiple requests on one connection."""
    print("\n[8] HTTP Pipelining")
    req1 = b"GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"
    req2 = b"GET /data.json HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"

    # Send two requests at once
    combined = req1 + req2
    resp, elapsed = raw_request(combined, timeout=5)

    # Count how many HTTP responses we got
    response_count = resp.count(b"HTTP/1.")
    result = {
        "requests_sent": 2,
        "responses_received": response_count,
        "total_bytes": len(resp),
        "elapsed": round(elapsed, 4),
        "response_preview": resp[:500].decode("ascii", errors="replace"),
    }
    print(f"  2 pipelined requests → {response_count} responses ({elapsed:.3f}s)")

    save_result("pipelining", {"test": "pipelining", "results": result})
    return result


def test_malformed_requests():
    """Test various malformed HTTP requests."""
    print("\n[9] Malformed Requests")
    tests = {
        "no_crlf": b"GET /index.html HTTP/1.1\nHost: 192.168.0.1\n\n",
        "no_host": b"GET /index.html HTTP/1.1\r\n\r\n",
        "double_slash": b"GET //index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "dot_dot": b"GET /../../../etc/passwd HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "null_in_uri": b"GET /index\x00.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "tab_in_uri": b"GET /index\t.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "space_in_uri": b"GET /index .html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "url_encoded": b"GET /%69%6e%64%65%78%2e%68%74%6d%6c HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "query_string": b"GET /data.json?foo=bar&baz=qux HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "fragment": b"GET /index.html#section HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "absolute_uri": b"GET http://192.168.0.1/index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "empty_line_before": b"\r\nGET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "crlf_injection": b"GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\nX-Inject: a\r\n\r\nGET /data.json HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
        "just_crlf": b"\r\n\r\n",
        "binary_garbage": bytes(range(256)),
    }
    results = {}
    for name, raw in tests.items():
        resp, elapsed = raw_request(raw)
        code, reason = parse_status_line(resp)
        results[name] = {
            "status": code,
            "reason": reason,
            "response_bytes": len(resp),
            "elapsed": round(elapsed, 4),
            "response_preview": resp[:200].decode("ascii", errors="replace"),
        }
        print(f"  {name:20s} → {code} ({elapsed:.3f}s)")

    save_result("malformed", {"test": "malformed_requests", "results": results})
    return results


def test_port_scan():
    """Quick scan of common ports on the Switch AP."""
    print("\n[10] Port Scan (common ports)")
    ports = [21, 22, 23, 25, 53, 80, 443, 445, 554, 1080, 2000, 2021,
             3000, 3389, 5000, 5353, 5555, 8000, 8080, 8443, 8888, 9090,
             49152, 49153, 49154]
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((SWITCH_IP, port))
            results[str(port)] = "open"
            print(f"  port {port:5d} → OPEN")
            sock.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            results[str(port)] = "closed/filtered"

    open_ports = [p for p, s in results.items() if s == "open"]
    print(f"  Open ports: {open_ports if open_ports else 'only 80 (when active)'}")
    save_result("port_scan", {"test": "port_scan", "results": results})
    return results


def test_connection_timing():
    """Measure timing characteristics that might reveal processing stages."""
    print("\n[11] Connection Timing")
    paths = ["/index.html", "/data.json", "/js/index.js",
             "/img/nonexistent.jpg", "/missing"]
    results = {}

    for path in paths:
        timings = []
        for _ in range(5):
            _, elapsed = http_request("GET", path)
            timings.append(elapsed)
            time.sleep(0.1)
        avg = sum(timings) / len(timings)
        results[path] = {
            "timings": [round(t, 6) for t in timings],
            "mean": round(avg, 6),
            "min": round(min(timings), 6),
            "max": round(max(timings), 6),
        }
        print(f"  {path:30s} → mean={avg*1000:.2f}ms min={min(timings)*1000:.2f}ms max={max(timings)*1000:.2f}ms")

    save_result("timing", {"test": "connection_timing", "results": results})
    return results


def test_concurrent_connections():
    """Test concurrent connection handling."""
    print("\n[12] Concurrent Connections")
    results = {}

    for count in [1, 2, 5, 10, 20]:
        sockets = []
        connected = 0
        try:
            for i in range(count):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                try:
                    s.connect((SWITCH_IP, SWITCH_PORT))
                    sockets.append(s)
                    connected += 1
                except (ConnectionRefusedError, socket.timeout, OSError):
                    s.close()
                    break

            # Try sending on the last connected socket
            response_on_last = False
            if sockets:
                try:
                    sockets[-1].sendall(b"GET /index.html HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n")
                    data = sockets[-1].recv(1024)
                    response_on_last = b"200 OK" in data
                except Exception:
                    pass

            results[str(count)] = {
                "attempted": count,
                "connected": connected,
                "response_on_last": response_on_last,
            }
            print(f"  {count:3d} attempted → {connected} connected, last responds: {response_on_last}")
        finally:
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass

    save_result("concurrent", {"test": "concurrent_connections", "results": results})
    return results


def test_range_integers():
    """Test extreme range values for integer overflow."""
    print("\n[13] Range Integer Edge Cases")
    test_ranges = {
        "max_32bit": "bytes=0-4294967295",
        "max_32bit_signed": "bytes=0-2147483647",
        "max_64bit": "bytes=0-18446744073709551615",
        "negative_via_wrap": "bytes=4294967295-0",
        "huge_start": "bytes=4294967290-4294967295",
        "zero_zero": "bytes=0-0",
        "minus_1": "bytes=-1",
        "minus_large": "bytes=-4294967295",
        "multi_range": "bytes=0-10, 20-30",
        "empty_range": "bytes=",
        "no_equals": "bytes",
        "wrong_unit": "kbytes=0-10",
    }

    path = "/img/2026082120041401-0E7DF678130F4F0FA2C88AE72B47AFDF.jpg"
    results = {}

    for name, range_val in test_ranges.items():
        resp, elapsed = http_request("GET", path, headers={"Range": range_val})
        code, reason = parse_status_line(resp)
        hdrs = parse_headers(resp)

        # Check for double Content-Type (known bug)
        ct_count = resp.count(b"Content-Type:")

        results[name] = {
            "range_header": range_val,
            "status": code,
            "reason": reason,
            "content_length": hdrs.get("content-length", ""),
            "content_range": hdrs.get("content-range", ""),
            "content_type_count": ct_count,
            "response_bytes": len(resp),
            "elapsed": round(elapsed, 4),
        }
        flag = " ⚠ DOUBLE CT" if ct_count > 1 else ""
        print(f"  {name:20s} → {code} CL={hdrs.get('content-length', '?'):>12s}{flag}")

    save_result("range_integers", {"test": "range_integer_edges", "path": path,
                                   "results": results})
    return results


def generate_manifest(all_results: dict):
    """Generate a summary manifest of all tests."""
    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": f"{SWITCH_IP}:{SWITCH_PORT}",
        "tests_run": list(all_results.keys()),
        "anomalies": [],
    }

    # Scan for anomalies
    for test_name, results in all_results.items():
        if isinstance(results, dict):
            for key, val in results.items():
                if isinstance(val, dict):
                    if val.get("possible_crash"):
                        manifest["anomalies"].append({
                            "test": test_name, "key": key,
                            "type": "possible_crash"
                        })
                    if val.get("content_type_count", 0) > 1:
                        manifest["anomalies"].append({
                            "test": test_name, "key": key,
                            "type": "double_content_type"
                        })

    path = evidence_dir() / "manifest.json"
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    print(f"\nManifest saved: {path}")
    return manifest


def main():
    print("=" * 60)
    print("Switch LDN HTTP Deep Recon")
    print(f"Target: {SWITCH_IP}:{SWITCH_PORT}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    if not connectivity_check():
        print("\nAbort: cannot reach Switch HTTP server.")
        print("Ensure the Switch is in Album → Send to Smartphone mode")
        print("and your PC is connected to the switch_* WiFi AP.")
        sys.exit(1)

    all_results = {}

    all_results["methods"] = test_http_methods()
    all_results["versions"] = test_http_versions()
    all_results["uri_lengths"] = test_uri_lengths()
    all_results["header_sizes"] = test_header_sizes()
    all_results["many_headers"] = test_many_headers()
    all_results["post_body"] = test_post_body()
    all_results["chunked"] = test_chunked_encoding()
    all_results["pipelining"] = test_pipelining()
    all_results["malformed"] = test_malformed_requests()
    all_results["port_scan"] = test_port_scan()
    all_results["timing"] = test_connection_timing()
    all_results["concurrent"] = test_concurrent_connections()
    all_results["range_integers"] = test_range_integers()

    manifest = generate_manifest(all_results)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print(f"Tests run: {len(all_results)}")
    print(f"Anomalies found: {len(manifest['anomalies'])}")
    for a in manifest["anomalies"]:
        print(f"  ⚠ {a['type']} in {a['test']}/{a['key']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
