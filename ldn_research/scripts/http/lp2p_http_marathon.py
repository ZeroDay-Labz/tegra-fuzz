#!/usr/bin/env python3
"""
Marathon HTTP fuzzer — runs continuously until Switch sleeps.
Covers: image file serving, Range on large files, concurrent edge cases,
protocol confusion, partial sends, slow writes, binary payloads.

Usage:
    sudo python3 -Iu lp2p_http_marathon.py --iface wlp5s0
"""

import subprocess
import socket
import time
import json
import sys
import struct
import argparse
import threading
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
SWITCH_IP = "192.168.0.1"


def ping_alive():
    r = subprocess.run(["ping", "-c", "1", "-W", "2", SWITCH_IP],
                       capture_output=True)
    return r.returncode == 0


def raw_http(request_bytes, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((SWITCH_IP, 80))
        sock.sendall(request_bytes)
        data = b""
        while True:
            try:
                chunk = sock.recv(8192)
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


def slow_send(request_bytes, chunk_size=1, delay=0.1, timeout=10):
    """Send request one byte at a time."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((SWITCH_IP, 80))
        for i in range(0, len(request_bytes), chunk_size):
            sock.sendall(request_bytes[i:i+chunk_size])
            time.sleep(delay)
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


def test(label, func, delay=1.0):
    if not ping_alive():
        return {"label": label, "status": "unreachable", "alive": False}

    print(f"  [{label}] ", end="", flush=True)
    try:
        data, status = func()
    except Exception as e:
        data, status = b"", f"EXCEPTION: {e}"

    time.sleep(0.5)
    alive = ping_alive()

    if not alive:
        print(f"→ CRASH! ({status[:60]})")
        time.sleep(15)
        recovered = ping_alive()
        result = {"label": label, "resp_len": len(data), "status_line": status[:200],
                  "alive": False, "recovered": recovered}
        if not recovered:
            print(f"      *** CONFIRMED CRASH ***")
        return result

    s = status.split(" ", 2)
    code = s[1] if len(s) > 1 else "?"
    print(f"→ {code} ({len(data)}B)")

    time.sleep(delay)
    return {"label": label, "resp_len": len(data), "status_line": status[:200], "alive": True}


# Get image filenames from data.json
def get_images():
    try:
        data, _ = raw_http(
            f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        )
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        j = json.loads(body)
        return j.get("FileNames", [])
    except:
        return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    args = parser.parse_args()

    print("=" * 60)
    print("  lp2p HTTP Marathon Fuzzer")
    print("=" * 60)
    ts = datetime.now(timezone.utc).isoformat()
    print(f"  Target: {SWITCH_IP}")
    print(f"  Time: {ts}")
    print("=" * 60)

    if not ping_alive():
        print("[!] Switch not reachable")
        sys.exit(1)

    images = get_images()
    print(f"[+] Switch alive, {len(images)} images available")
    if images:
        print(f"    First: {images[0][:40]}...")

    results = []
    crashed = False

    def run(label, func, delay=1.0):
        nonlocal crashed
        if crashed:
            return
        if not ping_alive():
            print(f"  [!] Switch went to sleep — stopping")
            crashed = True
            return
        r = test(label, func, delay)
        results.append(r)
        if not r.get("alive", True):
            crashed = True

    # === Phase 1: Image serving with Range headers ===
    if images:
        img = images[0]
        print(f"\n--- Phase 1: Image Range requests ({img[:30]}...) ---")

        # Normal image fetch (get size)
        run("img HEAD", lambda: raw_http(
            f"HEAD /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        ))

        # Range: first 100 bytes
        run("img Range 0-99", lambda: raw_http(
            f"GET /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nRange: bytes=0-99\r\nConnection: close\r\n\r\n".encode()
        ))

        # Range: last 100 bytes (suffix)
        run("img Range -100", lambda: raw_http(
            f"GET /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nRange: bytes=-100\r\nConnection: close\r\n\r\n".encode()
        ))

        # Range: beyond file size
        run("img Range 999999-9999999", lambda: raw_http(
            f"GET /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nRange: bytes=999999-9999999\r\nConnection: close\r\n\r\n".encode()
        ))

        # Multiple overlapping ranges on image
        run("img 50 ranges", lambda: raw_http(
            f"GET /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nRange: bytes={''.join(f'{i*100}-{i*100+200},' for i in range(50))[:-1]}\r\nConnection: close\r\n\r\n".encode()
        ))

        # Range with SMAX on image file
        run("img Range 0-SMAX", lambda: raw_http(
            f"GET /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nRange: bytes=0-9223372036854775807\r\nConnection: close\r\n\r\n".encode()
        ))

    # === Phase 2: Multiple image requests ===
    if images and not crashed:
        print(f"\n--- Phase 2: Requesting all {len(images)} images ---")
        for i, img in enumerate(images):
            if crashed:
                break
            run(f"img[{i}] GET", lambda img=img: raw_http(
                f"GET /img/{img} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
            ), delay=0.5)

    # === Phase 3: Slow HTTP attacks ===
    if not crashed:
        print(f"\n--- Phase 3: Slow HTTP (Slowloris-style) ---")

        # Slow header send (1 byte every 100ms)
        run("slow header 1B/100ms", lambda: slow_send(
            f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode(),
            chunk_size=1, delay=0.1, timeout=15
        ))

        # Partial request (never finish headers)
        def partial_req():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                sock.connect((SWITCH_IP, 80))
                sock.sendall(b"GET /data.json HTTP/1.1\r\nHost: ")
                time.sleep(5)  # Hold connection open
                sock.close()
            except:
                pass
            return b"", "PARTIAL_SENT"
        run("partial request", partial_req, delay=0.5)

    # === Phase 4: Protocol confusion ===
    if not crashed:
        print(f"\n--- Phase 4: Protocol confusion ---")

        # Send raw binary
        run("raw binary", lambda: raw_http(b"\x00\x01\x02\x03" * 256))

        # TLS ClientHello on HTTP port
        tls_hello = bytes([
            0x16, 0x03, 0x01, 0x00, 0xf1,  # Record: Handshake, TLS 1.0
            0x01, 0x00, 0x00, 0xed,          # ClientHello
            0x03, 0x03,                       # TLS 1.2
        ]) + b"\x00" * 230
        run("TLS on HTTP port", lambda: raw_http(tls_hello))

        # HTTP/2 preface
        h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        run("HTTP/2 preface", lambda: raw_http(h2_preface))

        # WebSocket upgrade
        ws_req = (
            f"GET /data.json HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()
        run("WebSocket upgrade", lambda: raw_http(ws_req))

    # === Phase 5: Heavy concurrent image fetching ===
    if not crashed:
        print(f"\n--- Phase 5: Concurrent image flood ---")

        errors = {"count": 0}
        def fetch_image(img_name):
            try:
                raw_http(
                    f"GET /img/{img_name} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode(),
                    timeout=10
                )
            except:
                errors["count"] += 1

        if images:
            threads = []
            for i in range(min(10, len(images))):
                t = threading.Thread(target=fetch_image, args=(images[i % len(images)],))
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=15)
            time.sleep(1)
            alive = ping_alive()
            print(f"  [10 concurrent images] errors={errors['count']} alive={alive}")
            results.append({"label": "10_concurrent_images", "errors": errors["count"], "alive": alive})
            if not alive:
                crashed = True

    # === Phase 6: Format string in various places ===
    if not crashed:
        print(f"\n--- Phase 6: Format strings ---")
        for payload in ["%s%s%s%s%s%s%s%s%s%s", "%n%n%n%n", "%x" * 50, "AAAA%08x.%08x.%08x.%08x"]:
            run(f"fmt URL '{payload[:20]}'", lambda p=payload: raw_http(
                f"GET /{p} HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
            ), delay=0.5)
            if crashed:
                break
            run(f"fmt Host '{payload[:20]}'", lambda p=payload: raw_http(
                f"GET /data.json HTTP/1.1\r\nHost: {p}\r\nConnection: close\r\n\r\n".encode()
            ), delay=0.5)
            if crashed:
                break

    # === Phase 7: Keep probing while alive ===
    if not crashed:
        print(f"\n--- Phase 7: Extended edge cases ---")

        # Very large number of headers
        hdrs = "".join(f"X-H{i}: {'B' * 200}\r\n" for i in range(200))
        run("200 headers x 200B", lambda: raw_http(
            f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\n{hdrs}Connection: close\r\n\r\n".encode()
        ))

        # POST with form-urlencoded (might parse differently)
        body = "&".join(f"key{i}={'A'*1000}" for i in range(100))
        run("POST form 100KB", lambda: raw_http(
            f"POST /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode()
        ))

        # Multipart form
        boundary = "----WebKitFormBoundaryABCDEFG"
        body = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{'A'*1000}.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n{'B'*10000}\r\n--{boundary}--\r\n"
        run("POST multipart 10KB", lambda: raw_http(
            f"POST /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode()
        ))

        # GET with body (technically valid but unusual)
        run("GET with body 1KB", lambda: raw_http(
            f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{'A'*1024}".encode()
        ))

        # Empty method
        run("empty method", lambda: raw_http(
            f" /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
        ))

        # Method with special chars
        for m in ["GET\x00POST", "G\tET", "GET\r\nX-Inject: evil"]:
            run(f"method '{repr(m)[:20]}'", lambda m=m: raw_http(
                f"{m} /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
            ), delay=0.5)
            if crashed:
                break

    # === Phase 8: Periodic alive check ===
    if not crashed:
        print(f"\n--- Phase 8: Keeping connection alive ---")
        for i in range(60):
            if not ping_alive():
                print(f"  Switch went to sleep after {i * 10}s of idle")
                break
            if i % 6 == 0:
                # Send a keepalive request
                run(f"keepalive #{i//6}", lambda: raw_http(
                    f"GET /data.json HTTP/1.1\r\nHost: {SWITCH_IP}\r\nConnection: close\r\n\r\n".encode()
                ), delay=0.5)
                if crashed:
                    break
            else:
                time.sleep(10)
                sys.stdout.write(".")
                sys.stdout.flush()

    # Save evidence
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "marathon_results.json"
    with open(path, "w") as f:
        json.dump({
            "test": "http_marathon_fuzz",
            "timestamp": ts,
            "results": results,
            "crashed": crashed,
            "total_tests": len(results),
        }, f, indent=2, default=str)
    print(f"\n\nEvidence saved: {path}")

    # Summary
    print("\n" + "=" * 60)
    crashes = [r for r in results if not r.get("alive", True)]
    if crashes:
        print(f"  CRASHES: {len(crashes)}")
        for c in crashes:
            print(f"    {c['label']}: {c.get('status_line', '?')[:60]}")
    else:
        print(f"  No crashes in {len(results)} tests")

    statuses = {}
    for r in results:
        if "status_line" in r:
            s = r["status_line"].split(" ", 2)
            code = s[1] if len(s) > 1 else "?"
        else:
            code = "?"
        statuses.setdefault(code, []).append(r["label"])
    print(f"  Status distribution:")
    for code, labels in sorted(statuses.items()):
        print(f"    {code}: {len(labels)} tests ({', '.join(labels[:3])}{'...' if len(labels) > 3 else ''})")
    print("=" * 60)


if __name__ == "__main__":
    main()
