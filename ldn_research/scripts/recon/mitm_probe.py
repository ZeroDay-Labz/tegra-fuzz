#!/usr/bin/env python3
"""
MITM Network Probe — Pass Nintendo's connectivity test, then intercept
all HTTP traffic from the Switch to find injectable endpoints.

We control DNS (via dnsmasq wildcard) so ALL domains resolve to us.
For the connectivity test, we return the expected response.
For everything else, we log the request and return a plausible response.

This reveals what HTTP endpoints the Switch contacts and whether any
are exploitable (unencrypted, no cert pinning, etc.)

Usage:
    sudo python3 -I mitm_probe.py --iface wlp5s0

The Switch should already be connected or will connect to our AP.
"""

import subprocess
import tempfile
import signal
import sys
import os
import json
import ssl
import time
import argparse
import http.server
import socketserver
import threading
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "mitm_probe"
AP_IP = "192.168.44.1"
HTTP_PORT = 80
HTTPS_PORT = 443

NINTENDO_CONNTEST_HOSTS = [
    "conntest.nintendowifi.net",
    "ctest.cdn.nintendo.net",
]

procs = []
tmpfiles = []
evidence = {
    "start_time": None,
    "http_requests": [],
    "https_attempts": [],
    "dns_queries": [],
    "user_agents": [],
    "unique_hosts": set(),
    "unique_paths": set(),
}


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def cleanup(*args):
    print("\n[*] Cleaning up...")
    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    for f in tmpfiles:
        try:
            os.unlink(f)
        except Exception:
            pass

    # Save evidence
    evidence["end_time"] = datetime.now(timezone.utc).isoformat()
    evidence["unique_hosts"] = sorted(evidence["unique_hosts"])
    evidence["unique_paths"] = sorted(evidence["unique_paths"])
    evidence["summary"] = {
        "total_http_requests": len(evidence["http_requests"]),
        "total_https_attempts": len(evidence["https_attempts"]),
        "unique_hosts": len(evidence["unique_hosts"]),
        "unique_user_agents": evidence["user_agents"],
    }
    path = evidence_dir() / "mitm_evidence.json"
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, default=list)
    print(f"[*] Evidence saved to {path}")

    print("\n[*] Summary:")
    print(f"  HTTP requests: {len(evidence['http_requests'])}")
    print(f"  HTTPS attempts: {len(evidence['https_attempts'])}")
    print(f"  Unique hosts: {len(evidence['unique_hosts'])}")
    print(f"  User agents: {evidence['user_agents']}")
    print(f"\n  Hosts contacted:")
    for h in sorted(evidence["unique_hosts"]):
        print(f"    {h}")

    sys.exit(0)


class MitmHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _record(self, method):
        ts = datetime.now(timezone.utc).isoformat()
        host = self.headers.get("Host", "unknown")
        ua = self.headers.get("User-Agent", "")
        path = self.path

        entry = {
            "timestamp": ts,
            "client": self.client_address[0],
            "method": method,
            "host": host,
            "path": path,
            "user_agent": ua,
            "headers": dict(self.headers),
        }
        evidence["http_requests"].append(entry)
        evidence["unique_hosts"].add(host)
        evidence["unique_paths"].add(f"{host}{path}")

        if ua and ua not in evidence["user_agents"]:
            evidence["user_agents"].append(ua)
            print(f"\n  {'!'*40}")
            print(f"  NEW USER-AGENT: {ua}")
            print(f"  {'!'*40}\n")

        # Color-code output
        is_conntest = any(h in host for h in NINTENDO_CONNTEST_HOSTS)
        prefix = "  [CONNTEST]" if is_conntest else "  [REQUEST] "
        print(f"{prefix} {method} http://{host}{path}")
        print(f"           UA: {ua[:80]}")
        for k, v in self.headers.items():
            if k.lower() not in ("host", "user-agent", "accept"):
                print(f"           {k}: {v[:100]}")

        return host, path, ua

    def do_GET(self):
        host, path, ua = self._record("GET")

        # Nintendo connectivity test — return expected "ok" response
        is_conntest = any(h in host for h in NINTENDO_CONNTEST_HOSTS)
        if is_conntest:
            print(f"  → Passing connectivity test (returning expected response)")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Organization", "Nintendo")
            content = b"ok"
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # For everything else, log and return a generic response
        print(f"  → Serving generic response for {host}{path}")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        content = b"<html><body>OK</body></html>"
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        host, path, ua = self._record("POST")
        content_length = int(self.headers.get("Content-Length", 0))
        body = b""
        if content_length > 0:
            body = self.rfile.read(min(content_length, 65536))

        entry = evidence["http_requests"][-1]
        entry["body_size"] = content_length
        entry["body_preview"] = body[:2000].hex()

        print(f"  → POST body: {content_length} bytes")
        if content_length < 500:
            print(f"     Hex: {body[:200].hex()}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        resp = b'{"status":"ok"}'
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_HEAD(self):
        host, path, ua = self._record("HEAD")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_CONNECT(self):
        """HTTPS CONNECT tunnel request — log the attempt."""
        ts = datetime.now(timezone.utc).isoformat()
        host = self.path
        print(f"\n  [HTTPS!] CONNECT {host} from {self.client_address[0]}")
        evidence["https_attempts"].append({
            "timestamp": ts,
            "client": self.client_address[0],
            "target": host,
        })
        evidence["unique_hosts"].add(host.split(":")[0])

        # We can't actually MITM HTTPS without certs, just log it
        self.send_error(502, "Bad Gateway")


def dns_monitor(iface):
    """Monitor DNS queries via tcpdump in background."""
    pcap_path = str(evidence_dir() / "dns_capture.pcap")
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", pcap_path, "-U", "port", "53"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    procs.append(proc)
    return proc


def tcp_monitor(iface):
    """Monitor ALL TCP connections to see HTTPS attempts."""
    pcap_path = str(evidence_dir() / "tcp_capture.pcap")
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", pcap_path, "-U",
         "tcp and not port 53"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    procs.append(proc)
    return proc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="wlp5s0")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)

    evidence["start_time"] = datetime.now(timezone.utc).isoformat()

    signal.signal(signal.SIGINT, lambda s, f: cleanup(args.iface))
    signal.signal(signal.SIGTERM, lambda s, f: cleanup(args.iface))

    print("=" * 60)
    print("  MITM PROBE — Nintendo Switch Network Traffic Intercept")
    print("=" * 60)
    print(f"  Interface: {args.iface}")
    print(f"  AP IP: {AP_IP}")
    print(f"  Strategy: Pass conntest, intercept everything else")
    print("=" * 60)

    # Check if AP is already running
    rc, out, _ = subprocess.run(
        f"ip addr show {args.iface}",
        shell=True, capture_output=True, text=True
    ).returncode, "", ""
    out = subprocess.run(f"ip addr show {args.iface}",
                         shell=True, capture_output=True, text=True).stdout
    if AP_IP not in out:
        print(f"[!] AP not running on {args.iface} ({AP_IP} not found)")
        print(f"    Start the captive portal first, or set up the AP manually")
        sys.exit(1)

    # Start monitors
    print("[*] Starting DNS monitor...")
    dns_monitor(args.iface)

    print("[*] Starting TCP monitor...")
    tcp_monitor(args.iface)

    # Start HTTP server
    print(f"[*] Starting HTTP server on port {HTTP_PORT}...")
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("0.0.0.0", HTTP_PORT), MitmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] HTTP server listening on 0.0.0.0:{HTTP_PORT}")

    # Also listen on port 443 as a plain TCP to detect HTTPS attempts
    print(f"[*] Starting HTTPS detector on port {HTTPS_PORT}...")
    try:
        https_sock = socketserver.TCPServer(("0.0.0.0", HTTPS_PORT), MitmHandler)
        https_thread = threading.Thread(target=https_sock.serve_forever, daemon=True)
        https_thread.start()
        print(f"[+] HTTPS detector on 0.0.0.0:{HTTPS_PORT}")
    except OSError as e:
        print(f"[!] Could not bind port {HTTPS_PORT}: {e}")

    print()
    print("=" * 60)
    print("  READY — Connect the Switch to our AP")
    print("  Connectivity test will PASS (Switch thinks it has internet)")
    print("  ALL HTTP traffic will be logged")
    print("  HTTPS attempts will be detected (can't decrypt)")
    print()
    print("  TIP: Navigate menus on the Switch that use network:")
    print("    - eShop (don't buy anything)")
    print("    - News")
    print("    - User icon sync")
    print("    - Game updates check")
    print("  Each generates traffic we can analyze.")
    print("=" * 60)
    print()

    # Monitor loop
    try:
        last_count = 0
        while True:
            time.sleep(5)
            count = len(evidence["http_requests"])
            if count > last_count:
                # Auto-save periodically
                ev_copy = dict(evidence)
                ev_copy["unique_hosts"] = sorted(ev_copy["unique_hosts"])
                ev_copy["unique_paths"] = sorted(ev_copy["unique_paths"])
                path = evidence_dir() / "mitm_evidence.json"
                with open(path, "w") as f:
                    json.dump(ev_copy, f, indent=2, default=list)
                last_count = count
    except KeyboardInterrupt:
        pass

    cleanup(args.iface)


if __name__ == "__main__":
    main()
