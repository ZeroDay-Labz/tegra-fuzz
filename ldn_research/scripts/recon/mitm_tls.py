#!/usr/bin/env python3
"""
TLS MITM Probe — Present a self-signed cert to the Switch and see if it
accepts it or rejects it. If it accepts, we can decrypt all HTTPS traffic.

Also handles the HTTP connectivity test on port 80.

Usage:
    sudo python3 -I mitm_tls.py --iface wlp5s0 \
        --cert /path/to/mitm.crt --key /path/to/mitm.key
"""

import subprocess
import signal
import sys
import os
import json
import ssl
import socket
import time
import argparse
import http.server
import socketserver
import threading
import struct
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "mitm_probe"
AP_IP = "192.168.44.1"

NINTENDO_CONNTEST_HOSTS = [
    "conntest.nintendowifi.net",
    "ctest.cdn.nintendo.net",
]

evidence = {
    "start_time": None,
    "http_requests": [],
    "tls_connections": [],
    "tls_decrypted_requests": [],
    "cert_rejections": 0,
    "cert_acceptances": 0,
}


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def save_evidence():
    path = evidence_dir() / "mitm_tls_evidence.json"
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)


class HttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        host = self.headers.get("Host", "unknown")
        ua = self.headers.get("User-Agent", "")
        ts = datetime.now(timezone.utc).isoformat()

        entry = {
            "timestamp": ts,
            "client": self.client_address[0],
            "tls": hasattr(self.connection, "getpeercert"),
            "method": "GET",
            "host": host,
            "path": self.path,
            "user_agent": ua,
            "headers": dict(self.headers),
        }

        is_tls = entry["tls"]
        prefix = "[HTTPS]" if is_tls else "[HTTP] "
        print(f"  {prefix} GET http{'s' if is_tls else ''}://{host}{self.path}")
        print(f"          UA: {ua}")

        if is_tls:
            evidence["tls_decrypted_requests"].append(entry)
            print(f"\n  {'!'*50}")
            print(f"  DECRYPTED HTTPS REQUEST!")
            print(f"  Host: {host}")
            print(f"  Path: {self.path}")
            print(f"  UA: {ua}")
            print(f"  Headers: {dict(self.headers)}")
            print(f"  {'!'*50}\n")
        else:
            evidence["http_requests"].append(entry)

        # Connectivity test
        is_conntest = any(h in host for h in NINTENDO_CONNTEST_HOSTS)
        if is_conntest:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Organization", "Nintendo")
            content = b"ok"
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        content = b"<html><body>OK</body></html>"
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        host = self.headers.get("Host", "unknown")
        ua = self.headers.get("User-Agent", "")
        ts = datetime.now(timezone.utc).isoformat()
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(min(content_length, 65536)) if content_length > 0 else b""

        is_tls = hasattr(self.connection, "getpeercert")
        entry = {
            "timestamp": ts,
            "client": self.client_address[0],
            "tls": is_tls,
            "method": "POST",
            "host": host,
            "path": self.path,
            "user_agent": ua,
            "headers": dict(self.headers),
            "body_size": content_length,
            "body_hex": body[:2000].hex(),
        }

        prefix = "[HTTPS]" if is_tls else "[HTTP] "
        print(f"  {prefix} POST http{'s' if is_tls else ''}://{host}{self.path} ({content_length}B)")
        print(f"          UA: {ua}")

        if is_tls:
            evidence["tls_decrypted_requests"].append(entry)
            print(f"\n  {'!'*50}")
            print(f"  DECRYPTED HTTPS POST!")
            print(f"  Body ({content_length}B): {body[:200]}")
            print(f"  {'!'*50}\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        resp = b'{"status":"ok"}'
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def parse_sni(data):
    """Extract SNI from TLS ClientHello."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        # Skip record header (5 bytes) + handshake header (4 bytes)
        # + client version (2) + random (32) + session_id
        pos = 5 + 4 + 2 + 32
        if pos >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(data):
            return None
        cipher_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2 + cipher_len
        if pos >= len(data):
            return None
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return None
        ext_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            ext_type = struct.unpack("!H", data[pos:pos+2])[0]
            ext_data_len = struct.unpack("!H", data[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0:  # SNI
                if pos + 5 <= len(data):
                    sni_list_len = struct.unpack("!H", data[pos:pos+2])[0]
                    sni_type = data[pos+2]
                    sni_len = struct.unpack("!H", data[pos+3:pos+5])[0]
                    if pos + 5 + sni_len <= len(data):
                        return data[pos+5:pos+5+sni_len].decode("ascii", errors="replace")
            pos += ext_data_len
    except Exception:
        pass
    return None


def tls_proxy(cert_file, key_file):
    """Accept TLS connections, present our cert, proxy to log."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    # Allow all protocols the Switch supports
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 443))
    sock.listen(5)
    sock.settimeout(1.0)

    print(f"[+] TLS proxy listening on 0.0.0.0:443")

    while True:
        try:
            client, addr = sock.accept()
        except socket.timeout:
            continue
        except Exception:
            continue

        threading.Thread(target=handle_tls_client,
                         args=(client, addr, ctx),
                         daemon=True).start()


def handle_tls_client(client, addr, ctx):
    """Handle one TLS client connection."""
    ts = datetime.now(timezone.utc).isoformat()
    print(f"\n  [TLS] Connection from {addr[0]}:{addr[1]}")

    # Peek at the ClientHello to get SNI
    try:
        data = client.recv(4096, socket.MSG_PEEK)
        sni = parse_sni(data)
        if sni:
            print(f"  [TLS] SNI: {sni}")
    except Exception:
        sni = "unknown"

    # Try TLS handshake
    try:
        tls_client = ctx.wrap_socket(client, server_side=True)
        evidence["cert_acceptances"] += 1
        tls_version = tls_client.version()
        cipher = tls_client.cipher()

        print(f"\n  {'*'*60}")
        print(f"  CERT ACCEPTED! TLS handshake succeeded!")
        print(f"  SNI: {sni}")
        print(f"  TLS Version: {tls_version}")
        print(f"  Cipher: {cipher}")
        print(f"  {'*'*60}\n")

        entry = {
            "timestamp": ts,
            "client": addr[0],
            "sni": sni,
            "result": "ACCEPTED",
            "tls_version": tls_version,
            "cipher": str(cipher),
        }
        evidence["tls_connections"].append(entry)
        save_evidence()

        # Now handle the HTTP request over TLS
        try:
            request_data = tls_client.recv(8192)
            if request_data:
                entry["request_data"] = request_data[:2000].decode("utf-8", errors="replace")
                print(f"  [TLS] Request: {request_data[:500]}")

                # Send a basic HTTP response
                response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nOK"
                tls_client.send(response)
        except Exception as e:
            print(f"  [TLS] Request read error: {e}")

        tls_client.close()

    except ssl.SSLError as e:
        evidence["cert_rejections"] += 1
        reason = str(e)

        # Categorize the rejection
        if "alert" in reason.lower():
            if "unknown_ca" in reason.lower() or "unknown ca" in reason.lower():
                rejection_type = "UNKNOWN_CA"
            elif "certificate" in reason.lower():
                rejection_type = "CERT_REJECTED"
            elif "handshake" in reason.lower():
                rejection_type = "HANDSHAKE_FAILURE"
            else:
                rejection_type = "TLS_ALERT"
        else:
            rejection_type = "SSL_ERROR"

        print(f"  [TLS] CERT REJECTED: {rejection_type}")
        print(f"         Reason: {reason[:200]}")

        entry = {
            "timestamp": ts,
            "client": addr[0],
            "sni": sni,
            "result": "REJECTED",
            "rejection_type": rejection_type,
            "error": reason[:500],
        }
        evidence["tls_connections"].append(entry)
        save_evidence()

        client.close()

    except Exception as e:
        print(f"  [TLS] Error: {e}")
        try:
            client.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="wlp5s0")
    parser.add_argument("--cert", required=True, help="Path to self-signed cert")
    parser.add_argument("--key", required=True, help="Path to private key")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)

    evidence["start_time"] = datetime.now(timezone.utc).isoformat()

    print("=" * 60)
    print("  TLS MITM PROBE — Certificate Acceptance Test")
    print("=" * 60)
    print(f"  Cert: {args.cert}")
    print(f"  Key: {args.key}")
    print(f"  Testing: Will the Switch accept our self-signed cert?")
    print("=" * 60)

    # Start HTTP server on port 80 (for conntest)
    print("[*] Starting HTTP server on port 80...")
    socketserver.TCPServer.allow_reuse_address = True
    http_server = socketserver.TCPServer(("0.0.0.0", 80), HttpHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    # Start TLS proxy on port 443
    print("[*] Starting TLS proxy on port 443...")
    tls_thread = threading.Thread(target=tls_proxy,
                                   args=(args.cert, args.key),
                                   daemon=True)
    tls_thread.start()

    print()
    print("[*] Waiting for Switch connections...")
    print("    Acceptances: cert pinning is BROKEN → full MITM possible")
    print("    Rejections:  cert pinning works → need different approach")
    print()

    def cleanup(*a):
        print("\n[*] Final stats:")
        print(f"  Cert acceptances: {evidence['cert_acceptances']}")
        print(f"  Cert rejections:  {evidence['cert_rejections']}")
        evidence["end_time"] = datetime.now(timezone.utc).isoformat()
        save_evidence()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True:
            time.sleep(5)
            save_evidence()
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
