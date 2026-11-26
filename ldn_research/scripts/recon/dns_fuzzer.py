#!/usr/bin/env python3
"""
DNS Response Fuzzer — Craft malformed DNS responses to test the Switch's
DNS parser (NIFM) for buffer overflows.

Replaces dnsmasq as the DNS server. When the Switch queries any domain,
we respond with increasingly malformed DNS responses to probe for crashes.

Attack surface:
- DNS name decompression (classic overflow vector)
- Large TXT/CNAME/MX records
- Many answer/additional records
- Malformed record lengths
- DNS name pointer loops (infinite decompression)

Usage:
    sudo python3 -I dns_fuzzer.py --iface wlp5s0

Requires: AP running (hostapd + DHCP via dnsmasq on a different port or
pre-configured), and dnsmasq stopped (we take over port 53).
"""

import socket
import struct
import signal
import sys
import os
import json
import time
import argparse
import threading
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "dns_fuzz"
AP_IP = "192.168.44.1"
DNS_PORT = 53
HTTP_PORT = 80

CONNTEST_DOMAINS = [
    b"conntest.nintendowifi.net",
    b"ctest.cdn.nintendo.net",
]

evidence = {
    "start_time": None,
    "queries": [],
    "fuzz_results": [],
    "crashes_detected": 0,
}

fuzz_stage = 0
fuzz_cases = []


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def save_evidence():
    path = evidence_dir() / "dns_fuzz_evidence.json"
    ev = dict(evidence)
    with open(path, "w") as f:
        json.dump(ev, f, indent=2, default=str)


def build_dns_name(domain):
    """Encode a domain name in DNS wire format."""
    parts = domain.split(b".")
    result = b""
    for part in parts:
        result += bytes([len(part)]) + part
    result += b"\x00"
    return result


def build_normal_response(query_data, ip=AP_IP):
    """Build a normal DNS A response."""
    # Parse query
    txn_id = query_data[:2]
    # Extract query name
    pos = 12  # skip header
    name_parts = []
    while pos < len(query_data) and query_data[pos] != 0:
        label_len = query_data[pos]
        pos += 1
        name_parts.append(query_data[pos:pos+label_len])
        pos += label_len
    pos += 1  # skip null terminator
    qtype = struct.unpack("!H", query_data[pos:pos+2])[0]
    pos += 4  # skip qtype + qclass

    # Build response header
    # QR=1, AA=1, RCODE=0
    flags = 0x8400
    header = txn_id + struct.pack("!H", flags)
    header += struct.pack("!HHH", 1, 1, 0)  # qdcount=1, ancount=1, nscount=0
    header += struct.pack("!H", 0)  # arcount=0

    # Question section (echo back)
    question = query_data[12:pos]

    # Answer: pointer to name in question + A record
    answer = b"\xc0\x0c"  # pointer to name at offset 12
    answer += struct.pack("!HH", 1, 1)  # type A, class IN
    answer += struct.pack("!I", 300)  # TTL
    ip_bytes = socket.inet_aton(ip)
    answer += struct.pack("!H", 4) + ip_bytes

    return header + question + answer


def build_fuzz_response(query_data, fuzz_type, fuzz_param):
    """Build a fuzzed DNS response based on the fuzz type."""
    txn_id = query_data[:2]

    # Parse query name
    pos = 12
    name_end = pos
    while pos < len(query_data) and query_data[pos] != 0:
        pos += 1 + query_data[pos]
    name_end = pos + 1
    pos = name_end + 4  # skip qtype + qclass

    question = query_data[12:pos]

    if fuzz_type == "oversized_name":
        # Answer with an extremely long name (no compression)
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, 1, 0, 0)

        # Build a name with many long labels
        name = b""
        for i in range(fuzz_param):
            label = bytes([63]) + b"A" * 63
            name += label
        name += b"\x00"

        answer = name
        answer += struct.pack("!HH", 1, 1)  # A, IN
        answer += struct.pack("!I", 300)
        answer += struct.pack("!H", 4) + socket.inet_aton(AP_IP)
        return header + question + answer

    elif fuzz_type == "many_answers":
        # Lots of answer records
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, fuzz_param, 0, 0)

        answers = b""
        for i in range(fuzz_param):
            answers += b"\xc0\x0c"
            answers += struct.pack("!HH", 1, 1)
            answers += struct.pack("!I", 300)
            # Different IPs
            ip_b = socket.inet_aton(f"192.168.44.{(i % 254) + 1}")
            answers += struct.pack("!H", 4) + ip_b
        return header + question + answers

    elif fuzz_type == "large_txt":
        # TXT record with large data
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, 1, 0, 0)

        answer = b"\xc0\x0c"
        answer += struct.pack("!HH", 16, 1)  # TXT, IN
        answer += struct.pack("!I", 300)
        # TXT data: length-prefixed strings
        txt_data = bytes([255]) + b"X" * 255
        txt_data = txt_data * (fuzz_param // 256 + 1)
        txt_data = txt_data[:fuzz_param]
        answer += struct.pack("!H", len(txt_data)) + txt_data
        return header + question + answer

    elif fuzz_type == "compression_loop":
        # DNS name compression pointer that creates a loop
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, 1, 0, 0)

        # Answer name points back to itself
        answer_offset = len(header) + len(question)
        # Create a pointer that points to itself
        ptr = struct.pack("!H", 0xC000 | (answer_offset & 0x3FFF))
        answer = ptr
        answer += struct.pack("!HH", 1, 1)
        answer += struct.pack("!I", 300)
        answer += struct.pack("!H", 4) + socket.inet_aton(AP_IP)
        return header + question + answer

    elif fuzz_type == "negative_rdlength":
        # Answer with RDLENGTH that's larger than remaining data
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, 1, 0, 0)

        answer = b"\xc0\x0c"
        answer += struct.pack("!HH", 1, 1)
        answer += struct.pack("!I", 300)
        # Claim huge RDATA but only provide 4 bytes
        answer += struct.pack("!H", fuzz_param) + socket.inet_aton(AP_IP)
        return header + question + answer

    elif fuzz_type == "cname_chain":
        # Chain of CNAME records
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, fuzz_param + 1, 0, 0)

        answers = b""
        for i in range(fuzz_param):
            answers += b"\xc0\x0c"  # name ptr
            answers += struct.pack("!HH", 5, 1)  # CNAME, IN
            answers += struct.pack("!I", 300)
            cname = build_dns_name(f"c{i}.fuzz.local".encode())
            answers += struct.pack("!H", len(cname)) + cname

        # Final A record
        answers += b"\xc0\x0c"
        answers += struct.pack("!HH", 1, 1)
        answers += struct.pack("!I", 300)
        answers += struct.pack("!H", 4) + socket.inet_aton(AP_IP)
        return header + question + answers

    elif fuzz_type == "many_additional":
        # Many additional records (OPT, etc.)
        flags = 0x8400
        header = txn_id + struct.pack("!H", flags)
        header += struct.pack("!HHHH", 1, 1, 0, fuzz_param)

        # Normal answer
        answer = b"\xc0\x0c"
        answer += struct.pack("!HH", 1, 1)
        answer += struct.pack("!I", 300)
        answer += struct.pack("!H", 4) + socket.inet_aton(AP_IP)

        # Additional records (A records for random names)
        additional = b""
        for i in range(fuzz_param):
            name = build_dns_name(f"extra{i}.local".encode())
            additional += name
            additional += struct.pack("!HH", 1, 1)
            additional += struct.pack("!I", 300)
            ip_b = socket.inet_aton(f"10.0.{i // 256}.{i % 256}")
            additional += struct.pack("!H", 4) + ip_b

        return header + question + answer + additional

    elif fuzz_type == "null_bytes":
        # Normal response with null bytes injected in the name
        resp = build_normal_response(query_data)
        # Insert null bytes at various positions in the answer name
        fuzzed = bytearray(resp)
        for i in range(min(fuzz_param, len(fuzzed) - 20)):
            pos = 12 + (i * 3) % (len(fuzzed) - 12)
            fuzzed[pos] = 0
        return bytes(fuzzed)

    return build_normal_response(query_data)


def define_fuzz_cases():
    """Define all fuzz test cases."""
    cases = []

    # Stage 1: Baseline
    cases.append(("normal", "Normal response (baseline)", "normal", 0))

    # Stage 2: Oversized names
    for n in [4, 8, 16, 32, 64, 127]:
        cases.append(("oversized_name", f"Name with {n}x63-byte labels ({n*64}B)", "oversized_name", n))

    # Stage 3: Many answer records
    for n in [5, 10, 50, 100, 255, 1000]:
        cases.append(("many_answers", f"{n} answer records", "many_answers", n))

    # Stage 4: Large TXT records
    for n in [256, 1024, 4096, 16384, 65535]:
        cases.append(("large_txt", f"TXT record with {n}B data", "large_txt", n))

    # Stage 5: Compression attacks
    cases.append(("compression_loop", "Self-referencing compression pointer", "compression_loop", 0))

    # Stage 6: RDLENGTH mismatches
    for n in [100, 1000, 10000, 65535]:
        cases.append(("negative_rdlength", f"RDLENGTH={n} with 4B data", "negative_rdlength", n))

    # Stage 7: CNAME chains
    for n in [5, 10, 50, 100]:
        cases.append(("cname_chain", f"Chain of {n} CNAMEs", "cname_chain", n))

    # Stage 8: Many additional records
    for n in [10, 50, 100, 255]:
        cases.append(("many_additional", f"{n} additional records", "many_additional", n))

    return cases


class DnsFuzzer:
    def __init__(self, iface):
        self.iface = iface
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((AP_IP, DNS_PORT))
        self.sock.settimeout(1.0)
        self.current_case_idx = 0
        self.cases = define_fuzz_cases()
        self.query_count = 0
        self.last_query_time = 0

    def run(self):
        print(f"[+] DNS Fuzzer listening on {AP_IP}:{DNS_PORT}")
        print(f"[+] {len(self.cases)} fuzz cases defined")
        print()

        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                # Check if Switch stopped querying (possible crash)
                if self.last_query_time > 0:
                    gap = time.time() - self.last_query_time
                    if gap > 10 and self.current_case_idx > 0:
                        print(f"\n  [!] No queries for {gap:.0f}s — possible crash!")
                        print(f"      Last fuzz case: {self.cases[self.current_case_idx - 1][1]}")
                        evidence["fuzz_results"].append({
                            "case_idx": self.current_case_idx - 1,
                            "case_name": self.cases[self.current_case_idx - 1][1],
                            "result": "TIMEOUT",
                            "gap_seconds": gap,
                        })
                        save_evidence()
                continue
            except Exception:
                continue

            self.last_query_time = time.time()
            self.query_count += 1

            # Parse query
            if len(data) < 12:
                continue

            txn_id = struct.unpack("!H", data[:2])[0]
            flags = struct.unpack("!H", data[2:4])[0]

            # Extract queried name
            pos = 12
            name_parts = []
            while pos < len(data) and data[pos] != 0:
                label_len = data[pos]
                if label_len > 63:
                    break
                pos += 1
                name_parts.append(data[pos:pos+label_len].decode("ascii", errors="replace"))
                pos += label_len
            qname = ".".join(name_parts)

            ts = datetime.now(timezone.utc).isoformat()
            evidence["queries"].append({
                "timestamp": ts,
                "client": addr[0],
                "query": qname,
                "txn_id": txn_id,
            })

            # Check if this is a conntest domain — always respond normally
            is_conntest = any(qname.encode() == d for d in CONNTEST_DOMAINS)
            if is_conntest:
                resp = build_normal_response(data)
                self.sock.sendto(resp, addr)
                print(f"  [CONNTEST] {qname} → {AP_IP} (normal)")
                continue

            # Pick the current fuzz case
            if self.current_case_idx >= len(self.cases):
                # All cases done, respond normally
                resp = build_normal_response(data)
                self.sock.sendto(resp, addr)
                print(f"  [DONE] {qname} → normal (all cases tested)")
                continue

            case = self.cases[self.current_case_idx]
            case_type, case_desc, fuzz_type, fuzz_param = case

            print(f"\n  [FUZZ #{self.current_case_idx}] {case_desc}")
            print(f"          Query: {qname} from {addr[0]}")

            if fuzz_type == "normal":
                resp = build_normal_response(data)
            else:
                try:
                    resp = build_fuzz_response(data, fuzz_type, fuzz_param)
                except Exception as e:
                    print(f"          Build error: {e}")
                    resp = build_normal_response(data)

            resp_len = len(resp)
            # Truncate to UDP max if needed (but test oversized too)
            if resp_len > 65507:
                resp = resp[:65507]
                resp_len = 65507

            try:
                self.sock.sendto(resp, addr)
                print(f"          Sent {resp_len}B fuzzed response")
            except Exception as e:
                print(f"          Send error: {e}")

            evidence["fuzz_results"].append({
                "case_idx": self.current_case_idx,
                "case_name": case_desc,
                "query": qname,
                "response_size": resp_len,
                "result": "SENT",
                "timestamp": ts,
            })

            self.current_case_idx += 1
            save_evidence()


def run_http_conntest():
    """Minimal HTTP server for connectivity test."""
    import http.server
    import socketserver

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Organization", "Nintendo")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("0.0.0.0", HTTP_PORT), Handler)
    srv.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="wlp5s0")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)

    evidence["start_time"] = datetime.now(timezone.utc).isoformat()

    def cleanup(*a):
        print(f"\n[*] DNS Fuzzer stats:")
        print(f"  Queries received: {fuzzer.query_count}")
        print(f"  Fuzz cases sent: {fuzzer.current_case_idx}")
        print(f"  Crashes detected: {evidence['crashes_detected']}")
        evidence["end_time"] = datetime.now(timezone.utc).isoformat()
        save_evidence()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("=" * 60)
    print("  DNS RESPONSE FUZZER — NIFM DNS Parser Testing")
    print("=" * 60)

    # Start HTTP for conntest
    print("[*] Starting HTTP conntest server...")
    http_thread = threading.Thread(target=run_http_conntest, daemon=True)
    http_thread.start()

    # We need dnsmasq stopped on this interface for us to bind port 53
    # Check if we can bind
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        test_sock.bind((AP_IP, DNS_PORT))
        test_sock.close()
    except OSError as e:
        print(f"[!] Cannot bind {AP_IP}:{DNS_PORT}: {e}")
        print(f"[!] Kill dnsmasq first: sudo pkill -f 'dnsmasq.*mitm'")
        sys.exit(1)

    fuzzer = DnsFuzzer(args.iface)

    print()
    print("  The Switch should be connected to our AP.")
    print("  Each DNS query gets a different fuzzed response.")
    print("  If the Switch stops querying, we may have crashed NIFM.")
    print()
    print("  TIP: Navigate menus on the Switch to trigger DNS queries:")
    print("    - Open eShop (triggers many lookups)")
    print("    - Check for updates")
    print("    - Open News")
    print()

    fuzzer.run()


if __name__ == "__main__":
    main()
