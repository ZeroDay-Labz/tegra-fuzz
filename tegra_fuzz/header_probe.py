"""Probe whether RCM header fields control the destination copy address.

Sends messages with modified header bytes and traces ptr_36 (the
destination pointer) after each first chunk. If a header byte
changes ptr_36 from the baseline 0x40010D58, we've found a way
to redirect the payload copy to arbitrary IRAM.

Each test requires a fresh RCM session. Runs ONE test per invocation.

Usage:
    sudo python -m tegra_fuzz.header_probe <test_name>

Tests:
    baseline     — normal header (length=0x30298, rest=0), reference trace
    length_min   — length=0x00000008 (minimum possible)
    length_half  — length=0x18000
    off8_ff      — byte 8-11 = 0xFFFFFFFF
    off16_ptr    — bytes 16-19 = 0x40004C30 (SVC handler addr)
    off32_ptr    — bytes 32-35 = 0x40004C30
    off64_ptr    — bytes 64-67 = 0x40004C30
    off128_ptr   — bytes 128-131 = 0x40004C30
    off256_ptr   — bytes 256-259 = 0x40004C30
    off512_ptr   — bytes 512-515 = 0x40004C30
    off1024_ptr  — bytes 1024-1027 = 0x40004C30
    bct_load     — BCT LoadAddress field @ offset 0x18 = 0x40004C00
    all_ff       — first chunk all 0xFF (except length field)
    sweep_N      — set 4 bytes at offset N to 0x40004C30 (N = decimal)
"""
import struct, sys, time, json, os
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000
SVC_HANDLER = 0x40004C30
FORBIDDEN = {(0x00, 0x05)}


def ep0_read(dev):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, 500))
    except Exception:
        return None


def parse_ptr36(data):
    if data and len(data) >= 40:
        return struct.unpack_from('<I', data, 36)[0]
    return None


def parse_remaining(data):
    if data and len(data) >= 64:
        return struct.unpack_from('<I', data, 60)[0]
    return None


def build_header(test_name, chunk_buf):
    """Modify the first chunk (4096 bytes) based on the test."""
    struct.pack_into('<I', chunk_buf, 0, MSG_LEN)

    if test_name == 'baseline':
        pass
    elif test_name == 'length_min':
        struct.pack_into('<I', chunk_buf, 0, 0x00000008)
    elif test_name == 'length_half':
        struct.pack_into('<I', chunk_buf, 0, 0x18000)
    elif test_name == 'off8_ff':
        struct.pack_into('<I', chunk_buf, 8, 0xFFFFFFFF)
    elif test_name == 'off16_ptr':
        struct.pack_into('<I', chunk_buf, 16, SVC_HANDLER)
    elif test_name == 'off32_ptr':
        struct.pack_into('<I', chunk_buf, 32, SVC_HANDLER)
    elif test_name == 'off64_ptr':
        struct.pack_into('<I', chunk_buf, 64, SVC_HANDLER)
    elif test_name == 'off128_ptr':
        struct.pack_into('<I', chunk_buf, 128, SVC_HANDLER)
    elif test_name == 'off256_ptr':
        struct.pack_into('<I', chunk_buf, 256, SVC_HANDLER)
    elif test_name == 'off512_ptr':
        struct.pack_into('<I', chunk_buf, 512, SVC_HANDLER)
    elif test_name == 'off1024_ptr':
        struct.pack_into('<I', chunk_buf, 1024, SVC_HANDLER)
    elif test_name == 'bct_load':
        struct.pack_into('<I', chunk_buf, 0x18, 0x40004C00)
    elif test_name == 'all_ff':
        for i in range(4, CHUNK):
            chunk_buf[i] = 0xFF
    elif test_name.startswith('sweep_'):
        offset = int(test_name.split('_')[1])
        if offset + 4 <= CHUNK:
            struct.pack_into('<I', chunk_buf, offset, SVC_HANDLER)
        else:
            print(f"offset {offset} out of range")
            return False
    else:
        print(f"unknown test: {test_name}")
        return False
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python -m tegra_fuzz.header_probe <test_name>")
        print("Tests: baseline, length_min, length_half, off8_ff, off16_ptr,")
        print("       off32_ptr, off64_ptr, off128_ptr, off256_ptr, off512_ptr,")
        print("       off1024_ptr, bct_load, all_ff, sweep_N")
        return 1

    test_name = sys.argv[1]

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device"); return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # Pre-handshake baseline
    pre = ep0_read(dev)
    pre_ptr36 = parse_ptr36(pre)
    print(f"pre-handshake ptr_36=0x{pre_ptr36:08X}" if pre_ptr36 else "pre: no data", flush=True)

    # Claim
    try:
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        pass

    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"id={did.hex()}", flush=True)
    except Exception as e:
        print(f"id fail: {e}"); return 1

    # Post-claim state
    post_claim = ep0_read(dev)
    pc_ptr36 = parse_ptr36(post_claim)
    print(f"post_claim ptr_36=0x{pc_ptr36:08X}" if pc_ptr36 else "post_claim: no data", flush=True)

    # Build first chunk with test modifications
    chunk0 = bytearray(CHUNK)
    if not build_header(test_name, chunk0):
        return 1

    # Show what we're sending
    print(f"\ntest={test_name}", flush=True)
    print(f"chunk0 header: {chunk0[:64].hex()}", flush=True)

    # Send first chunk
    t0 = time.perf_counter_ns()
    try:
        w = dev.write(0x01, chunk0, timeout=2000)
        t1 = time.perf_counter_ns()
        print(f"chunk0: wrote {w}B in {(t1-t0)/1000:.0f}us", flush=True)
    except usb.core.USBTimeoutError:
        print("chunk0: TIMEOUT"); return 1
    except usb.core.USBError as e:
        print(f"chunk0: {e}"); return 1

    # Read IRAM after first chunk — THE KEY MEASUREMENT
    after0 = ep0_read(dev)
    if after0:
        ptr36 = parse_ptr36(after0)
        remaining = parse_remaining(after0)
        print(f"\n*** ptr_36 after chunk 0: 0x{ptr36:08X} ***", flush=True)
        print(f"    remaining: 0x{remaining:X}", flush=True)
        print(f"    baseline expected: 0x40010D58", flush=True)
        if ptr36 != 0x40010D58:
            print(f"    !!! DIFFERENT FROM BASELINE !!! delta=0x{ptr36 - 0x40010D58:X}", flush=True)
        else:
            print(f"    matches baseline", flush=True)
    else:
        print("EP0 read failed after chunk 0 — bootROM may have rejected early")
        # Try reading response
        try:
            r = bytes(dev.read(0x81, 4096, timeout=3000))
            val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
            print(f"early response: 0x{val:08X}")
        except:
            print("no response either")

    # Send 2 more chunks to watch ptr_36 advance
    for i in range(1, 3):
        chunk = bytearray(CHUNK)  # all zeros
        try:
            w = dev.write(0x01, chunk, timeout=2000)
        except:
            print(f"chunk {i}: write failed")
            break
        after = ep0_read(dev)
        if after:
            ptr = parse_ptr36(after)
            rem = parse_remaining(after)
            print(f"chunk {i}: ptr_36=0x{ptr:08X} remaining=0x{rem:X}", flush=True)

    # Save results
    result = {
        'test': test_name,
        'pre_ptr36': f"0x{pre_ptr36:08X}" if pre_ptr36 else None,
        'post_claim_ptr36': f"0x{pc_ptr36:08X}" if pc_ptr36 else None,
        'chunk0_header': chunk0[:64].hex(),
    }
    if after0:
        result['after_chunk0_ptr36'] = f"0x{parse_ptr36(after0):08X}"
        result['after_chunk0_remaining'] = parse_remaining(after0)
        result['after_chunk0_hex'] = after0[:128].hex()

    outfile = f"findings/header_probe_{test_name}.json"
    os.makedirs("findings", exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nSaved to {outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
