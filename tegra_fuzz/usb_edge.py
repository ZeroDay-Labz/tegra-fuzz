"""USB transfer edge-case testing for IPATCH bypass research.

Tests whether the bootROM's IPATCH correctly handles all USB transfer
termination patterns. The original CVE-2018-6242 exploited short-packet
termination to desync the declared vs actual transfer size.

SAFETY: Never sends SET_ADDRESS. All tests are read-after-write.

Usage:
    sudo python -m tegra_fuzz.usb_edge <case>

Cases:
    partial_48    — Send 48 of 49 chunks, then read (missing last chunk)
    partial_1     — Send only first chunk, then read
    short_last    — Send 48 chunks + unpadded last (664B instead of 4096B)
    double_send   — Send full message, then immediately send another chunk
    interleave_ep0 — Send 24 chunks, do EP0 read, send remaining 25
    zlp_after     — Send all 49 chunks + zero-length packet
    tiny_first    — Send 1-byte first write, then normal chunks
    split_header  — Send 512B first write (header only), then rest
"""
import struct, sys, time, json, os
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000

FORBIDDEN = {(0x00, 0x05)}


def build_msg(fill=0x00):
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0, MSG_LEN)
    if fill:
        for i in range(4, MSG_LEN):
            msg[i] = fill
    return msg


def init_device():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return None
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # EP0 pre-handshake IRAM read
    try:
        leak = bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, 1000))
        print(f"ep0_leak={len(leak)}B", flush=True)
    except Exception as e:
        print(f"ep0_leak={e}", flush=True)

    # Claim
    try:
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError as exc:
        print(f"claim={exc}", flush=True)

    # Device ID
    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"id={did.hex()}", flush=True)
    except Exception as e:
        print(f"id fail: {e}")
        return None

    return dev


def write_chunks(dev, msg, count, pad_last=True, timeout=2000):
    total = 0
    for i in range(count):
        start = i * CHUNK
        end = min(start + CHUNK, len(msg))
        chunk = msg[start:end]
        if pad_last and len(chunk) < CHUNK:
            chunk = chunk + b'\x00' * (CHUNK - len(chunk))
        elif not pad_last and i == count - 1:
            pass  # send unpadded
        try:
            w = dev.write(0x01, chunk, timeout=timeout)
            total += w
            if i < 3 or i >= count - 2:
                print(f"  chunk[{i}]={w}B (total={total})", flush=True)
            elif i == 3:
                print(f"  ... (chunks 3-{count-3})", flush=True)
        except usb.core.USBTimeoutError:
            print(f"  chunk[{i}]=TIMEOUT (total={total})", flush=True)
            return total, 'timeout'
        except usb.core.USBError as e:
            print(f"  chunk[{i}]={e} (total={total})", flush=True)
            return total, str(e)
    return total, 'ok'


def read_response(dev, timeout=5000):
    t0 = time.perf_counter_ns()
    try:
        r = bytes(dev.read(0x81, 4096, timeout=timeout))
        t1 = time.perf_counter_ns()
        us = (t1 - t0) / 1000
        if len(r) >= 4:
            val = struct.unpack_from('<I', r, 0)[0]
            print(f"resp={len(r)}B status=0x{val:08X} wait={us:.0f}us", flush=True)
            return {'len': len(r), 'status': val, 'hex': r.hex(), 'wait_us': us}
        else:
            print(f"resp={len(r)}B hex={r.hex()} wait={us:.0f}us", flush=True)
            return {'len': len(r), 'hex': r.hex(), 'wait_us': us}
    except usb.core.USBTimeoutError:
        t1 = time.perf_counter_ns()
        us = (t1 - t0) / 1000
        print(f"resp=TIMEOUT wait={us:.0f}us", flush=True)
        return {'status': 'timeout', 'wait_us': us}
    except usb.core.USBError as e:
        print(f"resp={e}", flush=True)
        return {'status': str(e)}


def ep0_read(dev, timeout=1000):
    try:
        d = bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
        return d
    except Exception:
        return None


def case_partial_48(dev):
    """Send 48 of 49 chunks — does bootROM timeout waiting for last chunk?"""
    print("\n=== partial_48: 48/49 chunks ===", flush=True)
    msg = build_msg()
    total, status = write_chunks(dev, msg, 48)
    print(f"wrote {total}B status={status}", flush=True)
    return read_response(dev, timeout=5000)


def case_partial_1(dev):
    """Send only first chunk — bootROM sees length=0x30298, only gets 4096B"""
    print("\n=== partial_1: 1/49 chunks ===", flush=True)
    msg = build_msg()
    total, status = write_chunks(dev, msg, 1)
    print(f"wrote {total}B status={status}", flush=True)
    return read_response(dev, timeout=5000)


def case_short_last(dev):
    """Send 48 padded chunks + unpadded last chunk (664B instead of 4096B)"""
    print("\n=== short_last: 48 full + 1 short ===", flush=True)
    msg = build_msg()
    # Send first 48 chunks padded
    total, status = write_chunks(dev, msg, 48)
    if status != 'ok':
        return {'error': status}
    # Send last chunk unpadded (remaining 0x298 = 664 bytes)
    last_start = 48 * CHUNK
    last_data = msg[last_start:]
    print(f"  last chunk raw size={len(last_data)}B", flush=True)
    try:
        w = dev.write(0x01, bytes(last_data), timeout=2000)
        total += w
        print(f"  chunk[48]={w}B (total={total})", flush=True)
    except usb.core.USBTimeoutError:
        print(f"  chunk[48]=TIMEOUT (total={total})", flush=True)
        return {'error': 'last_chunk_timeout', 'total': total}
    except usb.core.USBError as e:
        print(f"  chunk[48]={e} (total={total})", flush=True)
        return {'error': str(e), 'total': total}
    return read_response(dev)


def case_double_send(dev):
    """Send full message, read response, then try sending another chunk"""
    print("\n=== double_send: full msg + extra chunk ===", flush=True)
    msg = build_msg()
    n_chunks = (MSG_LEN + CHUNK - 1) // CHUNK
    total, status = write_chunks(dev, msg, n_chunks)
    print(f"wrote {total}B status={status}", flush=True)
    resp = read_response(dev)
    # Try sending more data after response
    print("  trying extra write...", flush=True)
    try:
        extra = b'\x41' * CHUNK
        w = dev.write(0x01, extra, timeout=2000)
        print(f"  extra write={w}B", flush=True)
        resp['extra_write'] = w
    except usb.core.USBTimeoutError:
        print(f"  extra write=TIMEOUT", flush=True)
        resp['extra_write'] = 'timeout'
    except usb.core.USBError as e:
        print(f"  extra write={e}", flush=True)
        resp['extra_write'] = str(e)
    # Try reading again
    resp2 = read_response(dev, timeout=2000)
    resp['second_read'] = resp2
    return resp


def case_interleave_ep0(dev):
    """Send 24 chunks, do EP0 IRAM read mid-transfer, send remaining 25"""
    print("\n=== interleave_ep0: 24 chunks → EP0 → 25 chunks ===", flush=True)
    msg = build_msg(fill=0xBB)
    total, status = write_chunks(dev, msg, 24)
    if status != 'ok':
        return {'error': status, 'phase': 'first_half'}
    print(f"  first half: {total}B", flush=True)

    # Mid-transfer EP0 read — does bootROM still respond?
    print("  EP0 mid-transfer read...", flush=True)
    leak = ep0_read(dev)
    if leak:
        print(f"  EP0 mid={len(leak)}B", flush=True)
    else:
        print(f"  EP0 mid=FAIL", flush=True)

    # Send remaining chunks
    remaining_msg = msg[24 * CHUNK:]
    remaining_padded = bytearray()
    n_remaining = (len(remaining_msg) + CHUNK - 1) // CHUNK
    for i in range(n_remaining):
        start = i * CHUNK
        end = min(start + CHUNK, len(remaining_msg))
        chunk = remaining_msg[start:end]
        if len(chunk) < CHUNK:
            chunk = chunk + b'\x00' * (CHUNK - len(chunk))
        remaining_padded.extend(chunk)

    total2, status2 = write_chunks(dev, bytes(remaining_padded), n_remaining)
    total += total2
    print(f"  total: {total}B status={status2}", flush=True)
    resp = read_response(dev)
    resp['mid_ep0'] = len(leak) if leak else None
    return resp


def case_zlp_after(dev):
    """Send all 49 chunks + zero-length packet"""
    print("\n=== zlp_after: full msg + ZLP ===", flush=True)
    msg = build_msg()
    n_chunks = (MSG_LEN + CHUNK - 1) // CHUNK
    total, status = write_chunks(dev, msg, n_chunks)
    print(f"wrote {total}B status={status}", flush=True)
    # Send ZLP
    try:
        w = dev.write(0x01, b'', timeout=2000)
        print(f"  ZLP={w}B", flush=True)
    except usb.core.USBTimeoutError:
        print(f"  ZLP=TIMEOUT", flush=True)
    except usb.core.USBError as e:
        print(f"  ZLP={e}", flush=True)
    return read_response(dev)


def case_tiny_first(dev):
    """Send 1-byte first write (contains only byte 0 of length), then normal"""
    print("\n=== tiny_first: 1B + rest ===", flush=True)
    msg = build_msg()
    # Send just 1 byte
    try:
        w = dev.write(0x01, msg[0:1], timeout=2000)
        print(f"  tiny={w}B", flush=True)
    except usb.core.USBTimeoutError:
        print(f"  tiny=TIMEOUT", flush=True)
        return read_response(dev, timeout=3000)
    except usb.core.USBError as e:
        print(f"  tiny={e}", flush=True)
        return {'error': str(e)}
    # Try reading — does the 1-byte short packet terminate the transfer?
    return read_response(dev, timeout=3000)


def case_split_header(dev):
    """Send 512B first write (one max packet with header), then rest normally"""
    print("\n=== split_header: 512B header + rest ===", flush=True)
    msg = build_msg()
    # Send 512 bytes (one max packet size)
    try:
        w = dev.write(0x01, msg[0:512], timeout=2000)
        print(f"  header={w}B", flush=True)
    except usb.core.USBTimeoutError:
        print(f"  header=TIMEOUT", flush=True)
        return read_response(dev, timeout=3000)
    except usb.core.USBError as e:
        print(f"  header={e}", flush=True)
        return {'error': str(e)}
    # Try reading immediately
    return read_response(dev, timeout=3000)


CASES = {
    'partial_48': case_partial_48,
    'partial_1': case_partial_1,
    'short_last': case_short_last,
    'double_send': case_double_send,
    'interleave_ep0': case_interleave_ep0,
    'zlp_after': case_zlp_after,
    'tiny_first': case_tiny_first,
    'split_header': case_split_header,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CASES:
        print(f"Usage: sudo python -m tegra_fuzz.usb_edge <case>")
        print(f"Cases: {', '.join(CASES.keys())}")
        return 1

    case = sys.argv[1]
    print(f"case={case}", flush=True)

    dev = init_device()
    if not dev:
        return 1

    result = CASES[case](dev)

    # Check if device survived
    alive = usb.core.find(idVendor=VID, idProduct=PID) is not None
    print(f"alive={alive}", flush=True)
    if result:
        result['alive'] = alive

    outfile = f"findings/edge_{case}.json"
    os.makedirs("findings", exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"Saved to {outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
