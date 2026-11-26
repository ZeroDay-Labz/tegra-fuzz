"""Timing analysis of bootROM signature verification.

Sends 0x30298-byte RCM messages with different content patterns
and measures the response time with high precision. If the RSA-PSS
verification processes data sequentially, timing differences could
leak information about the expected signature.

REQUIRES: One fresh RCM session per message. Run each test case
with a fresh RCM boot.

Usage:
    sudo python -m tegra_fuzz.timing <case>

Cases:
    zeros        — All-zero body (baseline timing)
    ones         — All-0xFF body
    sig_ff       — 0xFF in signature field (offset 0x94-0x293), zeros elsewhere
    sig_valid_e  — Public exponent 0x10001 at signature offset
    half_sig     — First half of sig field 0xFF, second half 0x00
    random       — Random body (crypto.getrandbits)
"""
import struct, sys, time, os, json
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000

# RCM header offsets (from ShofEL2)
SIG_START = 0x94
SIG_END = 0x294
RANDOM_START = 0x294
RANDOM_END = 0x2A4
PAYLOAD_START = 0x2A4


def build_message(case):
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0, MSG_LEN)

    if case == 'zeros':
        pass
    elif case == 'ones':
        for i in range(4, MSG_LEN):
            msg[i] = 0xFF
    elif case == 'sig_ff':
        for i in range(SIG_START, SIG_END):
            msg[i] = 0xFF
    elif case == 'sig_valid_e':
        # Place RSA public exponent at start of sig field
        struct.pack_into('>I', msg, SIG_START, 0x00010001)
    elif case == 'half_sig':
        half = (SIG_END - SIG_START) // 2
        for i in range(SIG_START, SIG_START + half):
            msg[i] = 0xFF
    elif case == 'random':
        import random
        random.seed(42)
        for i in range(4, MSG_LEN):
            msg[i] = random.randint(0, 255)
    else:
        print(f"unknown case: {case}")
        return None

    return bytes(msg)


def run_timing(case):
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return None
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # EP0 init
    try:
        bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 128, 1000))
    except Exception:
        pass

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

    # Device ID
    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"id={did.hex()}", flush=True)
    except Exception as e:
        print(f"id failed: {e}")
        return None

    msg = build_message(case)
    if not msg:
        return None

    # Send all chunks
    n_chunks = (MSG_LEN + CHUNK - 1) // CHUNK
    total = 0
    t_send_start = time.perf_counter_ns()
    for i in range(n_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = msg[start:end]
        if len(chunk) < CHUNK:
            chunk = chunk + b'\x00' * (CHUNK - len(chunk))
        try:
            w = dev.write(0x01, chunk, timeout=2000)
            total += w
        except Exception as e:
            print(f"chunk[{i}]={e}")
            return None
    t_send_end = time.perf_counter_ns()
    send_us = (t_send_end - t_send_start) / 1000

    print(f"sent {total}B in {send_us:.0f}us", flush=True)

    # Read response with high-precision timing
    t_read_start = time.perf_counter_ns()
    try:
        r = bytes(dev.read(0x81, 4096, timeout=10000))
        t_read_end = time.perf_counter_ns()
        resp_us = (t_read_end - t_read_start) / 1000
        total_us = (t_read_end - t_send_start) / 1000
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"resp={len(r)}B status=0x{val:08X} resp_wait={resp_us:.0f}us total={total_us:.0f}us", flush=True)
        return {
            'case': case,
            'status': val,
            'send_us': send_us,
            'resp_us': resp_us,
            'total_us': total_us,
            'resp_hex': r.hex(),
        }
    except usb.core.USBTimeoutError:
        t_read_end = time.perf_counter_ns()
        resp_us = (t_read_end - t_read_start) / 1000
        print(f"resp=TIMEOUT resp_wait={resp_us:.0f}us")
        return {'case': case, 'status': 'timeout', 'resp_us': resp_us}
    except usb.core.USBError as e:
        print(f"resp={e}")
        return {'case': case, 'status': str(e)}


def main():
    case = sys.argv[1] if len(sys.argv) > 1 else 'zeros'
    result = run_timing(case)
    if result:
        outfile = f"findings/timing_{case}.json"
        with open(outfile, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"Saved to {outfile}")


if __name__ == "__main__":
    main()
