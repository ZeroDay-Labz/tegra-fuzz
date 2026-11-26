"""Send a 0x30298-byte RCM message with structured header fields.

Explores what happens with different header field values to map
the bootROM's processing stages and error codes.

Usage:
    sudo python -m tegra_fuzz.rcm_header <case>

Cases:
    zeros       — All-zero header (baseline, should give 0xF)
    ff_sig      — 0xFF signature field
    valid_len   — Correct internal length fields
    garbage_sig — Random-looking signature
    all_ff      — All 0xFF
"""
import struct, sys, time, os
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000

# RCM message layout (from ShofEL2 / T210 docs):
# Offset 0x000: Length field (4 bytes LE) = 0x30298
# Offset 0x004: CMAC hash? (16 bytes)
# Offset 0x014: Reserved/padding
# Offset 0x094: Encrypted secure boot header? (0x200 bytes)
# Offset 0x294: Random AES block (16 bytes)
# Offset 0x2A4: Payload start
# Total header = 0x2A4 bytes

def build_message(case):
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0, MSG_LEN)

    if case == 'zeros':
        pass  # all zeros except length

    elif case == 'ff_sig':
        # Fill signature area with 0xFF
        for i in range(0x94, 0x294):
            msg[i] = 0xFF

    elif case == 'valid_len':
        # Set some plausible internal fields
        # Offset 4: could be a secondary length or version
        struct.pack_into('<I', msg, 4, MSG_LEN - 0x2A4)  # payload length
        # Random block at 0x294 — fill with pattern
        for i in range(0x294, 0x2A4):
            msg[i] = 0xAA

    elif case == 'garbage_sig':
        # Fill signature with pseudo-random data
        import hashlib
        for i in range(0x94, 0x294):
            msg[i] = hashlib.sha256(bytes([i & 0xFF])).digest()[0]

    elif case == 'all_ff':
        for i in range(4, MSG_LEN):
            msg[i] = 0xFF

    else:
        print(f"unknown case: {case}")
        return None

    return bytes(msg)


def send_rcm(msg):
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return

    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # EP0 init
    try:
        d = bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 128, 1000))
        print(f"ep0_init={len(d)}B", flush=True)
    except Exception as e:
        print(f"ep0_init={e}", flush=True)

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
        print(f"id failed: {e}")
        return

    # Send in chunks
    n_chunks = (MSG_LEN + CHUNK - 1) // CHUNK
    total = 0
    for i in range(n_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = msg[start:end]
        if len(chunk) < CHUNK:
            chunk = chunk + b'\x00' * (CHUNK - len(chunk))
        try:
            w = dev.write(0x01, chunk, timeout=2000)
            total += w
            if i < 3 or i == n_chunks - 1:
                print(f"  chunk[{i}]={w}B (total={total})", flush=True)
        except usb.core.USBTimeoutError:
            print(f"  chunk[{i}]=TIMEOUT (total={total})", flush=True)
            break
        except usb.core.USBError as e:
            print(f"  chunk[{i}]={e} (total={total})", flush=True)
            break

    print(f"total_written={total}", flush=True)

    # Read response
    try:
        r = bytes(dev.read(0x81, 4096, timeout=5000))
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"resp={len(r)}B hex={r.hex()} status=0x{val:08X}", flush=True)
    except usb.core.USBTimeoutError:
        print("resp=TIMEOUT")
    except usb.core.USBError as e:
        print(f"resp={e}")

    alive = usb.core.find(idVendor=VID, idProduct=PID) is not None
    print(f"alive={alive}", flush=True)


def main():
    case = sys.argv[1] if len(sys.argv) > 1 else 'zeros'
    print(f"case={case} msg_len=0x{MSG_LEN:X}", flush=True)
    msg = build_message(case)
    if msg:
        send_rcm(msg)

if __name__ == "__main__":
    main()
