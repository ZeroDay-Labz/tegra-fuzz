"""Diagnostic: send minimal RCM message variants to isolate the crash.

The corrected message format causes the device to crash (EP0 dead).
This script tests variants with fewer fields to find which field causes it.

Usage:
    sudo python -m tegra_fuzz.rcm_msg_diag [variant]

Variants:
    0  = only len_insecure (everything else zeros)
    1  = len_insecure + len_secure
    2  = len_insecure + len_secure + payload_len
    3  = len_insecure + len_secure + payload_len + rcm_version
    4  = len_insecure + len_secure + payload_len + rcm_version + opcode
    5  = full (all fields including PKCS and args)
    6  = full but try reading response BEFORE dummy
    7  = EP0 trace: monitor EP0 during last 5 chunks
"""
import struct, sys, time
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
HEADER_SIZE = 0x2A8
CHUNK = 0x1000


def ep0_read(dev, timeout=500):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
    except Exception:
        return None


def build_variant(variant):
    msg = bytearray(MSG_LEN)

    # Always set len_insecure
    struct.pack_into('<I', msg, 0x000, MSG_LEN)

    if variant >= 1:
        struct.pack_into('<I', msg, 0x25C, MSG_LEN)  # len_secure

    if variant >= 2:
        struct.pack_into('<I', msg, 0x260, MSG_LEN - HEADER_SIZE)  # payload_len

    if variant >= 3:
        struct.pack_into('<I', msg, 0x264, 0x00400001)  # rcm_version

    if variant >= 4:
        struct.pack_into('<I', msg, 0x258, 0x4)  # opcode = DL_MINILOADER

    if variant >= 5:
        struct.pack_into('<I', msg, 0x268, 0x40010000)  # args[0] entry addr
        msg[0x2A0] = 0x80  # PKCS marker

    return msg


def send_and_check(dev, msg, variant, read_before_dummy=False, trace_ep0=False):
    total_chunks = 49  # 48 full + 1 partial

    print(f"\n--- Variant {variant} ---")
    desc = [
        "len_insecure only",
        "+ len_secure",
        "+ payload_len",
        "+ rcm_version",
        "+ opcode",
        "full (all fields)",
        "full + read-before-dummy",
        "EP0 trace last 5 chunks",
    ]
    print(f"Fields: {desc[min(variant, len(desc)-1)]}")

    # Show non-zero fields in signed area
    for off in range(0x238, 0x2A8, 4):
        val = struct.unpack_from('<I', msg, off)[0]
        if val != 0:
            print(f"  [0x{off:03X}] = 0x{val:08X}")
    # Check PKCS byte
    if msg[0x2A0] != 0:
        print(f"  [0x2A0] = 0x{msg[0x2A0]:02X} (PKCS)")

    total_sent = 0
    t_start = time.perf_counter_ns()

    for i in range(total_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = bytes(msg[start:end])

        try:
            w = dev.write(0x01, chunk, timeout=5000)
            total_sent += w
        except usb.core.USBError as e:
            print(f"  WRITE ERROR at chunk {i}: {e}")
            break

        # EP0 trace for last 5 chunks
        if trace_ep0 and i >= total_chunks - 5:
            ep = ep0_read(dev, timeout=200)
            if ep and len(ep) >= 64:
                rem = struct.unpack_from('<I', ep, 60)[0]
                ptr = struct.unpack_from('<I', ep, 36)[0]
                print(f"  chunk {i}: rem=0x{rem:X} ptr=0x{ptr:08X}")
            elif ep:
                print(f"  chunk {i}: EP0 {len(ep)}B")
            else:
                print(f"  chunk {i}: EP0 DEAD!")
                break

    t_send = time.perf_counter_ns()
    print(f"  Sent {total_sent} bytes in {(t_send - t_start)/1e6:.1f} ms")

    # Try reading response BEFORE dummy (variant 6)
    if read_before_dummy:
        print("  Trying read BEFORE dummy...")
        t0 = time.perf_counter_ns()
        try:
            resp = bytes(dev.read(0x81, 4096, timeout=3000))
            t1 = time.perf_counter_ns()
            if len(resp) >= 4:
                status = struct.unpack_from('<I', resp, 0)[0]
                print(f"  PRE-DUMMY RESPONSE: 0x{status:08X} ({(t1-t0)/1e6:.1f} ms)")
                return status
            else:
                print(f"  PRE-DUMMY: {resp.hex()}")
                return -1
        except usb.core.USBTimeoutError:
            print(f"  PRE-DUMMY: timeout (3s)")
        except usb.core.USBError as e:
            print(f"  PRE-DUMMY: {e}")

    # Send dummy byte
    try:
        dev.write(0x01, b'\x00', timeout=2000)
        print("  Dummy: OK")
    except usb.core.USBError as e:
        print(f"  Dummy: {e}")

    # Read response
    t0 = time.perf_counter_ns()
    try:
        resp = bytes(dev.read(0x81, 4096, timeout=5000))
        t1 = time.perf_counter_ns()
        if len(resp) >= 4:
            status = struct.unpack_from('<I', resp, 0)[0]
            error_names = {
                0x00: "SUCCESS", 0x01: "HASH_FAIL_PAYLOAD",
                0x02: "HASH_FAIL_HEADER", 0x04: "INVALID_LOWSEC_KEY",
                0x08: "INVALID_LEN_INSECURE", 0x0A: "LEN_MISMATCH",
                0x0B: "PAYLOAD_LEN_MISMATCH", 0x0F: "LEFTOVER_DATA",
                0x13: "NO_PUBKEY_LOADED", 0x14: "CONFIG_MISMATCH",
                0x16: "INVALID_SIGNATURE",
            }
            name = error_names.get(status, f"UNKNOWN")
            print(f"  RESPONSE: 0x{status:08X} = {name} ({(t1-t0)/1e6:.1f} ms)")
            return status
        else:
            print(f"  Short response: {resp.hex()}")
            return -1
    except usb.core.USBTimeoutError:
        t1 = time.perf_counter_ns()
        print(f"  NO RESPONSE ({(t1-t0)/1e6:.1f} ms timeout)")
    except usb.core.USBError as e:
        print(f"  Response error: {e}")

    # Check EP0
    ep = ep0_read(dev, timeout=1000)
    if ep:
        print(f"  EP0: alive ({len(ep)}B)")
    else:
        print(f"  EP0: DEAD")

    return None


def main():
    variant = 0
    if len(sys.argv) > 1:
        try:
            variant = int(sys.argv[1])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [0-7]"); return 1

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("ERROR: No device"); return 1
    print(f"Device: bus {dev.bus} addr {dev.address}")

    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass

    baseline = None
    for attempt in range(3):
        baseline = ep0_read(dev, timeout=1000)
        if baseline:
            break
        time.sleep(0.3)
    if not baseline:
        print("ERROR: EP0 baseline failed"); return 1
    print(f"EP0: {len(baseline)} bytes")

    try:
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        pass

    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"Device ID: {did.hex()}")
    except Exception as e:
        print(f"Device ID failed: {e}"); return 1

    msg = build_variant(variant)
    read_before = (variant == 6)
    trace = (variant == 7)

    result = send_and_check(dev, msg, variant,
                            read_before_dummy=read_before,
                            trace_ep0=trace)

    if result is not None:
        print(f"\nResult: 0x{result:08X}")
    else:
        print(f"\nResult: CRASH/NO RESPONSE")

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
