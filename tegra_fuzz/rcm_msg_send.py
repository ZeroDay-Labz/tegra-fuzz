"""Send a properly formatted RCM message and observe the response error code.

RCM T210 message layout (from NVIDIA rcm.h + bootROM decompilation):
  0x000: len_insecure (4)      msg_len = 0x30298
  0x004: modulus (256)          RSA-2048 public key modulus
  0x104: cmac_hash (16)         CMAC-AES hash (non-PKC mode)
  0x114: rsa_pss_sig (256)      RSA-PSS signature
  0x214: extra (36)             T210-specific (unknown purpose)
  0x238: reserved (16)
  0x248: ecid (16)              Device ECID
  0x258: opcode (4)             RCM command
  0x25C: len_secure (4)         Must match len_insecure
  0x260: payload_len (4)        msg_len - 0x2A8
  0x264: rcm_version (4)        0x00400001 = version 40.1
  0x268: args (48)              Command arguments
  0x298: padding (16)           Byte 8 = 0x80 (PKCS marker)
  0x2A8: payload start

Expected error codes:
  0x08 = INVALID_LEN_INSECURE  (bad msg_len)
  0x0A = LEN_MISMATCH          (len_insecure != len_secure)
  0x0B = PAYLOAD_LEN_MISMATCH  (payload_len wrong)
  0x0F = LEFTOVER_DATA         (USB chunking wrong)
  0x13 = NO_PUBKEY_LOADED      (PKC mode, our key hash != fuse hash)
  0x14 = CONFIG_MISMATCH       (config byte mismatch)
  0x16 = INVALID_SIGNATURE     (signature verification failed)

Usage:
    sudo python -m tegra_fuzz.rcm_msg_send
"""
import struct, sys, time, hashlib
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
HEADER_SIZE = 0x2A8
CHUNK = 0x1000

RCM_CMD_SYNC = 0x1
RCM_CMD_DL_MINILOADER = 0x4
RCM_CMD_QUERY_BR_VERSION = 0x5
RCM_CMD_QUERY_RCM_VERSION = 0x6
RCM_VERSION_40 = 0x00400001


def ep0_read(dev, timeout=500, verbose=False):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
    except usb.core.USBTimeoutError:
        if verbose:
            print("  EP0: timeout")
        return None
    except usb.core.USBError as e:
        if verbose:
            print(f"  EP0: {e}")
        return None


def build_rcm_message(opcode=RCM_CMD_DL_MINILOADER, pubkey_256=None):
    """Build a 0x30298-byte RCM message with correct T210 structure."""
    msg = bytearray(MSG_LEN)

    # 0x000: len_insecure
    struct.pack_into('<I', msg, 0x000, MSG_LEN)

    # 0x004: RSA-2048 modulus (256 bytes)
    if pubkey_256:
        msg[0x004:0x104] = pubkey_256[:256]

    # 0x104: cmac_hash (16 bytes) — leave zeros for PKC mode
    # 0x114: rsa_pss_sig (256 bytes) — leave zeros
    # 0x214: extra (36 bytes) — zeros
    # 0x238: reserved (16 bytes) — zeros
    # 0x248: ecid (16 bytes) — zeros

    # 0x258: opcode
    struct.pack_into('<I', msg, 0x258, opcode)

    # 0x25C: len_secure (must match len_insecure)
    struct.pack_into('<I', msg, 0x25C, MSG_LEN)

    # 0x260: payload_len = msg_len - header_size
    payload_len = MSG_LEN - HEADER_SIZE
    struct.pack_into('<I', msg, 0x260, payload_len)

    # 0x264: rcm_version
    struct.pack_into('<I', msg, 0x264, RCM_VERSION_40)

    # 0x268: args (48 bytes) — zeros for DL_MINILOADER (entry addr in first 4)
    if opcode == RCM_CMD_DL_MINILOADER:
        struct.pack_into('<I', msg, 0x268, 0x40010000)

    # 0x298: padding (16 bytes) — byte 8 must be 0x80 for PKCS check
    msg[0x2A0] = 0x80  # 0x298 + 8 = 0x2A0

    return msg


def main():
    print("=== RCM T210 Message Send ===")
    print(f"Message length: 0x{MSG_LEN:X} ({MSG_LEN} bytes)")
    print(f"Header: 0x{HEADER_SIZE:X} ({HEADER_SIZE} bytes)")
    print(f"Payload: 0x{MSG_LEN - HEADER_SIZE:X} ({MSG_LEN - HEADER_SIZE} bytes)")
    print()

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("ERROR: No device"); return 1
    print(f"Device: bus {dev.bus} addr {dev.address}")

    import time as _time

    # Try detaching kernel driver early — Linux may grab it
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
            print("Detached kernel driver")
    except (NotImplementedError, usb.core.USBError):
        pass

    baseline = None
    for attempt in range(5):
        baseline = ep0_read(dev, timeout=1000, verbose=True)
        if baseline:
            break
        print(f"  EP0 attempt {attempt+1}/5 failed, retrying...")
        if attempt == 1:
            # Try a USB reset on 2nd failure
            try:
                dev.reset()
                _time.sleep(0.3)
                print("  USB device reset")
            except usb.core.USBError:
                pass
        _time.sleep(0.5)
    if not baseline:
        print("ERROR: EP0 baseline failed after 5 attempts")
        print("  Try: unplug/replug device, or check RCM mode")
        return 1
    print(f"EP0 baseline: {len(baseline)} bytes OK")

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

    msg = build_rcm_message(opcode=RCM_CMD_DL_MINILOADER)

    pubkey = msg[0x004:0x104]
    pubkey_hash = hashlib.sha256(pubkey).hexdigest()
    print(f"\nMessage layout verification:")
    print(f"  [0x000] len_insecure  = 0x{struct.unpack_from('<I', msg, 0x000)[0]:08X}")
    print(f"  [0x004] modulus[0:4]  = {msg[0x004:0x008].hex()}")
    print(f"  [0x258] opcode        = 0x{struct.unpack_from('<I', msg, 0x258)[0]:08X}")
    print(f"  [0x25C] len_secure    = 0x{struct.unpack_from('<I', msg, 0x25C)[0]:08X}")
    print(f"  [0x260] payload_len   = 0x{struct.unpack_from('<I', msg, 0x260)[0]:08X}")
    print(f"  [0x264] rcm_version   = 0x{struct.unpack_from('<I', msg, 0x264)[0]:08X}")
    print(f"  [0x2A0] PKCS marker   = 0x{msg[0x2A0]:02X}")
    print(f"  SHA-256(modulus)       = {pubkey_hash[:16]}...")

    after_first = MSG_LEN - CHUNK
    full_chunks = after_first // CHUNK
    last_chunk_size = after_first % CHUNK
    total_chunks = 1 + full_chunks + (1 if last_chunk_size > 0 else 0)

    print(f"\nChunk plan: {total_chunks} data chunks + 1 dummy")
    print(f"  Last chunk: {last_chunk_size} bytes at offset 0x{total_chunks * CHUNK - CHUNK:X}")

    total_sent = 0
    send_start = time.perf_counter_ns()

    for i in range(total_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = bytes(msg[start:end])

        try:
            w = dev.write(0x01, chunk, timeout=5000)
            total_sent += w
        except usb.core.USBError as e:
            print(f"ERROR at chunk {i} (offset 0x{start:X}): {e}")
            print(f"  total_sent={total_sent}")
            # Try reading response anyway
            break

    # Send dummy byte to complete the async receive
    dummy_send_time = time.perf_counter_ns()
    try:
        w = dev.write(0x01, b'\x00', timeout=5000)
        total_sent += w
    except usb.core.USBError as e:
        print(f"Dummy send: {e}")

    send_end = time.perf_counter_ns()
    send_us = (send_end - send_start) / 1000
    print(f"\nSent {total_sent} bytes in {send_us:.0f} us")

    t0 = time.perf_counter_ns()
    try:
        resp = bytes(dev.read(0x81, 4096, timeout=10000))
        t1 = time.perf_counter_ns()
        resp_us = (t1 - t0) / 1000
        resp_from_dummy_us = (t1 - dummy_send_time) / 1000

        if len(resp) >= 4:
            status = struct.unpack_from('<I', resp, 0)[0]
            error_names = {
                0x00: "SUCCESS",
                0x01: "HASH_FAIL_PAYLOAD",
                0x02: "HASH_FAIL_HEADER",
                0x04: "INVALID_LOWSEC_KEY",
                0x08: "INVALID_LEN_INSECURE",
                0x0A: "LEN_MISMATCH",
                0x0B: "PAYLOAD_LEN_MISMATCH",
                0x0C: "USB_EXTRA_DATA",
                0x0D: "GENERAL_FAIL",
                0x0F: "LEFTOVER_DATA",
                0x13: "NO_PUBKEY_LOADED",
                0x14: "CONFIG_MISMATCH",
                0x15: "INVALID_KEYINDEX",
                0x16: "INVALID_SIGNATURE",
            }
            name = error_names.get(status, f"UNKNOWN (0x{status:02X})")
            print(f"\n{'='*50}")
            print(f"RESPONSE: 0x{status:08X} = {name}")
            print(f"{'='*50}")
            print(f"  Raw: {resp[:16].hex()}")
            print(f"  Time from read(): {resp_us:.1f} us")
            print(f"  Time from dummy:  {resp_from_dummy_us:.1f} us")

            if status == 0x13:
                print(f"\n  *** REACHED PKC SIGNATURE PATH ***")
                print(f"  Our pubkey hash doesn't match fuse hash.")
                print(f"  Next: provide correct Nintendo RSA pubkey")
                print(f"  or mount timing attack on the hash comparison.")
            elif status == 0x0F:
                print(f"\n  LEFTOVER_DATA — chunking still wrong.")
                print(f"  Need to fix message framing.")
            elif status == 0x0A:
                print(f"\n  LEN_MISMATCH — len_insecure != len_secure.")
                print(f"  Check field offsets in the message.")
            elif status == 0x0B:
                print(f"\n  PAYLOAD_LEN_MISMATCH — payload_len wrong")
                print(f"  or payload_len field at wrong offset.")
            elif status == 0x02:
                print(f"\n  HASH_FAIL_HEADER — PKCS padding wrong.")
                print(f"  Check 0x80 marker byte position.")
            elif status == 0x14:
                print(f"\n  CONFIG_MISMATCH — message config field wrong.")
            elif status == 0x16:
                print(f"\n  *** SIGNATURE FAIL — pubkey MATCHED fuse hash! ***")
                print(f"  But the RSA-PSS signature is invalid.")
                print(f"  This means we found the correct public key!")
            elif status == 0x00:
                print(f"\n  *** SUCCESS — message ACCEPTED! ***")
        else:
            print(f"\nShort response: {resp.hex()}")

    except usb.core.USBTimeoutError:
        t1 = time.perf_counter_ns()
        wait_us = (t1 - t0) / 1000
        print(f"\nNo response after {wait_us:.0f} us")
        ep0 = ep0_read(dev)
        if ep0:
            print(f"EP0 alive ({len(ep0)} bytes)")
        else:
            print("EP0 DEAD")

    except usb.core.USBError as e:
        print(f"\nResponse error: {e}")

    final = ep0_read(dev)
    if final and len(final) > 63:
        rem = struct.unpack_from('<I', final, 60)[0]
        ptr = struct.unpack_from('<I', final, 36)[0]
        print(f"\nFinal EP0: remaining=0x{rem:X} ptr=0x{ptr:08X}")
    elif final:
        print(f"\nFinal EP0: {len(final)} bytes")
    else:
        print("\nFinal EP0: not responding")

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
