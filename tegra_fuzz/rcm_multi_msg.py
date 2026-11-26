"""Test: can we send MULTIPLE RCM messages per RCM entry?

After getting error 0x13, does the bootROM loop back and accept
another message? If so, the timing attack becomes practical —
we can do thousands of measurements per RCM entry instead of one.

Usage:
    sudo python -m tegra_fuzz.rcm_multi_msg
"""
import struct, sys, time
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000


def ep0_read(dev, timeout=500):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
    except Exception:
        return None


def build_minimal_msg():
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0x000, MSG_LEN)
    return msg


def send_msg_and_read(dev, msg, attempt_num):
    """Send one full RCM message, return (status, timing_ns) or (None, None)."""
    total_chunks = 49
    for i in range(total_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        try:
            dev.write(0x01, bytes(msg[start:end]), timeout=5000)
        except usb.core.USBError as e:
            print(f"  [{attempt_num}] Write failed at chunk {i}: {e}")
            return None, None

    # Dummy
    try:
        dev.write(0x01, b'\x00', timeout=2000)
    except usb.core.USBError:
        pass

    # Read response
    t0 = time.perf_counter_ns()
    try:
        resp = bytes(dev.read(0x81, 4096, timeout=5000))
        t1 = time.perf_counter_ns()
        if len(resp) >= 4:
            status = struct.unpack_from('<I', resp, 0)[0]
            return status, t1 - t0
    except usb.core.USBTimeoutError:
        print(f"  [{attempt_num}] Response timeout")
        return None, None
    except usb.core.USBError as e:
        print(f"  [{attempt_num}] Response error: {e}")
        return None, None

    return None, None


def main():
    max_attempts = 10

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("ERROR: No device"); return 1
    print(f"Device: bus {dev.bus} addr {dev.address}")

    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass

    for _ in range(3):
        if ep0_read(dev, timeout=1000):
            break
        time.sleep(0.3)
    else:
        print("EP0 baseline failed"); return 1

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

    msg = build_minimal_msg()
    print(f"\nSending up to {max_attempts} messages on SAME RCM entry...")
    print(f"Message: {MSG_LEN} bytes, modulus=zeros\n")

    timings = []

    for attempt in range(1, max_attempts + 1):
        status, timing = send_msg_and_read(dev, msg, attempt)

        if status is not None:
            timings.append(timing)
            print(f"  [{attempt}] Status: 0x{status:08X}  Timing: {timing/1000:.1f} us")

            # Check if device is still alive
            ep = ep0_read(dev, timeout=500)
            if not ep:
                print(f"  [{attempt}] EP0 died after response — device reset")
                break
        else:
            print(f"  [{attempt}] FAILED — device no longer accepting messages")
            # Check EP0
            ep = ep0_read(dev, timeout=500)
            if ep:
                print(f"  EP0 still alive ({len(ep)}B) — but message path broken")
            else:
                print(f"  EP0 DEAD — device in abort state")
            break

    print(f"\n--- Summary ---")
    print(f"Successful messages: {len(timings)}/{max_attempts}")
    if timings:
        mean_t = sum(timings) / len(timings)
        print(f"Timings (us): {', '.join(f'{t/1000:.1f}' for t in timings)}")
        print(f"Mean: {mean_t/1000:.1f} us")

        if len(timings) > 1:
            print(f"\n*** MULTI-MESSAGE WORKS! ***")
            print(f"Timing attack is PRACTICAL — {len(timings)} messages per RCM entry")
            print(f"At ~6ms per message, ~166 messages/sec = ~10,000/min")
        else:
            print(f"\nOnly 1 message worked — need 1 RCM entry per measurement")

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
