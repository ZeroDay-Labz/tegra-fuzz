"""Test: does the Switch re-enter RCM automatically after a failed message?

After error 0x13, EP0 dies. But does the SoC reboot back to RCM?
If the USB device reappears with a new address, we can automate
the timing attack without physical intervention.

Usage:
    sudo python -m tegra_fuzz.rcm_auto_reentry

    Hold VOL+ the entire time (tape it down). Don't unplug.
    The script will check if the device re-enumerates after each error.
"""
import struct, sys, time
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000
MAX_ROUNDS = 5


def ep0_read(dev, timeout=500):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
    except Exception:
        return None


def find_device(timeout_sec=5):
    """Wait for device to appear, return (dev, addr) or (None, None)."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev:
            return dev, dev.address
        time.sleep(0.2)
    return None, None


def setup_device(dev):
    """Full setup: detach, EP0, configure, claim, read device ID."""
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass

    for _ in range(5):
        if ep0_read(dev, timeout=1000):
            break
        time.sleep(0.2)
    else:
        return False

    try:
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        pass

    try:
        dev.read(0x81, 16, timeout=2000)
    except Exception:
        return False

    return True


def send_one_message(dev, msg):
    """Send a full RCM message, return (status, timing_ns)."""
    total_chunks = 49
    for i in range(total_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        try:
            dev.write(0x01, bytes(msg[start:end]), timeout=5000)
        except usb.core.USBError as e:
            return None, None

    try:
        dev.write(0x01, b'\x00', timeout=2000)
    except usb.core.USBError:
        pass

    t0 = time.perf_counter_ns()
    try:
        resp = bytes(dev.read(0x81, 4096, timeout=5000))
        t1 = time.perf_counter_ns()
        if len(resp) >= 4:
            return struct.unpack_from('<I', resp, 0)[0], t1 - t0
    except Exception:
        pass
    return None, None


def main():
    print("=== RCM Auto Re-entry Test ===")
    print("KEEP VOL+ HELD the entire time. Don't unplug.")
    print(f"Will attempt {MAX_ROUNDS} rounds.\n")

    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0x000, MSG_LEN)

    timings = []

    for rnd in range(1, MAX_ROUNDS + 1):
        if rnd == 1:
            print(f"[Round {rnd}] Looking for device...")
        else:
            print(f"[Round {rnd}] Waiting for device to re-enumerate...")

        dev, addr = find_device(timeout_sec=8)
        if not dev:
            print(f"  Device not found after 8 seconds")
            if rnd > 1:
                print(f"  → Device does NOT auto re-enter RCM")
            break

        print(f"  Found device at addr {addr}")

        if not setup_device(dev):
            print(f"  Setup failed")
            break

        status, timing = send_one_message(dev, msg)
        if status is not None:
            timings.append(timing)
            print(f"  Status: 0x{status:08X}  Timing: {timing/1000:.1f} us")
        else:
            print(f"  No response")
            break

        # Wait a moment for device to reset
        time.sleep(0.5)

        # Check if device is gone
        check = usb.core.find(idVendor=VID, idProduct=PID)
        if check:
            # Same device or new?
            if check.address == addr:
                print(f"  Device still at same addr — might not have reset yet")
                time.sleep(2)
            else:
                print(f"  Device at new addr {check.address} — re-enumerated!")
                continue
        else:
            print(f"  Device disappeared — waiting for re-enumeration...")

    print(f"\n--- Summary ---")
    print(f"Completed rounds: {len(timings)}/{MAX_ROUNDS}")
    if len(timings) > 1:
        print(f"Timings (us): {', '.join(f'{t/1000:.1f}' for t in timings)}")
        mean_t = sum(timings) / len(timings)
        print(f"Mean: {mean_t/1000:.1f} us")
        print(f"\n*** AUTO RE-ENTRY WORKS! ***")
        print(f"Timing attack can be fully automated!")
        print(f"Estimated: {1000/6:.0f} measurements per minute")
    elif len(timings) == 1:
        print(f"\nOnly 1 round worked. Device does not auto re-enter RCM.")
        print(f"Physical VOL+ press needed each time.")
        print(f"Timing attack not practical via USB alone.")
    else:
        print(f"\nNo successful rounds.")

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
