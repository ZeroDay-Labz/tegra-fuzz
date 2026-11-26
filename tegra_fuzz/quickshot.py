"""Minimal single-shot RCM test. No USB reset, no EP0, no frills.
Claim -> device ID -> one write -> one read -> exit cleanly.

Usage:
    sudo python -m tegra_fuzz.quickshot <length_hex> [body_byte_hex]

Examples:
    sudo python -m tegra_fuzz.quickshot 0        # len=0, zeros body
    sudo python -m tegra_fuzz.quickshot 0 DE     # len=0, 0xDE body fill
    sudo python -m tegra_fuzz.quickshot 1000     # len=0x1000, zeros body
"""
import struct, sys, time
import usb.core, usb.util

VID, PID = 0x0955, 0x7321

def main():
    length = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0
    fill = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x00

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # EP0 GET_STATUS before claiming — initializes bulk DMA in bootROM
    try:
        d = bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 128, 1000))
        print(f"ep0_init={len(d)}B", flush=True)
    except Exception as e:
        print(f"ep0_init={e}", flush=True)

    # Exact same setup as rcm_fuzz.py — set_config and claim in ONE try
    # If set_config fails, claim_interface must NOT run
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
        return 1

    # Build message — use 2x0x1000 like original fuzz (partial write behavior)
    body = bytes([fill]) * (0x2000 - 4)
    msg = struct.pack('<I', length) + body

    # Write — 2000ms timeout matches the working fuzz code
    t0 = time.monotonic()
    try:
        w = dev.write(0x01, msg, timeout=2000)
        ms = (time.monotonic() - t0) * 1000
        print(f"write={w}B {ms:.0f}ms", flush=True)
    except usb.core.USBTimeoutError:
        ms = (time.monotonic() - t0) * 1000
        print(f"write=TIMEOUT {ms:.0f}ms")
        return 1
    except usb.core.USBError as e:
        print(f"write={e}")
        return 1

    # Read response
    try:
        r = bytes(dev.read(0x81, 4096, timeout=5000))
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"resp={len(r)}B hex={r.hex()} status=0x{val:08X}", flush=True)
    except usb.core.USBTimeoutError:
        print("resp=TIMEOUT")
    except usb.core.USBError as e:
        print(f"resp={e}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
