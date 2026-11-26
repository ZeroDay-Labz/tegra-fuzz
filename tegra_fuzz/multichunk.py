"""Send a multi-chunk RCM message and observe bootROM response.

Tests what happens when we send the full CVE-2018-6242 exploit-sized message
to a PATCHED unit. The IPATCH should block the DMA overflow somehow.

Usage:
    sudo python -m tegra_fuzz.multichunk <length_hex> [chunk_count]

Examples:
    sudo python -m tegra_fuzz.multichunk 30298       # full CVE length, auto chunks
    sudo python -m tegra_fuzz.multichunk 30298 10    # only send 10 chunks
    sudo python -m tegra_fuzz.multichunk FFFFFFFF 5  # max uint32, 5 chunks
"""
import struct, sys, time
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
CHUNK = 0x1000  # 4096 bytes per USB bulk transfer

def main():
    length = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x30298
    max_chunks = int(sys.argv[2]) if (len(sys.argv) > 2 and sys.argv[2].isdigit()) else None

    total_wire = max(CHUNK, ((length + 4 + CHUNK - 1) // CHUNK) * CHUNK)
    n_chunks = total_wire // CHUNK
    if max_chunks:
        n_chunks = min(n_chunks, max_chunks)

    print(f"len=0x{length:X} total_wire={total_wire} chunks={n_chunks}", flush=True)

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return 1
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
        return 1

    # Body fill byte — scan args for hex byte (non-numeric, non-empty)
    fill = 0x00
    for a in sys.argv[2:]:
        if a and not a.isdigit():
            fill = int(a, 16)
            break

    # Build first chunk with header
    chunk0 = struct.pack('<I', length) + bytes([fill]) * (CHUNK - 4)

    # Send chunks one at a time
    total_written = 0
    for i in range(n_chunks):
        data = chunk0 if i == 0 else bytes([fill]) * CHUNK
        t0 = time.monotonic()
        try:
            w = dev.write(0x01, data, timeout=2000)
            ms = (time.monotonic() - t0) * 1000
            total_written += w
            if i < 5 or i == n_chunks - 1 or (i % 10 == 0):
                print(f"  chunk[{i}]={w}B {ms:.0f}ms (total={total_written})", flush=True)
        except usb.core.USBTimeoutError:
            ms = (time.monotonic() - t0) * 1000
            print(f"  chunk[{i}]=TIMEOUT {ms:.0f}ms (total={total_written})", flush=True)
            break
        except usb.core.USBError as e:
            ms = (time.monotonic() - t0) * 1000
            print(f"  chunk[{i}]={e} {ms:.0f}ms (total={total_written})", flush=True)
            break

    print(f"total_written={total_written}", flush=True)

    # Read response
    try:
        r = bytes(dev.read(0x81, 4096, timeout=5000))
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"resp={len(r)}B hex={r[:64].hex()} status=0x{val:08X}", flush=True)
    except usb.core.USBTimeoutError:
        print("resp=TIMEOUT")
    except usb.core.USBError as e:
        print(f"resp={e}")

    # Check alive
    dev2 = usb.core.find(idVendor=VID, idProduct=PID)
    print(f"alive={dev2 is not None}", flush=True)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
