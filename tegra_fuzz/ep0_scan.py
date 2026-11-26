"""EP0 control transfer scanner — enumerate what the bootROM responds to.

Runs pre-handshake (before claim/device ID) so we can do many reads per session.
Tests various bmRequestType, bRequest, wValue, wIndex combinations.

SAFETY: Never sends SET_ADDRESS (bRequest=0x05, bmRequestType=0x00).

Usage:
    sudo python -m tegra_fuzz.ep0_scan
"""
import sys, time, json
import usb.core

VID, PID = 0x0955, 0x7321

# Standard USB requests
GET_STATUS = 0x00
CLEAR_FEATURE = 0x01
SET_FEATURE = 0x03
GET_DESCRIPTOR = 0x06
GET_CONFIGURATION = 0x08
GET_INTERFACE = 0x0A

FORBIDDEN_REQUESTS = {
    (0x00, 0x05),  # SET_ADDRESS — NEVER SEND
}

def try_ctrl(dev, bmrt, breq, wval, widx, wlen, timeout=500):
    if (bmrt & 0x80) == 0:
        return None  # never send OUT transfers in scan mode
    if (bmrt, breq) in FORBIDDEN_REQUESTS:
        return None
    try:
        data = bytes(dev.ctrl_transfer(bmrt, breq, wval, widx, wlen, timeout))
        return data
    except usb.core.USBTimeoutError:
        return "TIMEOUT"
    except usb.core.USBError as e:
        errno = getattr(e, 'errno', None)
        if errno == 32:
            return "STALL"
        return f"ERR:{errno}"


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    results = []

    # 1. GET_STATUS on various endpoints/interfaces
    print("\n=== GET_STATUS (bRequest=0x00) ===", flush=True)
    for bmrt, label in [(0x80, "device"), (0x81, "interface"), (0x82, "endpoint")]:
        for widx in [0x00, 0x01, 0x02, 0x80, 0x81, 0x82]:
            for wlen in [2, 4, 16, 64, 128, 256, 512]:
                r = try_ctrl(dev, bmrt, GET_STATUS, 0, widx, wlen)
                if r is None:
                    continue
                if isinstance(r, bytes) and len(r) > 0:
                    nonzero = any(b != 0 for b in r)
                    tag = "*" if nonzero else " "
                    print(f"  {tag} bmrt=0x{bmrt:02X} widx=0x{widx:02X} wlen={wlen:3d} -> {len(r)}B {r[:32].hex()}", flush=True)
                    results.append({"bmrt": bmrt, "breq": 0, "widx": widx, "wlen": wlen,
                                    "got": len(r), "hex": r.hex(), "nonzero": nonzero})
                elif isinstance(r, str):
                    if r != "STALL":
                        print(f"    bmrt=0x{bmrt:02X} widx=0x{widx:02X} wlen={wlen:3d} -> {r}", flush=True)

    # 2. GET_DESCRIPTOR — may return additional descriptors
    print("\n=== GET_DESCRIPTOR (bRequest=0x06) ===", flush=True)
    for desc_type in range(1, 16):
        for desc_idx in range(3):
            wval = (desc_type << 8) | desc_idx
            r = try_ctrl(dev, 0x80, GET_DESCRIPTOR, wval, 0, 512)
            if isinstance(r, bytes) and len(r) > 0:
                print(f"  type={desc_type} idx={desc_idx} -> {len(r)}B {r[:32].hex()}", flush=True)
                results.append({"bmrt": 0x80, "breq": 6, "wval": wval,
                                "got": len(r), "hex": r.hex()})

    # 3. GET_CONFIGURATION
    print("\n=== GET_CONFIGURATION (bRequest=0x08) ===", flush=True)
    r = try_ctrl(dev, 0x80, GET_CONFIGURATION, 0, 0, 64)
    if isinstance(r, bytes):
        print(f"  -> {len(r)}B {r.hex()}", flush=True)
    else:
        print(f"  -> {r}", flush=True)

    # 4. GET_INTERFACE
    print("\n=== GET_INTERFACE (bRequest=0x0A) ===", flush=True)
    for iface in range(4):
        r = try_ctrl(dev, 0x81, GET_INTERFACE, 0, iface, 64)
        if isinstance(r, bytes) and len(r) > 0:
            print(f"  iface={iface} -> {len(r)}B {r.hex()}", flush=True)
        elif isinstance(r, str) and r != "STALL":
            print(f"  iface={iface} -> {r}", flush=True)

    # 5. Vendor-specific requests (bmRequestType 0xC0 = device-to-host, vendor, device)
    print("\n=== VENDOR REQUESTS (bmrt=0xC0/0xC1/0xC2) ===", flush=True)
    for bmrt in [0xC0, 0xC1, 0xC2]:
        for breq in range(0, 32):
            r = try_ctrl(dev, bmrt, breq, 0, 0, 512)
            if isinstance(r, bytes) and len(r) > 0:
                print(f"  * bmrt=0x{bmrt:02X} breq=0x{breq:02X} -> {len(r)}B {r[:32].hex()}", flush=True)
                results.append({"bmrt": bmrt, "breq": breq,
                                "got": len(r), "hex": r.hex()})
            elif isinstance(r, str) and r not in ("STALL", "ERR:32"):
                print(f"    bmrt=0x{bmrt:02X} breq=0x{breq:02X} -> {r}", flush=True)

    # 6. Try large reads on the known working endpoint (0x82, GET_STATUS, EP_IN)
    print("\n=== LARGE READS on known over-read ===", flush=True)
    for wlen in [128, 255, 256, 512, 1024, 2048, 4096]:
        r = try_ctrl(dev, 0x82, GET_STATUS, 0, 0x81, wlen)
        if isinstance(r, bytes):
            nonzero_count = sum(1 for b in r if b != 0)
            print(f"  wlen={wlen:4d} -> {len(r)}B nonzero={nonzero_count}", flush=True)
            if wlen <= 512:
                results.append({"test": "large_read", "wlen": wlen,
                                "got": len(r), "hex": r.hex()})
        else:
            print(f"  wlen={wlen:4d} -> {r}", flush=True)

    # Save results
    out = "findings/ep0_scan.json"
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved {len(results)} results to {out}", flush=True)

    # Verify device still alive
    dev2 = usb.core.find(idVendor=VID, idProduct=PID)
    print(f"alive={dev2 is not None}", flush=True)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
