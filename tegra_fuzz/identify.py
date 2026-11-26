"""Identify a connected Tegra X1 device in RCM mode.

Reads the USB descriptors and RCM device ID, then prints structured
hardware information. This is a passive, read-only operation — it sends
no malformed data and does not modify device state.

Usage:
    sudo python -m tegra_fuzz.identify
"""
from __future__ import annotations

import sys

from . import rcm
from .device_id import parse_device_id, ERISTA_PID, MARIKO_PID
from .transport import TransportError


def identify() -> int:
    import usb.core
    import usb.util

    dev = usb.core.find(idVendor=rcm.VID, idProduct=rcm.PID)
    if dev is None:
        print("error: Tegra APX device not found — put the console in RCM "
              "mode and connect it.", file=sys.stderr)
        return 2

    print("tegra_fuzz device identification (read-only)", file=sys.stderr)
    print(file=sys.stderr)

    # USB descriptor info (no claim needed)
    print(f"  usb addr   : bus {dev.bus}, device {dev.address}", file=sys.stderr)
    print(f"  vid:pid    : 0x{dev.idVendor:04X}:0x{dev.idProduct:04X}", file=sys.stderr)
    print(f"  bcdUSB     : {dev.bcdUSB >> 8}.{(dev.bcdUSB >> 4) & 0xF}{dev.bcdUSB & 0xF}", file=sys.stderr)
    print(f"  bcdDevice  : 0x{dev.bcdDevice:04X}", file=sys.stderr)
    for label, idx in [("product", dev.iProduct), ("mfg", dev.iManufacturer)]:
        if idx:
            try:
                val = usb.util.get_string(dev, idx)
            except (usb.core.USBError, ValueError):
                val = f"(index {idx}, unreadable)"
        else:
            val = "(none)"
        print(f"  {label:<10} : {val}", file=sys.stderr)
    print(f"  speed      : {'high (480 Mbps)' if dev.speed == 3 else f'code {dev.speed}'}", file=sys.stderr)
    print(file=sys.stderr)

    # Claim interface and read device ID
    try:
        try:
            if dev.is_kernel_driver_active(rcm.INTERFACE):
                dev.detach_kernel_driver(rcm.INTERFACE)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, rcm.INTERFACE)
    except usb.core.USBError as exc:
        print(f"error: could not claim interface: {exc}", file=sys.stderr)
        return 2

    try:
        raw_id = bytes(dev.read(rcm.EP_IN, rcm.DEVICE_ID_LENGTH, timeout=2000))
    except usb.core.USBError as exc:
        print(f"error: could not read device ID: {exc}", file=sys.stderr)
        return 2
    finally:
        usb.util.dispose_resources(dev)

    info = parse_device_id(raw_id, pid=dev.idProduct, bcd_device=dev.bcdDevice)
    print(info.summary(), file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(identify())
