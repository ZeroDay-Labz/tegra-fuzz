"""Capture and store USB descriptor information for a Tegra X1 in RCM mode.

This reads sysfs and libusb data to build a complete hardware fingerprint.
All operations are passive reads — no data is sent to the device.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class UsbDescriptors:
    vid: int
    pid: int
    bcd_usb: str
    bcd_device: int
    device_class: int
    device_subclass: int
    device_protocol: int
    max_packet_size_0: int
    num_configurations: int
    speed: str
    bus: int
    address: int
    manufacturer: str
    product: str
    serial: str
    interfaces: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def capture_from_sysfs(sysfs_path: str) -> UsbDescriptors | None:
    """Read USB descriptor fields from a sysfs device path."""
    p = Path(sysfs_path)
    if not p.exists():
        return None

    def _read(name: str, default: str = "") -> str:
        f = p / name
        return f.read_text().strip() if f.exists() else default

    def _read_int(name: str, base: int = 16, default: int = 0) -> int:
        val = _read(name)
        if not val:
            return default
        return int(val, base)

    return UsbDescriptors(
        vid=_read_int("idVendor"),
        pid=_read_int("idProduct"),
        bcd_usb=_read("version"),
        bcd_device=_read_int("bcdDevice"),
        device_class=_read_int("bDeviceClass"),
        device_subclass=_read_int("bDeviceSubClass"),
        device_protocol=_read_int("bDeviceProtocol"),
        max_packet_size_0=_read_int("bMaxPacketSize0", base=10),
        num_configurations=_read_int("bNumConfigurations", base=10),
        speed=_read("speed") + " Mbps",
        bus=_read_int("busnum", base=10),
        address=_read_int("devnum", base=10),
        manufacturer=_read("manufacturer"),
        product=_read("product"),
        serial=_read("serial"),
        interfaces=[],
        endpoints=[],
    )


def find_tegra_sysfs() -> str | None:
    """Find the sysfs path for a connected Tegra X1 APX device."""
    usb_devices = Path("/sys/bus/usb/devices")
    if not usb_devices.exists():
        return None
    for d in usb_devices.iterdir():
        vid_path = d / "idVendor"
        pid_path = d / "idProduct"
        if vid_path.exists() and pid_path.exists():
            vid = vid_path.read_text().strip()
            pid = pid_path.read_text().strip()
            if vid == "0955" and pid == "7321":
                return str(d)
    return None


def save_hardware_snapshot(out_path: Path | str, device_id: bytes | None = None) -> Path:
    """Capture all available hardware info and save to JSON."""
    out_path = Path(out_path)
    snapshot: dict[str, Any] = {}

    sysfs = find_tegra_sysfs()
    if sysfs:
        desc = capture_from_sysfs(sysfs)
        if desc:
            snapshot["usb_descriptors"] = desc.to_dict()
            snapshot["sysfs_path"] = sysfs

    if device_id is not None:
        snapshot["device_id_hex"] = device_id.hex()
        snapshot["device_id_bytes"] = list(device_id)

        from .device_id import parse_device_id
        bcd = snapshot.get("usb_descriptors", {}).get("bcd_device")
        info = parse_device_id(device_id, bcd_device=bcd)
        snapshot["parsed_id"] = {
            "chip": info.chip,
            "revision": info.revision,
            "uid": f"0x{info.uid:08X}",
            "ecid": info.ecid.hex(),
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(snapshot, indent=2))
    return out_path
