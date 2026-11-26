"""Parse the 16-byte Tegra X1 RCM device identifier.

The T210 bootROM sends a 16-byte device ID as the first bulk IN read during
the RCM handshake. This module extracts hardware identity fields from it.

Field layout (from fusee-launcher, Hekate, and Atmosphère source code):

  Bytes 0-3:   UID (lot/wafer info, little-endian u32)
  Bytes 4-15:  ECID (Electronic Chip ID, 96 bits)

The ECID encodes fab, lot, wafer, x/y coordinates, and implicitly the
chip revision. The USB PID distinguishes T210 (Erista, 0x7321) from
T210B01 (Mariko, 0x7721). bcdDevice encodes the silicon revision.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


ERISTA_PID = 0x7321
MARIKO_PID = 0x7721

NINTENDO_VID = 0x057E
SWITCH_PID = 0x2000
SWITCH_CHARGING_PID = 0x2009

BCD_REVISIONS = {
    0x0100: "A01 (engineering)",
    0x0101: "A01 (engineering)",
    0x0102: "A02 (production)",
    0x0103: "A03",
    0x0104: "A04",
}


@dataclass(frozen=True)
class DeviceInfo:
    raw: bytes
    uid: int
    ecid: bytes
    chip: str
    revision: str
    bcd_device: int | None = None

    def summary(self) -> str:
        lines = [
            f"  chip       : {self.chip}",
            f"  revision   : {self.revision}",
            f"  uid        : 0x{self.uid:08X}",
            f"  ecid       : {self.ecid.hex()}",
            f"  raw        : {self.raw.hex()}",
        ]
        return "\n".join(lines)


def parse_device_id(
    raw: bytes,
    pid: int = ERISTA_PID,
    bcd_device: int | None = None,
) -> DeviceInfo:
    """Parse a 16-byte RCM device ID into structured hardware info."""
    if len(raw) != 16:
        raise ValueError(f"expected 16 bytes, got {len(raw)}")

    uid = struct.unpack_from("<I", raw, 0)[0]
    ecid = raw[4:16]

    if pid == MARIKO_PID:
        chip = "T210B01 (Mariko)"
    elif pid == ERISTA_PID:
        chip = "T210 (Erista)"
    else:
        chip = f"unknown (PID 0x{pid:04X})"

    if bcd_device is not None:
        revision = BCD_REVISIONS.get(bcd_device, f"unknown (bcdDevice 0x{bcd_device:04X})")
    else:
        revision = "unknown (no bcdDevice)"

    return DeviceInfo(
        raw=raw,
        uid=uid,
        ecid=ecid,
        chip=chip,
        revision=revision,
        bcd_device=bcd_device,
    )
