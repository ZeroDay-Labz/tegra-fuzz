"""USB transport: the only module that touches hardware.

Defines a small :class:`Transport` protocol used by the engine, a real pyusb
implementation (:class:`UsbTransport`), and a :class:`FakeTransport` for tests and
offline dry-runs. All libusb/pyusb specifics are isolated here and surfaced as a
single :class:`TransportError` carrying a backend-agnostic ``kind``.
"""
from __future__ import annotations

import errno as _errno
from typing import Protocol

from . import rcm


class TransportError(Exception):
    """Backend-agnostic transfer failure.

    ``kind`` is one of: "timeout", "stall", "no_device", "permission", "error".
    """

    def __init__(self, kind: str, message: str = "", errno: int | None = None):
        super().__init__(message or kind)
        self.kind = kind
        self.errno = errno


class Transport(Protocol):
    def open(self) -> None: ...
    def close(self) -> None: ...
    def read_device_id(self, timeout_ms: int = 1000) -> bytes: ...
    def send_rcm(self, data: bytes, timeout_ms: int = 1000) -> int: ...
    def control(self, bmRequestType: int, bRequest: int, wValue: int,
                wIndex: int, data_or_length, timeout_ms: int = 1000) -> bytes: ...
    def probe_alive(self, timeout_ms: int = 500) -> bool: ...
    def reenumerated(self) -> bool: ...
    def reopen(self, timeout_ms: int = 2000) -> bool: ...
    def address(self) -> tuple[int, int] | None: ...


# --- real hardware --------------------------------------------------------------
def _map_usb_error(exc: Exception) -> TransportError:
    import usb.core  # local import so the module loads without pyusb installed

    errno = getattr(exc, "errno", None)
    if isinstance(exc, getattr(usb.core, "USBTimeoutError", ())):
        return TransportError("timeout", str(exc), errno)
    if errno == _errno.ETIMEDOUT:
        return TransportError("timeout", str(exc), errno)
    if errno == _errno.EPIPE:
        return TransportError("stall", str(exc), errno)
    if errno in (_errno.ENODEV, _errno.ENXIO, _errno.ENOENT):
        return TransportError("no_device", str(exc), errno)
    if errno in (_errno.EACCES, _errno.EPERM):
        return TransportError("permission", str(exc), errno)
    return TransportError("error", str(exc), errno)


class UsbTransport:
    """pyusb-backed transport to the Tegra APX (RCM) device."""

    def __init__(self, vid: int = rcm.VID, pid: int = rcm.PID):
        self.vid = vid
        self.pid = pid
        self._dev = None
        self._open_addr: tuple[int, int] | None = None

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
            raise _map_usb_error(exc) from exc
        self._dev = dev
        self._open_addr = (dev.bus, dev.address)

    def close(self) -> None:
        if self._dev is not None:
            import usb.util
            try:
                usb.util.dispose_resources(self._dev)
            except Exception:
                pass
        self._dev = None

    def address(self) -> tuple[int, int] | None:
        return self._open_addr

    def read_device_id(self, timeout_ms: int = 1000) -> bytes:
        if self._dev is None:
            raise TransportError("no_device", "device handle not open")
        import usb.core
        try:
            data = self._dev.read(rcm.EP_IN, rcm.DEVICE_ID_LENGTH, timeout=timeout_ms)
            return bytes(data)
        except usb.core.USBError as exc:
            raise _map_usb_error(exc) from exc

    def send_rcm(self, data: bytes, timeout_ms: int = 1000) -> int:
        if self._dev is None:
            raise TransportError("no_device", "device handle not open")
        import usb.core
        try:
            written = 0
            for off in range(0, max(len(data), 1), rcm.MAX_CHUNK):
                chunk = data[off:off + rcm.MAX_CHUNK]
                written += self._dev.write(rcm.EP_OUT, chunk, timeout=timeout_ms)
            return written
        except usb.core.USBError as exc:
            raise _map_usb_error(exc) from exc

    def control(self, bmRequestType, bRequest, wValue, wIndex,
                data_or_length, timeout_ms: int = 1000) -> bytes:
        if self._dev is None:
            raise TransportError("no_device", "device handle not open")
        import usb.core
        try:
            ret = self._dev.ctrl_transfer(
                bmRequestType, bRequest, wValue, wIndex, data_or_length, timeout_ms
            )
            return bytes(ret) if ret is not None and not isinstance(ret, int) else b""
        except usb.core.USBError as exc:
            raise _map_usb_error(exc) from exc

    def reenumerated(self) -> bool:
        dev = self._find()
        if dev is None:
            return False
        return (dev.bus, dev.address) != self._open_addr

    def probe_alive(self, timeout_ms: int = 500) -> bool:
        if self._dev is None:
            return False
        import usb.core
        dev = self._find()
        if dev is None:
            return False
        try:
            dev.ctrl_transfer(0x80, 0x06, 0x0100, 0x0000, 18, timeout_ms)
            return True
        except usb.core.USBError as exc:
            mapped = _map_usb_error(exc)
            # A stall/permission still means the device is physically answering;
            # only a timeout or a vanished device counts as not-alive.
            return mapped.kind not in ("timeout", "no_device")

    def reopen(self, timeout_ms: int = 2000) -> bool:
        import time
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            dev = self._find()
            if dev is not None:
                self.close()
                try:
                    self.open()
                    return True
                except TransportError:
                    pass
            time.sleep(0.05)
        return False


# --- fake transport for tests / offline dry-run ---------------------------------
class FakeTransport:
    """In-memory transport.

    Records every call. A ``script`` maps a predicate over a ``TestCase``-like call
    to a behaviour: return bytes, or raise a TransportError of some ``kind``. Used
    by the test suite to exercise every outcome path without hardware.
    """

    def __init__(self, device_id: bytes = b"\x00" * rcm.DEVICE_ID_LENGTH):
        self.device_id = device_id
        self.opened = False
        self.sent: list[bytes] = []
        self.controls: list[tuple] = []
        self._alive = True
        self._reenum = False
        self._addr: tuple[int, int] | None = (3, 12)
        # hooks the tests set:
        self.on_send = None        # callable(data) -> int | raises TransportError
        self.on_control = None     # callable(...) -> bytes | raises TransportError
        self.alive_sequence: list[bool] | None = None

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def address(self):
        return self._addr

    def read_device_id(self, timeout_ms: int = 1000) -> bytes:
        return self.device_id

    def send_rcm(self, data: bytes, timeout_ms: int = 1000) -> int:
        self.sent.append(data)
        if self.on_send is not None:
            return self.on_send(data)
        return len(data)

    def control(self, bmRequestType, bRequest, wValue, wIndex,
                data_or_length, timeout_ms: int = 1000) -> bytes:
        self.controls.append((bmRequestType, bRequest, wValue, wIndex, data_or_length))
        if self.on_control is not None:
            return self.on_control(bmRequestType, bRequest, wValue, wIndex, data_or_length)
        if isinstance(data_or_length, int):
            return bytes(min(data_or_length, 18))
        return b""

    def reenumerated(self) -> bool:
        return self._reenum

    def probe_alive(self, timeout_ms: int = 500) -> bool:
        if self.alive_sequence:
            return self.alive_sequence.pop(0)
        return self._alive

    def reopen(self, timeout_ms: int = 2000) -> bool:
        self._alive = True
        self.opened = True
        return True
