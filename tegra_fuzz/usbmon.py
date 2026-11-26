"""USB traffic capture via usbmon for instrumented exploit/fuzz sessions.

usbmon is a Linux kernel facility that logs USB transactions. This module
captures traffic on the bus where the Tegra APX device is connected, providing
exact timestamps for every USB transfer — closing the timing gap identified in
the exploit evidence review.

Usage:
    # Capture during an exploit attempt:
    sudo python -m tegra_fuzz.usbmon --bus 3 --duration 30

    # Or use programmatically:
    from tegra_fuzz.usbmon import UsbmonCapture
    with UsbmonCapture(bus=3) as cap:
        # ... do exploit/fuzz work ...
        events = cap.stop()
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class UsbmonEvent:
    timestamp_us: int
    event_type: str       # "S" submit, "C" callback, "E" error
    direction: str        # "IN" or "OUT"
    endpoint: int
    device: int
    bus: int
    length: int
    status: int = 0
    data_hex: str = ""
    setup_hex: str = ""   # for control transfers: 8-byte setup packet
    raw_line: str = ""

    def to_dict(self):
        return asdict(self)


def parse_usbmon_line(line: str) -> UsbmonEvent | None:
    """Parse a single usbmon text line (format 'u' from /sys/kernel/debug/usb/usbmon/Xu).

    Format: <urb_tag> <timestamp_us> <event_type> <address> <endpoint> <status/length> <data>
    Example: d5a4e300 3862934145 S Ci:3:028:0 s 80 06 0100 0000 0012 18 <
    """
    parts = line.strip().split()
    if len(parts) < 5:
        return None

    try:
        timestamp = int(parts[1])
        event_type = parts[2]  # S, C, E

        addr_parts = parts[3].split(":")
        if len(addr_parts) < 4:
            return None

        direction = "OUT" if addr_parts[0].endswith("o") else "IN"
        transfer_type = addr_parts[0][0]  # C=control, B=bulk, I=interrupt, Z=iso
        bus = int(addr_parts[1])
        device = int(addr_parts[2])
        endpoint = int(addr_parts[3])

        # For submit events on control transfers, bytes 4+ are the setup packet
        setup_hex = ""
        data_hex = ""
        length = 0
        status = 0

        if event_type == "S":
            if transfer_type == "C" and len(parts) > 4 and parts[4] == "s":
                setup_hex = " ".join(parts[5:10]) if len(parts) >= 10 else ""
                if len(parts) >= 11:
                    try:
                        length = int(parts[10])
                    except ValueError:
                        pass
            else:
                try:
                    length = int(parts[4])
                except (ValueError, IndexError):
                    pass
        elif event_type == "C":
            if len(parts) > 4:
                try:
                    status = int(parts[4])
                except ValueError:
                    pass
            if len(parts) > 5:
                try:
                    length = int(parts[5])
                except ValueError:
                    pass
            if len(parts) > 6 and parts[6] == "=":
                data_hex = " ".join(parts[7:])

        return UsbmonEvent(
            timestamp_us=timestamp,
            event_type=event_type,
            direction=direction,
            endpoint=endpoint,
            device=device,
            bus=bus,
            length=length,
            status=status,
            data_hex=data_hex,
            setup_hex=setup_hex,
            raw_line=line.strip(),
        )
    except (ValueError, IndexError):
        return None


class UsbmonCapture:
    """Context manager that captures usbmon traffic on a given USB bus."""

    def __init__(self, bus: int, device_filter: int | None = None):
        self.bus = bus
        self.device_filter = device_filter
        self._events: list[UsbmonEvent] = []
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._path = Path(f"/sys/kernel/debug/usb/usbmon/{bus}u")
        self._fd = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        if not self._path.exists():
            alt = Path(f"/dev/usbmon{self.bus}")
            if alt.exists():
                self._path = alt
            else:
                raise FileNotFoundError(
                    f"usbmon not available at {self._path} or {alt}. "
                    f"Try: sudo modprobe usbmon && sudo mount -t debugfs none /sys/kernel/debug"
                )

        self._fd = open(self._path, "r")
        self._stop.clear()
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        while not self._stop.is_set():
            line = self._fd.readline()
            if not line:
                time.sleep(0.001)
                continue
            evt = parse_usbmon_line(line)
            if evt is None:
                continue
            if self.device_filter is not None and evt.device != self.device_filter:
                continue
            self._events.append(evt)

    def stop(self) -> list[UsbmonEvent]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._fd:
            self._fd.close()
        return list(self._events)

    @property
    def events(self) -> list[UsbmonEvent]:
        return list(self._events)


def capture_session(bus: int, duration: float, device: int | None = None,
                    out_path: str | None = None) -> list[UsbmonEvent]:
    print(f"Capturing USB traffic on bus {bus} for {duration}s...", file=sys.stderr)
    if device:
        print(f"  Filtering device {device}", file=sys.stderr)

    with UsbmonCapture(bus=bus, device_filter=device) as cap:
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\nCapture interrupted.", file=sys.stderr)

        events = cap.stop()

    print(f"Captured {len(events)} USB events.", file=sys.stderr)

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "bus": bus,
            "device_filter": device,
            "duration_s": duration,
            "event_count": len(events),
            "events": [e.to_dict() for e in events],
        }
        p.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Saved to {p}", file=sys.stderr)

    return events


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Capture USB traffic via usbmon")
    parser.add_argument("--bus", type=int, required=True, help="USB bus number")
    parser.add_argument("--device", type=int, default=None, help="Filter by device number")
    parser.add_argument("--duration", type=float, default=30.0, help="Capture duration (seconds)")
    parser.add_argument("--out", default="findings/usbmon_capture.json", help="Output path")
    args = parser.parse_args()
    capture_session(args.bus, args.duration, args.device, args.out)


if __name__ == "__main__":
    main()
