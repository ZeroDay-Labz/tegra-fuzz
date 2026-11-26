# Findings

Evidence collected during authorized security research on my own Nintendo Switch
(serial XAW4 001878, Tegra X1 / T210 Erista).

## Evidence files

### `hardware_snapshot.json`

USB descriptor data and parsed device identity captured from the live device in
RCM mode (Bus 003, topology path `3-2.4`).

**How it was collected:** `tegra_fuzz.usb_info.save_hardware_snapshot()` reads
sysfs attributes at `/sys/bus/usb/devices/3-2.4` and the 16-byte RCM device ID
via bulk IN endpoint 0x81. All reads are passive — no data is sent to the device.

**What it establishes:**

- SoC is T210 (Erista), not T210B01 (Mariko) — determined by USB PID 0x7321 and
  product string "APX". Mariko uses XUSB and presents differently.
- Silicon revision A02 (production) — from bcdDevice 0x0102. Note: bcdDevice is
  the USB device-release descriptor field, not an IPATCH fuse indicator.
- Device ID (ECID): `40810205000000080047506401101062`. This is composed of
  one-time-programmable fuse values (vendor code, fab code, lot codes, wafer ID,
  X/Y coordinates). The exact byte packing is undocumented by NVIDIA. No
  open-source tool (fusee-launcher, Hekate, Linux kernel) parses it.
- ECID does **not** contain IPATCH fuse state. Those are separate fuse fields
  (FUSE_OPT_FT_REV, FUSE_OPT_CP_REV) readable only from software running on the
  SoC, not from the host side via USB.

**What it does not establish:**

- IPATCH fuse configuration
- Firmware version
- Whether the device is patched or unpatched

---

### `exploit_attempt_evidence.json`

Record of a Fusée Gelée (CVE-2018-6242) exploit attempt on 2026-11-19.

**How it was collected:** `tegra_fuzz.payload` sent the Hekate v6.5.5 payload
(110,208 bytes, exploit buffer 180,224 bytes, 44 chunks) using the reference
fusee-launcher flow: bulk OUT writes + GET_STATUS control transfer trigger with
wLength=0x4000. The kernel USB event log (`dmesg`) was captured before and after.

**Code audit status:** `payload.py` was audited against the reference
fusee-launcher (Smeat/Qyriad/ktemkin). The intermezzo relocator (92 bytes), all
IRAM addresses, stack spray construction, buffer switching logic, and trigger
sequence match byte-for-byte. Error handling matches the reference:
`_write_single_buffer` swallows `USBTimeoutError` only (narrow);
`_trigger_controlled_memcpy` swallows all `USBError` (broad but correct — the
device stops responding either way after the trigger).

**What was observed:**

1. APX/RCM device (0955:7321) enumerated at kernel timestamp +266752s on USB
   path `3-2.4`
2. Host program reported sending 44 chunks and the GET_STATUS trigger
3. No Hekate boot screen or other payload output appeared
4. APX device disconnected at +269240s (~41 min after enumeration)
5. Nintendo Switch USB HID device (057E:2000) appeared at +269247s on the same
   USB path
6. Nintendo HID interface initialized (`hid-generic 0003:057E:2000`)
7. Nintendo device disconnected at +269273s
8. User re-entered RCM; new APX device (0955:7321) appeared at +269284s

**Interpretation:** Consistent with the console leaving RCM and continuing into
its normal Horizon OS boot path. No successful custom payload execution was
observed.

**What it does not establish:**

- **Why** the RCM session ended. The USB transition is consistent with a patched
  bootROM rejecting the overflow, but also with other causes (RCM timeout, user
  action, etc.).
- Exact host-side payload transmission timing. The kernel log shows a 41-minute
  window between APX enumeration and disconnect. The exploit ran within that
  window but its precise timestamps are not in the kernel log.
- That the device received every byte correctly. Host-side write completion
  reports from pyusb do not prove device-side reception.
- IPATCH fuse state. No direct fuse data was collected.

**Patch status after this test: UNCONFIRMED.**

Supporting indicators: serial range XAW4 001878 falls in the possibly-patched
range. The code is correct (audit confirmed). The exploit was not demonstrated.
But these observations do not definitively distinguish patched from unpatched
hardware. A definitive determination requires either: (1) reading IPATCH fuse
registers directly (requires code execution on the SoC), or (2) a more
instrumented attempt that timestamps each USB transaction and distinguishes
bootROM rejection from other RCM exit causes.

---

### `dmesg_usb_history.txt`

Raw kernel log lines matching USB VID/PID 0955:7321 (Tegra APX) and
057E:2000 (Nintendo Switch). Contains all USB enumeration and disconnect events
across all research sessions.

**Notable entries:**

- 16 APX/RCM (0955:7321) enumerations across the research period
- 3 Nintendo Switch (057E:2000) appearances — the device booted into Horizon OS
  three separate times while connected via USB
- Two of the three Nintendo Switch appearances (at +262912s and +262965s) occurred
  **before** the exploit attempt, establishing that RCM-to-Horizon transitions are
  part of the device's normal behavior and not unique to the exploit attempt
- The first two APX connections used USB path `3-4`; subsequent ones used `3-2.4`
  (different physical port or hub path on the host)

---

## What has been tried

| Date | Action | Result |
| --- | --- | --- |
| 2026-11-19 | Device identification via USB descriptors | T210 Erista A02 confirmed |
| 2026-11-19 | RCM device ID read (16 bytes) | ECID captured; no IPATCH data in this field |
| 2026-11-19 | Fusée Gelée exploit attempt (Hekate v6.5.5) | Not demonstrated. Console left RCM, booted into Horizon OS. |
| 2026-11-19 | Code audit of payload.py | Matches reference fusee-launcher byte-for-byte |
| 2026-11-19 | Fuzzer dry-run (FakeTransport) | 65/65 tests pass, all outcome paths verified |

## What has not been tried

- Direct IPATCH fuse reads (requires code execution on SoC)
- Instrumented exploit attempt with per-transaction host-side timestamps
- USB traffic capture (usbmon) during exploit attempt
- Firmware version determination (requires checking Settings → System →
  System Information on the console — does not trigger updates)
- Warmboot / deep sleep exploit research
- TSEC firmware analysis
- Horizon OS system module fuzzing
- Peripheral interface (Bluetooth, Wi-Fi, NFC) research

## Prior art and reference research

### fail0verflow — ShofEL2 (2018)

Source: https://fail0verflow.com/blog/2018/shofel2/
Code: https://github.com/fail0verflow/shofel2

fail0verflow independently discovered the same bootROM vulnerability exploited
by Fusée Gelée (CVE-2018-6242). They found it first, began responsible disclosure
with Google 90 days prior, and were preparing to release when the bug was leaked
by another group two days before their disclosure window expired.

**Key technical details from fail0verflow:**

- The vulnerability is in the **RCM mode USB handling** in the Tegra X1 Boot ROM.
  RCM is intended for initial flashing and recovery, and normally only allows
  signed images. The bug allows arbitrary code execution.
- The bug is in **mask ROM** — cannot be patched without a hardware revision.
  Nintendo later addressed this by burning IPATCH fuses on newer units, which
  apply runtime patches to the ROM.
- The exploit is a "tethered jailbreak" (semi-tethered) — must be performed via
  USB on every boot. It does not touch the eMMC, making it undetectable to the
  Switch OS and allowing dual-boot.
- Their boot chain: `BootROM exploit → coreboot loader → coreboot → ARM TF →
  coreboot → u-boot → Linux`. The only closed-source component is NVIDIA's DDR4
  memory training blob (tegra_mtc.bin). Without it, RAM runs at ~200MHz.
- Entering RCM requires grounding Pin 10 on the right Joy-Con rail (the "Home"
  button in Tegra terms) while holding Volume Up and Power. A simple wire bridge,
  3D-printed jig, or disassembled Joy-Con connector works.
- The exploit requires a USB host with xHCI (USB 3.0). EHCI (USB 2.0) works
  with a kernel patch for long control transfers.
- Linux on Switch: GPU works (Mesa with patches), touchscreen, WiFi (buggy
  first boot), backlight, fan (thermal-managed), light sensor, battery gauge,
  basic USB charging. Missing at the time: sound (no mainline Tegra X1 audio
  driver), USB-PD, power button, dock support.

**Relevance to this project:**

- fail0verflow's blog confirms "there are actually many Boot ROM bugs" beyond
  the DMA overflow. This supports continued fuzzing research even if
  CVE-2018-6242 is patched on this unit.
- Their implementation (ShofEL2) uses a different boot chain than fusee-launcher
  but exploits the same underlying vulnerability. Our code audit verified
  `payload.py` against fusee-launcher, not ShofEL2 — a cross-reference against
  ShofEL2's `exploit/` directory would be an additional validation.
- The blog's comment section confirms IPATCH ("ipatched switches") was
  Nintendo's response — newer units patch the bootROM at runtime via fuses. This
  is exactly the mechanism we cannot read from the host side.
- Their observation that RCM mode is completely undetectable to Horizon OS is
  relevant: our dmesg logs showing 057E:2000 appearances before and after
  the exploit attempt are consistent with normal device behavior.
- PID 0x7721 is mentioned for NVIDIA Shield — this matches what we have in
  `device_id.py` as `MARIKO_PID`. (Note: fail0verflow's blog says Shield, not
  Mariko. The T210B01/Mariko Switch also uses 0x7721, suggesting it inherited the
  XUSB stack from NVIDIA's other Tegra products.)

### Fusée Gelée / CVE-2018-6242 (ktemkin, 2018)

Discoverer: Katherine Temkin (ktemkin)
Reference implementation: https://github.com/Qyriad/fusee-launcher

The public disclosure that our `payload.py` is based on. The vulnerability is a
DMA buffer overflow in the bootROM's RCM USB stack: the host declares a transfer
length in the RCM command, and the bootROM copies that many bytes into a fixed
IRAM buffer without bounds checking. By alternating USB endpoint buffers and
sending more data than the buffer can hold, the attacker overwrites the return
address on the bootROM's stack.

**Exploit flow (as implemented in our `payload.py` and verified by code audit):**

1. Read 16-byte device ID from bulk IN endpoint 0x81 (the handshake)
2. Construct exploit buffer: RCM header declaring 0x30298 bytes → intermezzo
   (92-byte ARM relocator at 0x40010000) → padding → actual payload (Hekate) →
   stack spray pointing to intermezzo
3. Write the buffer in 0x1000-byte chunks via bulk OUT endpoint 0x01, switching
   between high and low buffer addresses on the device side
4. Trigger the overflow via GET_STATUS control transfer with wLength=0x4000

The intermezzo is necessary because the initial execution address (the
overwritten return address) is in IRAM at a location that only fits a small
relocator. The intermezzo copies the actual payload to its final IRAM location
and jumps to it.

### Hekate (CTCaer)

Source: https://github.com/CTCaer/hekate

The payload binary we used (`hekate_ctcaer_6.5.5.bin`). Hekate is a custom
bootloader/payload for the Nintendo Switch that provides a graphical menu for
booting custom firmware, backing up NAND, and other operations. If the exploit
succeeds, Hekate's splash screen is immediately visible — its absence after our
attempt is a negative indicator (but not proof of patching, since other failure
modes exist).

---

## Methodology notes

- All research is on hardware I own
- The RCM bootROM is mask ROM — malformed input can hang or reset it until RCM is
  re-entered, but cannot permanently modify the bootROM or the console
- Evidence files distinguish observations from interpretations
- The code audit verified the exploit implementation is correct; the question is
  whether the hardware accepts it, not whether the software is broken
- Prior art is documented with sources so findings can be cross-referenced
