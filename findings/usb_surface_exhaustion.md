# USB Attack Surface Exhaustion Report

## Device: Nintendo Switch (XAW4 001878), Tegra X1 Erista, PATCHED
## Date: 2026-11-19 through 2026-11-20
## Devices consumed: 031-039 (9 sessions)

## Summary
The USB attack surface of this patched Tegra X1 bootROM has been systematically
tested and is **exhausted**. No code execution vector was found via USB.

## Vectors Tested and Eliminated

### 1. DMA Buffer Overflow (CVE-2018-6242 variant)
- **Result**: PATCHED. Only length=0x30298 accepted; all others rejected (0x08)
- **Evidence**: Devices 027-030 tested multiple lengths

### 2. EP0 wLength Overflow
- **Result**: PATCHED. IPATCH Patch 3 caps wLength to 255 (uint8 masking)
- **Evidence**: GET_STATUS returns max 255B; wLength value visible at offset 8

### 3. Header-Controlled Destination Redirect
- **Result**: HARDCODED. Destination copy pointer always lands at 0x40010D58
- **Tests**: baseline, bct_load (offset 0x18 = SVC handler), all_ff (all 0xFF)
- **Evidence**: Devices 031-033, all show ptr_36 = 0x40010D58 regardless of header
- **Conclusion**: The 0xD58 offset is a fixed bootROM constant, not from the message

### 4. Mid-Transfer State Manipulation (EP HALT)
- **EP_IN HALT**: Accepted but flag44 stays at 1; permanently breaks response
- **EP_OUT HALT**: Changes flag44 to 4; cleanly reversible; transfer resumes normally
- **Result**: No effect on destination pointer, remaining count, or processing
- **Evidence**: Devices 035-036

### 5. Timing Side-Channel
- **Result**: 35μs response = early check failure (CMAC/header), not RSA
- **Conclusion**: Content doesn't matter; timing is not viable

### 6. Descriptor Over-Read
- **Result**: Only GET_STATUS over-reads IRAM. GET_DESCRIPTOR returns exact lengths
- **Evidence**: Device 039 — device(18B), config(32B), qualifier(10B) all exact

### 7. Alternate EP0 Windows
- **High endpoint indices (0x82+)**: ERR:5, destroys USB controller
- **Non-zero wValue in GET_STATUS**: No effect
- **Vendor requests (0xC0-0xC2)**: No response
- **Class requests (0xA0-0xA2)**: No response
- **Varied bRequest on endpoint recipient**: No new data
- **Evidence**: Device 037 (window scan)

### 8. Incomplete Transfer Exploitation
- **1-byte write**: Hangs bootROM forever, EP0 alive, IRAM readable
- **Full chunk then stop**: Same hang, same IRAM exposure
- **Split-send resume**: Works normally, returns 0x0F
- **Result**: The hung state exposes IRAM but provides no write primitive
- **Evidence**: Devices 028-030

### 9. Transfer Timeout Exploitation
- **Result**: BootROM has NO internal timeout. Waits forever for remaining chunks
- **Implication**: Infinite instrumentation window, but no exploitable state

## What We Learned (Positive Findings)

### Complete IRAM Field Map (EP0 offset → meaning)
16 fields decoded via chunk-by-chunk trace (device 030, 49 snapshots):
- Double-buffer ping-pong DMA: 0x40005000/0x40009000 alternating
- Destination copy pointer at offset 36 (0x40010D58, +0x1000/chunk)
- Remaining count at offset 60 (decrements by 0x1000)
- Total received at offset 64 (running sum)
- EP_OUT halt flag at offset 44

### BootROM Code Addresses Leaked
7 unique addresses in 0x00100000-0x00112000 range:
- 0x001079DB (ShofEL2 known), 0x00107AE5, 0x00107B23
- 0x0010254B, 0x00102AD1, 0x0010291B, 0x0010293B
- 0x0010769A (IPATCH Patch 3 target)

### IRAM Memory Map
Complete layout from 0x40000000 (BCT) through 0x40040000 (IRAM end),
including DMA buffers, stack, SVC handler, and message payload regions.

### Operational Knowledge
- Pre-claim EP0 read is REQUIRED for reliable bulk writes
- High-endpoint GET_STATUS (wIndex >= 0x82) kills the USB controller
- SET_ADDRESS (bRequest=0x05) corrupts host xHCI controller

## Remaining Vectors (Non-USB)

1. **T210 BootROM static analysis** — Need actual bootROM binary dump for Ghidra/REA
   - 7 leaked code addresses need cross-referencing
   - May reveal non-USB vulnerabilities in signature verification or boot flow

2. **TSEC Falcon coprocessor** — Hardware security engine with known class of flaws
   - Requires firmware RE; version unknown on this unit

3. **Fuse analysis** — Read FUSE_OPT_FT_REV to confirm patch generation
   - Determines which IPATCH behaviors are active

4. **Boot chain beyond RCM** — Package1/TSEC/Warmboot paths
   - Different attack surface than USB/RCM
