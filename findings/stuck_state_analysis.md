# Stuck-State IRAM Analysis (Device 028)

## Discovery
Sending a 1-byte short packet as the first bulk write causes the bootROM to hang
(no response) while remaining alive on USB. EP0 control transfers still work.

## Procedure
1. Pre-handshake: `iram_deep` mapped all EP0 windows (baseline)
2. `usb_edge tiny_first`: claim → device ID → write 1 byte → TIMEOUT
3. Follow-up: wrote 4095 more bytes → still no response, but IRAM shows full processing
4. EP0 reads reveal the bootROM's internal state mid-transfer

## IRAM State Changes (Pre-handshake → Stuck)

### Stack
- src_base: 0x4000FC94 → 0x4000FC84 (-0x10, stack push from claim+ID+write)
- near-stack: 0x4000FCE0 → 0x4000FCDC (-4)

### Buffer Pointers
- Offsets 20,28,32,52: 0x40009000 → 0x40005000
  - DMA buffer moved from normal location to a different IRAM region
  - 0x40005000 is BEFORE the stack pointer (0x40008000)

### New BootROM Function Addresses
| Offset | Pre-handshake | Stuck State | Interpretation |
|--------|---------------|-------------|----------------|
| 36 | 0x40002990 | 0x40010D58 | IRAM→bootloader area |
| 56 | 0x00107B23 | 0x00107AE5 | USB handler state transition |
| 72 | 0x00102AD1 | 0x0010254B | New bootROM function |
| 120 | 0x00102929 | 0x0010293B | Different call path |

### Message Processing State (NEW!)
| Offset | Value | Interpretation |
|--------|-------|----------------|
| 60 | 0x0002F298 | Remaining bytes (0x30298 - 0x1000) |
| 64 | 0x00001000 | Chunk size (4096) |

The bootROM parsed length=0x30298 from the first chunk and is WAITING for 47 more chunks.
Remaining = MSG_LEN - CHUNK = 0x2F298. This confirms the bootROM calculates
remaining based on DECLARED length, not actual received bytes.

## USB Behavior in Stuck State
- EP0 control transfers: FULLY FUNCTIONAL
- Bulk EP_OUT write: Pipe error (endpoint broken)
- Bulk EP_IN read: Timeout (no response queued)
- SET_FEATURE (all values): STALL
- SYNCH_FRAME: Returns frame number (0x0011)

## Implications
1. The 1-byte + 4095-byte split was combined by USB hardware into one 4096B chunk
2. The bootROM processes the length field from bytes 0-3 of the first chunk
3. IRAM contains the remaining transfer size — if writable, could control DMA
4. No EP0 write primitive reaches the remaining count field
5. Buffer pointers changed post-claim, suggesting multiple buffer regions in IRAM

## All BootROM Addresses Found (Combined)
Pre-handshake: 0x001079DB, 0x00107B23, 0x00102AD1, 0x0010291B, 0x00102929
Post-claim: 0x001079DB (unchanged), 0x00107AE5, 0x0010254B, 0x0010293B
From IPATCH: 0x0010769A (Patch 3 target), 0x001007B0, 0x001007F8 (SVC dispatch)
