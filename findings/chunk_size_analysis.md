# Chunk Size Acceptance Analysis

## Device: 041 (Nintendo Switch XAW4 001878, Tegra X1 Erista, PATCHED)
## Date: 2026-11-20

## Summary
The bootROM accepts **arbitrary USB bulk transfer sizes**, not just 4096 bytes.
However, the DMA is capped at 4096 bytes per transfer — no memory overflow occurs.
An **accounting desync** exists: ptr/rem/total use the full USB transfer size, not the DMA size.

## Short Chunks (< 4096 bytes)

| Size | ptr delta | rem delta | DMA'd | Notes |
|------|-----------|-----------|-------|-------|
| 4095 | 0xFFF | 0xFFF | 4095 | Exact match — DMA == USB size |
| 4096 | 0x1000 | 0x1000 | 4096 | Normal operation |

Short chunks: DMA transfers EXACT USB size (no cap). Destination becomes misaligned.

## Oversized Chunks (> 4096 bytes)

| Size | ptr delta | rem delta | DMA'd | Notes |
|------|-----------|-----------|-------|-------|
| 4097 | 0x1001 | 0x1001 | 4096 | 1B accounting overshoot |
| 6144 | 0x1000 | 0x1000 | 4096 | Anomalous — only 4096 counted |
| 8192 | 0x2000 | 0x2000 | 4096 | Accounting uses full USB size |
| 12288 | 0x3000 | 0x3000 | 4096 | Confirmed |
| 16384 | 0x4000 | 0x4000 | 4096 | Confirmed |
| 24576 | 0x6000 | 0x6000 | 4096 | Confirmed |
| 32768 | 0x8000 | 0x8000 | 4096 | Confirmed — no IRAM corruption |

## DMA Overflow Verification

### Test 1: 32KB of zeros from buffer B
- Sent 32KB (0x8000) to buffer B (0x40009000)
- If DMA overflowed: would write through 0x4000A000-0x40010FFF
- EP0 state struct at ~0x4000FC84 would be overwritten with zeros
- **Result: NO EP0 changes** — struct values unchanged

### Test 2: 32KB with address markers from buffer B
- Each 4-byte word = buffer_start + offset (e.g., 0x4000FC84 at the right offset)
- **Result: NO EP0 changes** — coincidental match at src_base offset,
  but buf_20 (offset 20) would have changed to 0x4000FC8C if overflow were real
- buf_20 stayed at 0x40009000 → **overflow NOT happening**

### Test 3: Message completion after oversized chunks
- Sent remaining bytes (0xC298) in normal 4096B chunks after oversized chunks
- **Result: Normal 0x0F response** — no crash, no unusual behavior
- Confirms the function return address was NOT corrupted

## Conclusion
**DMA is capped at 4096 bytes per transfer.** The DMA hardware descriptor limits
the write to the configured buffer size. The USB FIFO accepts all host data
(all packets ACK'd), but only 4096 bytes are transferred to IRAM via DMA.
The remaining data is discarded from the FIFO.

The bootROM reads the USB transfer size from a register that counts total
bytes received (including FIFO data), not just DMA-transferred bytes.
This creates an accounting desync but no memory corruption.

## Exploitability Assessment
- Direct DMA overflow: **NOT EXPLOITABLE** (DMA capped)
- Accounting desync: **POTENTIALLY EXPLOITABLE** via remaining counter underflow
  - If remaining goes negative (unsigned wrap), the receive loop might not exit
  - Or the message might process with ptr past IRAM end
  - Needs further testing
- Short chunk misalignment: **LOW PROBABILITY** — ARM handles unaligned access
- OUT control transfers: **ALL REJECTED** — STALL or timeout on every request type
