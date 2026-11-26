# IPATCH Boundary Analysis (2026-11-19)

## Key Findings

### RCM Protocol: Fixed Message Size
The bootROM accepts **only** `length == 0x30298`. This is NOT a range check or maximum —
it is the fixed RCM message size in the T210 protocol. Any other value is rejected with status 0x08
after the first chunk.

### Status Codes
- **0x00000008**: Message rejected (wrong length, or any length != 0x30298)
- **0x0000000F**: Message fully processed through signature verification, which FAILED

### Length Probing Results (Binary Search)
| Length | Status | Chunks Accepted | Notes |
|--------|--------|-----------------|-------|
| 0x0 | 0x08 | 1 of 2 | Zero length — rejected |
| 0x4 | 0x08 | 1 of 2 | Minimal non-zero — rejected |
| 0x2A4 | 0x08 | 1 of 2 | Min RCM header (676B) — rejected |
| 0x1000 | 0x08 | 1 of 2 | 4096 — rejected |
| 0x10000 | 0x08 | 1 of 17 | 64KB — rejected |
| 0x30297 | 0x08 | 1 of 49 | CVE length - 1 — **REJECTED** |
| **0x30298** | **0x0F** | **49 of 49** | **CVE-2018-6242 exact length — ACCEPTED** |
| 0x30299 | 0x08 | 1 of 49 | CVE length + 1 — **REJECTED** |
| 0x30800 | 0x08 | 1 of 49 | Rejected |
| 0x31000 | 0x08 | 1 of 50 | Rejected |
| 0x32000 | 0x08 | 1 of 51 | Rejected |
| 0x34000 | 0x08 | 1 of 53 | Rejected |
| 0x38000 | 0x08 | 1 of 57 | Rejected |
| 0x40000 | 0x08 | 1 of 65 | IRAM size (256KB) — rejected |
| 0xFFFFFFFF | 0x08 | 1 of ?? | Max uint32 — rejected |

### DMA Overflow is PATCHED
Confirmed by sending 0x30298 bytes with these body patterns, all returning status 0x0F:
- All zeros (0x00)
- All 0xFF
- All 0x41 ('A')
- Crafted exploit payload (return addr at overflow offset, NOP sled + infinite loop at payload offset)

If the DMA overflow still happened, the return address would be overwritten and the bootROM
would crash/hang instead of returning status 0x0F. The IPATCH caps the DMA copy to the buffer
size (~0x30000 bytes). The extra 0x298 bytes of declared message are NOT written past the buffer.

### Body Content Does Not Affect Status for len=0x30298
All-zeros, all-0xFF, all-0xDE, crafted payloads — all return status 0x0F. The bootROM
performs RSA-PSS signature verification on the data and returns "signature failed" regardless
of content (since we don't have NVIDIA's signing key).

## EP0 Control Transfer Findings

### Over-Read Caps at 255 Bytes
The bootROM's USB controller uses a uint8 for the data phase length.
- wLength=255: returns 255 bytes (maximum)
- wLength=256: returns 0 bytes (wraps to 0)
- wLength=300: returns 44 bytes (300 mod 256 = 44)
- wLength=512: returns 0 bytes (512 mod 256 = 0)

### Responding Request Types (pre-handshake only)
| bmRequestType | bRequest | Description | Returns |
|---------------|----------|-------------|---------|
| 0x80 | 0x00 | GET_STATUS device | 2B: `0x0100` (self-powered) — no over-read |
| 0x80 | 0x08 | GET_CONFIGURATION | 255B: `0x01` + 254B zeros — over-read but mostly zeros |
| 0x81 | 0x00 | GET_STATUS interface | 255B: IRAM leak starting 4B earlier than endpoint |
| 0x81 | 0x0A | GET_INTERFACE | 255B: all zeros |
| 0x82 | 0x00 | GET_STATUS endpoint | 255B: **IRAM leak with bootROM pointers** |

All other standard, vendor (0xC0-0xC2), and class (0xA0-0xA2) requests return STALL or nothing.

### No Write Primitives
- SET_DESCRIPTOR (0x07): STALL on all descriptor types
- Vendor OUT (0x40, 0x41, 0x42): STALL on all bRequest values
- SET_INTERFACE: accepts ANY alt setting value (0-0xFFFF) — bug but no visible effect on IRAM
- SET/CLEAR_FEATURE HALT: works, changes endpoint status word, does NOT change over-read data

### EP0 Dies Post-Handshake AND Post-Message
After claiming the interface and reading the device ID, EP0 times out.
After sending an RCM message and receiving the response, EP0 also times out.
Both bulk endpoints also stall after the single message exchange.

## Critical Discovery: Halt Clear Breaks EP_IN
Sending CLEAR_FEATURE HALT on EP_IN (0x81) before the bulk write prevents the bootROM
from sending the response. The working setup sequence:
1. EP0 GET_STATUS (pre-handshake IRAM over-read)
2. set_configuration (fails "Resource busy" — OK)
3. Bulk read device ID (16 bytes)
4. Bulk write RCM message (timeout=2000ms)
5. Bulk read response (4 bytes)
No halt clear at any point.
