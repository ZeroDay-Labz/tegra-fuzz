# RCM Chunk-by-Chunk Trace Analysis (Device 030)

## Discovery: Double-Buffer Ping-Pong DMA + Destination Copy Tracking

### Double-Buffering
The bootROM uses two 4096-byte DMA buffers alternately (ping-pong):
- **Buffer A**: 0x40005000-0x40006000 (odd chunks)
- **Buffer B**: 0x40009000-0x4000A000 (even chunks)

EP0 field `buf_20` = active DMA target (being filled by USB hardware)
EP0 field `ptr_84` = other buffer (being copied from to destination)
These are ALWAYS opposite — confirmed across all 48 readable chunks.

### Destination Copy Pointer (ptr_36)
ptr_36 at offset 36 tracks where the payload is being assembled:
- Post-claim: 0x40002E58 (USB descriptor area)
- After chunk 0: 0x40010D58 (payload start in bootloader area)
- Increments by 0x1000 per chunk thereafter
- After chunk 47: 0x4003FD58

**Chunk 0 is HEADER** — the first 4096 bytes contain the RCM message header
(length field, signature info, etc.). These are parsed but NOT copied to the
payload destination. The bootROM processes the header and sets ptr_36 to
0x40010D58 as the payload start address.

### Message Layout in IRAM
```
Payload start:  0x40010D58
Payload size:   0x2F298 (remaining after header chunk)
Payload end:    0x40010D58 + 0x2F298 = 0x4003FFF0
IRAM end:       0x40040000
Margin:         16 bytes (0x10)
```

The message fills IRAM almost exactly — 16 bytes of headroom.

### Field Meanings (Revised)

| Offset | Field | Meaning |
|--------|-------|---------|
| 12 | src_base | Stack frame pointer (0x4000FC84) |
| 20 | buf_20 | **Active DMA buffer** (alternates 0x40009000/0x40005000) |
| 28 | buf_28 | Same as buf_20 (mirror) |
| 32 | buf_32 | Same as buf_20 (mirror) |
| 36 | ptr_36 | **Destination copy pointer** (where next payload chunk goes) |
| 40 | rom_40 | 0x001079DB — ShofEL2 known addr (constant) |
| 44 | flag_44 | Endpoint state flag (1=normal, 4=halted) |
| 48 | stack_48 | Stack-relative pointer (0x4000FCDC) |
| 52 | buf_52 | Same as buf_20 (DMA buffer, mirror) |
| 56 | rom_56 | **Handler function** (0x00107AE5 = "receive chunk") |
| 60 | remaining | **Bytes remaining to receive** (decrements by 0x1000/chunk) |
| 64 | chunk_size | **Total bytes received so far** (NOT chunk size!) |
| 72 | rom_72 | 0x0010254B — bootROM function |
| 76 | ptr_76 | 0x40005000 — secondary buffer base |
| 84 | ptr_84 | **Inactive DMA buffer** (opposite of buf_20) |
| 120 | rom_120 | 0x0010293B — bootROM function |

### State Transitions

```
pre-handshake → post_claim:
  ptr_36: 0x40002990 → 0x40002E58
  rom_56: 0x00107B23 → 0x00107AE5  (USB handler → receive handler)
  rom_72: 0x00102AD1 → 0x0010254B
  rom_120: 0x28C5FA74 → 0x0010293B  (garbage? → bootROM function)

post_claim → chunk_0:
  ptr_36: 0x40002E58 → 0x40010D58  (USB desc → payload destination)
  remaining: 1024 → 193176 (0x2F298)
  chunk_size: 0 → 4096

chunk_N → chunk_N+1 (steady state):
  ptr_36: +0x1000
  buf_20: alternates
  ptr_84: alternates (opposite of buf_20)
  remaining: -0x1000
  chunk_size: +0x1000
  All ROM pointers: UNCHANGED
```

### Key Observation: Header Controls Destination?
The destination pointer (ptr_36) jumps from 0x40002E58 to 0x40010D58 after chunk 0.
This ~0xDF00 jump does NOT match a simple +0x1000 increment.

**Question**: Does the header data determine where ptr_36 lands?
If a field in the first chunk controls the destination address, we could redirect
the payload copy to overwrite the IPATCH SVC handler (0x40004C30) or the stack.

The offset 0xD58 within the bootloader area (0x40010000) may come from:
1. A BCT LoadAddress field
2. A hardcoded offset in bootROM
3. A calculated offset from message header fields

**header_probe.py** was built to test this hypothesis.

### Complete IRAM Memory Map (Updated)

```
0x40000000-0x40002800  BCT (Boot Configuration Table)
0x400028E4             Debug auth IPATCH target
0x40002990             USB data structures (pre-claim)
0x40002E30-0x40002E60  USB descriptor area
0x40002E58             Pre-payload ptr_36 destination
0x40003114             IRAM struct
0x40004C28             Warmboot entry (Patch 8 target)
0x40004C30             IPATCH SVC handler base (T210)
0x40005000-0x40006000  DMA double-buffer A (4096B) [odd chunks]
0x40006000-0x40007000  (unused?)
0x40007000-0x40008000  NX boot stub stack
0x40008000-0x40009000  Stack (grows down from 0x40008000)
0x40009000-0x4000A000  DMA double-buffer B (4096B) [even chunks]
0x4000A000-0x40010000  Unknown gap (24KB)
0x40010000             Bootloader load address
0x40010020             Entry point (1.0.0-3.0.2)
0x40010040             Entry point (4.0.0+)
0x40010D58-0x4003FFF0  RCM MESSAGE PAYLOAD (192KB)
0x40013FE0             PK11 blob address (within payload region)
0x4003FFF0-0x40040000  IRAM end margin (16 bytes)
```

### Timing
- Bulk writes: 121-243us per chunk (avg 131us)
- Final response: 91us (signature verification)
- EP0 reads between chunks: ~1ms each
- Total instrumented send: ~200ms for 49 chunks with 48 EP0 reads

### Attack Vectors to Explore
1. **Header field manipulation** → Can we change ptr_36 destination?
2. **Partial header** → What if chunk 0 has wrong length but valid structure?
3. **Chunk-by-chunk IRAM modification** → Can SET_FEATURE HALT change byte[44]
   between chunks and affect processing?
4. **Race condition** → EP0 read happening while DMA writes — does the
   bootROM serialize these or could they race?
