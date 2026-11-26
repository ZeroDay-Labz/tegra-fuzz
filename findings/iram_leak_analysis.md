# IRAM Leak Analysis (2026-11-19)

## Overview
The EP0 GET_STATUS over-read bug leaks 255 bytes of IRAM content. Two distinct memory windows
are available via different request types, with the interface read starting 4 bytes earlier
than the endpoint read.

## Endpoint Over-Read (bmrt=0x82, GET_STATUS, widx=0x81)
255 bytes. All endpoint targets (0x00, 0x01, 0x80, 0x81) return identical data.

### Parsed as LE uint32 Words
```
Offset  Value       Interpretation
------  ----------  --------------------------------------------------
  [0]   0x00000000  Endpoint status (not halted)
  [4]   0x00000000  Padding / unused
  [8]   0x000000FF  wLength echo (255 = requested transfer size)
 [12]   0x4000FC94  ** src_base — IRAM stack/struct base **
 [16]   0x00000001  Flag or count
 [20]   0x40009000  ** dst_base — RCM DMA destination buffer **
 [24]   0x00000000  Zero
 [28]   0x40009000  dst_base (repeated)
 [32]   0x40009000  dst_base (repeated)
 [36]   0x40002990  IRAM address — unknown struct
 [40]   0x001079DB  ** bootROM code — ShofEL2 known return address **
 [44]   0x00000001  Flag or count
 [48]   0x4000FCE0  IRAM address — near src_base (+0x4C)
 [52]   0x40009000  dst_base (repeated)
 [56]   0x00107B23  ** bootROM code — unknown function **
 [60]   0x40005000  IRAM address — unknown region
 [64]   0x40002E30  IRAM address — unknown struct
 [68]   0x40003114  IRAM address — unknown struct
 [72]   0x00102AD1  ** bootROM code — unknown function **
 [76]   0x00880088  Possible config: two uint16 (0x0088, 0x0088)
 [80]   0x00002101  Possible config: 0x2101 (8449)
 [84]   0x0010291B  ** bootROM code — unknown function **
 [88]   0x40003114  IRAM address (same as offset 68)
 [92]   0x40002E50  IRAM address — unknown struct
 [96]   0x40002E30  IRAM address (same as offset 64)
[100]   0x00000238  Size field? 0x238 = 568 decimal
[104]   0x00102929  ** bootROM code — unknown function **
[108+]  High entropy data (146 bytes) — probable crypto material
```

### High Entropy Region (offset 108-254)
```
0x6c: 09 06 ce 44 a8 8f be fa d5 90 30 41 74 fa c5 28
0x7c: 72 0a b2 4f 92 2a f5 fa 50 b4 80 fe ab 32 12 d3
0x8c: 9a aa e7 4d 72 33 05 59 f3 fb 6b 3f d8 b8 1e 88
0x9c: f7 fe e8 25 8c 5f c5 df 2b dd e6 f5 ba 4c b7 74
0xac: 55 c1 c0 51 79 8e 08 d0 ac 8c 5a 8b a2 be 9f 2e
0xbc: 1f 8b c3 07 b5 74 4f 04 2c 95 b3 ca d1 85 92 14
0xcc: e0 e2 46 f0 ab 17 a3 4a 9f 47 cd 78 79 af cc 39
0xdc: 46 38 c4 c0 75 9f 87 2b 41 5e 1b 84 a8 8e 6f 3e
0xec: b2 0d 40 20 02 0a 1a 6e 61 f2 b4 2e f8 a6 e8 40
0xfc: 7a 0a b4 2a f3 27 61
```
This is 147 bytes of high-entropy data. Could be:
- Part of an RSA public key (full key is 256 or 512 bytes)
- AES key / IV material
- Hash/CMAC output
- RNG state
- Stack contents from previous crypto operations

## Interface Over-Read (bmrt=0x81, GET_STATUS, widx=0x00)
255 bytes. Starts 4 bytes earlier in IRAM than the endpoint read.

### Key Differences from Endpoint Read
- Offset 4: contains wLength echo (0xFF) — 4 bytes earlier than endpoint
- Offset 8: contains 0x4000FC98 (src_base + 4) instead of 0x4000FC94
- Rest of data matches endpoint read shifted by 4 bytes

Combined, the two windows cover ~259 bytes of contiguous IRAM.

## BootROM Code Addresses
All in the range 0x00100000-0x00112000 (typical T210 bootROM).

| Address    | Offset in Dump | Known Context |
|------------|----------------|---------------|
| 0x001079DB | [40]           | ShofEL2 exploited return address — this is the function that processes RCM messages |
| 0x00107B23 | [56]           | Unknown — possibly a caller of the RCM handler |
| 0x00102AD1 | [72]           | Unknown — possibly USB/DMA related |
| 0x0010291B | [84]           | Unknown — close to 0x00102929 |
| 0x00102929 | [104]          | Unknown — close to 0x0010291B |

The addresses 0x0010291B and 0x00102929 are only 14 bytes apart — they may be entry points
in the same function or adjacent functions in the USB handler code.

## IRAM Layout Addresses

| Address    | Offset in Dump | Purpose |
|------------|----------------|---------|
| 0x4000FC94 | [12]           | src_base — stack/struct base. ShofEL2 unpatched was 0x4000FC84 (+0x10 shift from IPATCH) |
| 0x4000FCE0 | [48]           | Near src_base (+0x4C). Possibly end of struct or another stack frame |
| 0x40009000 | [20,28,32,52]  | dst_base — RCM DMA buffer start. Matches ShofEL2 exactly |
| 0x40005000 | [60]           | Unknown IRAM region. Between dst_base and bottom of IRAM |
| 0x40002990 | [36]           | Unknown IRAM struct |
| 0x40002E30 | [64,96]        | Unknown IRAM struct (referenced twice) |
| 0x40002E50 | [92]           | Near 0x40002E30 (+0x20). Same struct array? |
| 0x40003114 | [68,88]        | Unknown IRAM struct (referenced twice) |

### IRAM Map (inferred)
```
0x40002990  - Unknown struct
0x40002E30  - Unknown struct (referenced 2x)
0x40002E50  - Unknown struct (+0x20 from above)
0x40003114  - Unknown struct (referenced 2x)
0x40005000  - Unknown region
0x40009000  - DMA buffer (dst_base), size ~0x30000
0x40039000  - End of DMA buffer (approx)
  ...
0x4000FC94  - src_base / stack struct base
0x4000FCE0  - Near src_base, possibly end of struct
```
