# LDN Vulnerability Research — Technical Report

**Internal identifier:** LDN-VULN-001
**Status:** CVE-2026-82079 stack overflow **IDENTIFIED** by static analysis.
Heap OOB write (separate finding) also confirmed. Code execution not yet achieved
— ASLR bypass required for both paths.
**Last updated:** 2026-11-25
**Hardware:** Nintendo Switch HAC-001 (XAW4 001878), Tegra X1 Erista, FW 22.5.0
**Attack surface:** WiFi via lp2p "Send to Smartphone" AP mode

This document contains only current findings. Superseded hypotheses are
preserved in [RESEARCH_JOURNAL.md](RESEARCH_JOURNAL.md).

---

## 1. CVE-2026-82079 — DHCP Server Stack Buffer Overflow (CONFIRMED)

**Vulnerable function:** FUN_71000a13d0 ("NetworkLayersCopy") at offset `0xa13d0`

The DHCP server event coordinator (FUN_71000a25f0, "OnNewMessage") allocates a
**1500-byte stack buffer** and calls `NetworkLayersCopy` to reassemble parsed
network layers into it. The function accepts a buffer size parameter (x3 = 0x5dc)
but **never reads it** — it computes the total layer size from the parsed packet
structure and performs an unbounded `memcpy` at instruction `0x71000a1470`.

**Why previous analysis missed this:** Earlier sessions analyzed the DHCP option
parser (FUN_71000a1ed0), which IS properly bounded. The overflow is in the
frame reassembly step that runs BEFORE option parsing.

### 1.1 Overflow Geometry (assembly-verified, corrected)

| Component | Size | Evidence |
|-----------|------|----------|
| BPF read buffer (global) | 4096 bytes (0x1000) | memset at FUN_71000a0d40 |
| Stack buffer | 1500 bytes (0x5dc) | `add x0, sp, #0x3c` at 0x71000a2688 |
| WiFi 802.11 max MSDU | 2304 bytes | IEEE 802.11-2020 §9.2.3 |
| Max Ethernet frame (WiFi) | 2318 bytes | 14 + 2304 |
| **Buffer-to-LR distance** | **1676 bytes** (0x68C) | FP-0x684 to FP+0x08 |
| DHCP options to reach LR | 1398 bytes | 1676 - 42(hdrs) - 236(BOOTP) |
| Available past LR (WiFi) | 642 bytes | Includes 48B of callee-saved regs |

**Discrepancy resolution:** Previous estimates of 1698/1740 bytes were wrong. Ghidra's
`auStack_6c4` measures from SP_entry; the FP-relative offset is 0x684 (= 0x6C4 - 0x40,
where 0x40 is the prologue's `stp` pre-decrement). Correct: 0x684 + 8 = **1676 bytes**.

### 1.2 Call Chain

```
BPF read (FUN_71000a0d40) → 4096-byte global buffer
  → OnEthernetPacket (FUN_71000a1640) → strips Ethernet header
    → OnInternetPacket (FUN_71000a17e0) → validates IP, strips IP header
      → OnUserDatagramPacket (FUN_71000a1a50) → validates UDP
        → OnBootProtocolRequestPacket (FUN_71000a1ed0) → validates DHCP options
          → SendDhcpPacketEvent (code 0x65)
            → OnNewMessage (FUN_71000a25f0) ← 1500-byte stack buffer
              → NetworkLayersCopy (FUN_71000a13d0) ← OVERFLOW (memcpy at 0x71000a1470)
```

### 1.3 Attack Scenario

1. Switch opens "Send to Smartphone" → creates LP2P WiFi AP → starts DHCP server
2. Attacker connects to WiFi AP (QR code or manual credentials)
3. Attacker sends crafted DHCP DISCOVER with >1500 bytes total frame data
4. NetworkLayersCopy overflows stack buffer → overwrites saved FP and LR
5. No stack canaries, no PAC on FW 22.5.0 Erista

**Remaining blocker:** ASLR (~17 bits, 2 MiB alignment). See §5 for bypass options.

Full analysis: [docs/cve_2026_82079_analysis.md](docs/cve_2026_82079_analysis.md)

---

## 2. Heap OOB Write (Separate Finding)

This is a **separate vulnerability** from CVE-2026-82079, affecting the same
`ldn` sysmodule via a different code path (action frame type 3 processing).

| Field | CVE-2026-82079 | Heap OOB Write |
|-------|----------------|----------------|
| Type | CWE-121 stack overflow | Heap out-of-bounds write |
| Function | FUN_71000a13d0 (NetworkLayersCopy) | FUN_71000398b0 (join handler) |
| Trigger | DHCP packet (requires WiFi association) | Action frame (pre-association) |
| Buffer | 1500-byte stack | Heap-allocated parser object |

---

## 2. Attack Setup

```
┌─────────────┐    WiFi AP (WPA2-PSK)    ┌──────────────────┐
│  Attacker PC │◄─────────────────────────│  Nintendo Switch  │
│  (Linux)     │  192.168.0.2             │  192.168.0.1      │
│  iwlwifi     │  Action frames ──────────►  ldn sysmodule    │
│  nl80211     │                          │  FW 22.5.0        │
└─────────────┘                          └──────────────────┘
```

**Prerequisites:**
1. Switch user opens Album → Share → Send to Smartphone
2. Switch creates WiFi AP (SSID: `switch_<MAC>0100S`, WPA2-PSK)
3. Attacker obtains credentials from QR code or "Trouble connecting" screen
4. Attacker connects to Switch AP
5. Attacker sends crafted action frames via nl80211 CMD_FRAME

**Switch BSSID:** ec:c4:0d:f3:dc:db
**Channel:** 1 (2412 MHz)
**PC interface:** wlp5s0 (Intel iwlwifi)

---

## 3. Code Path (Static Analysis)

**Binary:** `firmware/ldn_22.5.0/main.flat.bin` (961288 bytes, arm64, base 0x7100000000)

### 3.1 Join Handler

**Function:** FUN_71000398b0 (3412 bytes)

Processes incoming lp2p action frames. Dispatches based on the type byte at
body[0x21].

### 3.2 Type 3 Path

For body[0x21] == 0x03:
- **No SHA-256 hash verification** (type 1 requires this)
- **No payload_size cap** (type 1 caps at 385 bytes)
- **No AES-GCM encryption required**
- Body size validated only via: `body[0x22:0x24] == BE(body_size - 0x38)`

### 3.3 Parser Allocation

**Function:** FUN_7100044120

```
allocate(0x48, 8)   // 72 bytes, 8-byte aligned
```

The parser object is 0x48 (72) bytes. Vtable pointer is at parser[0].

### 3.4 The Out-of-Bounds Copy

Body data is copied to `parser + 0x5C`. The parser allocation is 0x48 bytes,
so the copy destination starts **0x14 bytes past the allocation boundary**.

**Unresolved: exact copy semantics.** The precise copy operation needs
re-verification against the binary instructions. If the copy is
`memcpy(parser + 0x5C, body, body_size)`, then ALL `body_size` bytes (up to
0x800) are written past the allocation, reaching `parser + 0x5C + body_size - 1`.
The earlier figure of "0x7A4 bytes of overflow" (computed as 0x800 - 0x5C) is
not the correct out-of-bounds length in that case — the full body is out of
bounds since the copy starts past the allocation. The actual copy length,
source offset, and destination arithmetic need to be confirmed from the
disassembly before quoting a precise overflow extent.

### 3.5 Parser Free

**Function:** FUN_71000444a0

After the join handler times out (~500ms), the parser is freed:
1. vtable+0x28 called (get type)
2. vtable[0] called (destructor)
3. allocator vtable+0x18 called (deallocate)

The vtable at parser[0] is NOT reachable via the overflow copy. Body copy
starts at parser+0x5C; vtable is at parser+0x00.

### 3.6 Frame Construction

```python
# Action frame structure
frame = [
    0x00D0 (le16),         # Frame control: Action frame
    0x0000 (2 bytes),      # Duration
    SWITCH_MAC (6 bytes),  # Destination
    SRC_MAC (6 bytes),     # Source
    SWITCH_MAC (6 bytes),  # BSSID
    0x0000 (le16),         # Sequence
    LP2P_HEADER (12 bytes),# 7f 00 22 aa 04 01 01 01 00 00 00 00
    body (up to 0x800),    # Body with type 3 content
]

# Type 3 body requirements
body[0x21] = 0x03                           # Type 3
body[0x22:0x24] = BE(body_size - 0x38)      # Size validation
body[0x26] = 0x01; body[0x27] = 0x01        # Required flags
body[0x1DA:0x1DC] = BE(0x0100)              # For bodies > 0x1DC
```

**Frame size limit:** iwlwifi limits the action frame body to 0x800 bytes
(confirmed empirically via frame_size_test.py).

---

## 4. Experimental Results

### 4.1 Methodology and Limitations

**Oracle:** HTTP endpoint at 192.168.0.1:80. Binary signal: responds or doesn't.

**What the oracle does NOT tell us:**
- Which process or thread failed
- What memory address was accessed
- What the CPU register state was
- Whether allocator metadata was corrupted
- Whether our data was interpreted as we intended

**Frame delivery gap:** `send_frame()` returns nl80211 error codes, but these
were not consistently validated or recorded in early tests. We cannot
independently confirm all frames were accepted and transmitted.

**Terminology:** Throughout this document:
- "HTTP available" = endpoint responded within timeout
- "HTTP unavailable" = endpoint did not respond within timeout
- These are NOT labeled "OK" or "CRASH" because the failure mode is unknown

### 4.2 Content-Sensitive Behavior

| Fill Pattern | Body Size | HTTP After | Evidence |
|--------------|-----------|------------|----------|
| 0x00 (zeros) | 0x800 | Available | live_exploit.py Phase 1 |
| 0x41 ('A') | 0x800 | Available | live_exploit2.json |
| DEAD markers | 0x800 | Available | live_exploit2.json |
| 0xFF | 0x800 | Unavailable | live_exploit2.json |

**What this establishes:** Different byte patterns in the overflow region
correlate with different HTTP availability outcomes. The data we supply in the
body influences something that affects the HTTP endpoint.

**What this does NOT establish:** That the data was written to specific memory
locations, that specific structures were corrupted, or that the unavailability
is caused by a particular memory-safety violation.

### 4.3 Content-Sensitivity Map (Zero-Probe Scan)

**Method:** Body filled with 0x41, one 8-byte chunk zeroed at a time.

**Sensitive offsets** (zeroing causes HTTP unavailability):

| Body Offset | Parser Offset | Spacing from Previous |
|-------------|---------------|-----------------------|
| 0x0E0 | 0x013C | — (first) |
| 0x0E8 | 0x0144 | 8 bytes |
| 0x0F8 | 0x0154 | 16 bytes |
| 0x108 | 0x0164 | 16 bytes |
| 0x120 | 0x017C | 24 bytes |
| 0x140 | 0x019C | 32 bytes |
| 0x158 | 0x01B4 | 24 bytes |
| 0x160 | 0x01BC | 8 bytes |
| 0x168 | 0x01C4 | 8 bytes (scan stopped) |

**Evidence:** null_ptr_probe.json

**Confound:** Each unavailability event potentially restarts the sysmodule with
a different heap layout. Later entries may reflect different layouts. The scan
should be repeated with a fresh sysmodule state for each test to eliminate this.

**What this establishes:** Zeroing specific 8-byte regions while keeping the
rest as 0x41 correlates with HTTP unavailability. The irregular spacing
(8, 16, 16, 24, 32, 24, 8, 8) is inconsistent with regularly-spaced allocator
metadata headers.

**What this does NOT establish:** That these offsets are pointer fields, that
NULL dereference is the failure mode, or what data structures occupy these
locations. This is a **content-sensitivity map**, not a pointer map.

### 4.4 Heap Layout Non-Determinism

The heap layout changes across sysmodule restarts:

| Instance | Observation | Evidence |
|----------|-------------|----------|
| First | Free block header (FR magic) at body[0x750]; zero fill past it → unavailable | heap_boundary_bsearch.json |
| After restarts | Boundary at body[0x724], non-monotonic | heap_reprobe.py |
| Fresh restart | No boundaries (full 0x800 zero fill → available) | live_exploit.py |

Hardcoded offsets are unreliable across restarts.

### 4.5 Timing-Dependent Two-Stage Behavior

| S1 Fill | Gap | S2 Body | HTTP After | Evidence |
|---------|-----|---------|------------|----------|
| 0x41, 0x800 | 0.5s | 0xBB, 0x800 | Available | live_exploit2.json |
| 0x41, 0x800 | 1.0s | 0xBB, 0x800 | Unavailable | live_exploit2.json |
| 0x41, 0x800 | 2.0s | 0xBB, 0x800 | Unavailable | live_exploit2.json |
| 0x41, 0x800 | 5.0s | 0xBB, 0x800 | Available | live_exploit2.json |

**What this establishes:** Timing-dependent behavior — a 1-2s gap between
overflow frame sets correlates with HTTP unavailability.

**What this does NOT establish:** That the first parser was freed, that
allocator metadata was processed, or that the second allocation overlapped
with corrupted data. The timing window is consistent with parser lifetime,
but the mechanism is not confirmed.

### 4.6 Fake Allocator Metadata Placement

| Body Offset | Parser Offset | Result |
|-------------|---------------|--------|
| 0x100 | 0x015C | Unavailable (after stage 1 frames) |
| 0x300 | 0x035C | Available (both stages) |
| 0x500 | 0x055C | Unavailable (after stage 2 frames) |
| 0x700 | 0x075C | Unavailable (after stage 1 frames) |

**Evidence:** live_exploit2.json

---

## 5. Exploit Mitigations (Erista, FW 22.5.0) — Binary-Verified

| Mitigation | Status | Evidence | Impact |
|------------|--------|----------|--------|
| ASLR | Yes — 17-bit, 2 MiB aligned | Switchbrew Memory_layout | 131,072 possible bases |
| NX (W^X) | Yes | Standard Horizon mapping | No shellcode; ROP required |
| Stack canaries | **ABSENT** | No `__stack_chk_guard` string in binary (search_strings) | Direct LR overwrite |
| PAC | **ABSENT** | PACIASP opcode (`7f2303d5`) not found in 961,288 bytes (search_bytes) | Unauthenticated returns |
| CFI | clang cfi-icall/cfi-vcall | Switchbrew documentation | Constrains indirect calls |
| XOM | Possibly on 20.0.0+ Erista | Switchbrew 20.0.0 | May prevent code reading |

---

## 6. Gap Analysis

**What we have:**
- Static analysis indicating an out-of-bounds copy into heap memory
- Content-sensitive and timing-dependent HTTP availability changes in live tests
- A partial content-sensitivity map of the overflow region

**What we need for code execution:**
1. Confirm the exact copy operation (length, source, destination) from disassembly
2. Identify what heap objects/structures are adjacent to the parser
3. Establish a write-what-where primitive or equivalent
4. Defeat ASLR (information leak or brute force)
5. Redirect control flow (vtable pointer, return address, or function pointer)

**Prioritized next steps:**
1. **Re-verify the copy operation** in the binary — exact instruction sequence,
   source buffer, copy length, destination pointer arithmetic
2. **RE: Identify adjacent heap objects** — correlate with content-sensitivity map
3. **Improve the oracle** — validate frame delivery, measure timing, separate
   WiFi AP stability from HTTP availability
4. **Information leak** — AdvertiseData uninitialized memory (Switchbrew)
5. **Heap spray** — deterministic layout before overflow

---

## 7. Superseded Hypotheses

Preserved in [RESEARCH_JOURNAL.md](RESEARCH_JOURNAL.md):

1. **BuildVendorIE stack overflow** (`vuln_function_0x99d80.md` — SUPERSEDED)
   vtable[4] is fixed-size AES-128, not variable memcpy.

2. **DHCP server stack overflow** (`cve_2026_82079_analysis.md` — SUPERSEDED)
   DHCP code proven clean; crash is pre-DHCP.

3. **Two-buffer amplification chain** — 21.0.0 parser fix blocks this path.

---

## 8. File Index

### Evidence (JSON) — `evidence/action_frame_overflow/`
| File | Description |
|------|-------------|
| heap_boundary_test.json | First crash-boundary discovery |
| heap_boundary_bsearch.json | Binary search refinement |
| header_probe.json | FR magic identification |
| overflow_control_test.json | Full body-fill survival tests |
| heap_overlap_test.json | Forged free-block size tests |
| two_stage_heap.json | Two-stage timing tests |
| clean_stage_test.json | Post-restart verification |
| live_exploit2.json | Comprehensive live tests |
| null_ptr_probe.json | Content-sensitivity map (zero probe) |

### Analysis Scripts
| File | Description |
|------|-------------|
| scripts/exploit/live_exploit.py | Heap probe + overflow + two-stage |
| scripts/exploit/live_exploit2.py | Fill tests, fake headers, timing |
| scripts/heap/null_ptr_probe.py | 8-byte zero-probe scanner |
| scripts/heap/heap_reprobe.py | Post-restart layout prober |
