# LDN Heap Out-of-Bounds Write — Experimental Findings

**Internal identifier:** LDN-HEAP-OOB-001
**Finding:** Out-of-bounds heap copy in ldn sysmodule join handler
**Binary:** `firmware/ldn_22.5.0/main.flat.bin` (961288 bytes, arm64, base 0x7100000000)
**Affected function:** FUN_71000398b0 (join handler, 3412 bytes)
**Fixed in:** Firmware 23.0.0 (relationship to CVE-2026-82079 unresolved — see
[TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) §1)
**Attack vector:** WiFi action frames via lp2p local wireless protocol

Last updated: 2026-11-24

---

## Table of Contents

1. [Vulnerability Mechanism](#1-vulnerability-mechanism)
2. [Parser Allocation](#2-parser-allocation)
3. [Overflow Characteristics](#3-overflow-characteristics)
4. [Heap Layout Observations](#4-heap-layout-observations)
5. [NULL-Sensitive Offset Scan](#5-null-sensitive-offset-scan)
6. [Two-Stage Behavior](#6-two-stage-behavior)
7. [Evidence Classification](#7-evidence-classification)
8. [Methodology Limitations](#8-methodology-limitations)
9. [Open Questions](#9-open-questions)
10. [File Index](#10-file-index)

---

## 1. Vulnerability Mechanism

The join handler FUN_71000398b0 processes incoming lp2p action frames. For
type 3 frames (body[0x21] == 0x03):

- **No SHA-256 hash verification** (unlike type 1)
- **No payload_size cap** (type 1 caps at 385)
- **No AES-GCM encryption required**
- Body is copied to a heap-allocated parser object at an offset past the
  allocation boundary

The BNE (branch-not-equal) path requires: `body[0x22:0x24] == BE(body_size - 0x38)`

**Evidence:** RE analysis of FUN_71000398b0 pseudocode (22803 UTF-16 code units),
confirmed by successful frame delivery to live Switch.

---

## 2. Parser Allocation

**Established:** FUN_7100044120 allocates the parser object.

```
allocate(0x48, 8)   // 72 bytes, 8-byte aligned
```

The parser is 0x48 (72) bytes. The vtable pointer is at parser[0].
Body data is copied starting at parser + 0x5C, which is **0x14 bytes past
the parser allocation boundary**.

**Parser free:** FUN_71000444a0 frees the parser by:
1. Calling vtable+0x28 (get type)
2. Calling vtable[0] (destructor)
3. Calling allocator vtable+0x18 (deallocate)

The vtable pointer at parser[0] is NOT in the overflow region (body copy
starts at parser+0x5C, vtable is at parser+0x00). We cannot directly overwrite
the parser's own vtable via overflow.

**Evidence:** RE analysis of FUN_7100044120 and FUN_71000444a0 pseudocode.

---

## 3. Overflow Characteristics

**What's established:**

| Test | Fill | Body Size | Result | Evidence File |
|------|------|-----------|--------|---------------|
| Zero fill, max size | 0x00 | 0x800 | HTTP remained available | live_exploit.py run |
| 0x41 fill, max size | 0x41 | 0x800 | HTTP remained available | live_exploit2.json |
| DEAD pattern markers | varies | 0x800 | HTTP remained available | live_exploit2.json |
| 0xFF fill, max size | 0xFF | 0x800 | HTTP became unavailable | live_exploit2.json |

**Overflow extent (needs re-verification):** The body is up to 0x800 bytes.
Body copy starts at parser+0x5C, which is 0x14 bytes past the 0x48-byte
allocation boundary. The earlier figure of "0x7A4 bytes of overflow" (computed
as 0x800 - 0x5C) is under review — if the copy is `memcpy(parser+0x5C, body,
body_size)`, then ALL body_size bytes are out of bounds since the destination
already exceeds the allocation. The precise copy length and source offset need
to be confirmed from the binary's instruction sequence.

**Key qualification:** "HTTP remained available" means the HTTP endpoint at
192.168.0.1:80 responded within the test's timeout after sending 60 frames.
This does NOT prove:
- The data was written as intended
- No other corruption occurred
- The overflow region is "unrestricted" for arbitrary writes

The correct description is: **certain byte patterns in the overflow copy do not
immediately cause the HTTP endpoint to become unavailable**.

**iwlwifi frame size limit:** Maximum action frame body is 0x800 bytes,
confirmed by frame_size_test.py. This limits the overflow to 0x7A4 bytes.
The overflow is entirely within heap memory. The published CVE classifies
this as CWE-121 (stack overflow); the relationship between the published
classification and our heap finding is unresolved (see TECHNICAL_REPORT.md §1).

---

## 4. Heap Layout Observations

**Key observation:** The heap layout adjacent to the parser is NOT deterministic
across sysmodule restarts. When the sysmodule restarts (e.g., after the HTTP
endpoint becomes unavailable), the new heap layout may differ.

**Evidence of non-determinism:**
- First heap instance: free block header (magic=0x4652 "FR") observed at
  parser+0x7AC (body offset 0x750). Overflow past this point with zero fill
  caused HTTP unavailability unless the FR header was preserved.
  (Evidence: heap_boundary_test.json, heap_boundary_bsearch.json, header_probe.json)

- After multiple sysmodule restarts: crash boundary moved to parser+0x780
  (body offset 0x724), and was NON-MONOTONIC — some body sizes between 0x780
  and 0x800 caused HTTP unavailability while others did not.
  (Evidence: heap_reprobe.py output)

- After further restarts: the full 0x800 overflow with zero fill caused NO
  HTTP unavailability at all — no crash boundaries detected.
  (Evidence: live_exploit.py run, Phase 1)

**Interpretation:** The allocator arranges objects differently on each sysmodule
restart. This complicates exploitation because we cannot rely on a fixed heap
layout.

---

## 5. Content-Sensitivity Map (Zero-Probe Scan)

**Method:** Send body filled with 0x41, except one 8-byte chunk zeroed.
Scan body offsets 0x060 through 0x168 in 8-byte steps. Record whether HTTP
remains available.

**Important caveat:** Each time HTTP becomes unavailable, the sysmodule restarts
and the heap layout may change. Later results in the scan may reflect a
different heap layout than earlier results.

**Results (single scan run, 2026-11-24):**

```
body[0x060:0x0E0] (parser+0x00BC..0x013C): all OK (16 chunks)
body[0x0E0:0x0E8] (parser+0x013C): HTTP unavailable
body[0x0E8:0x0F0] (parser+0x0144): HTTP unavailable
body[0x0F0:0x0F8] (parser+0x014C): OK
body[0x0F8:0x100] (parser+0x0154): HTTP unavailable
body[0x100:0x108] (parser+0x015C): OK
body[0x108:0x110] (parser+0x0164): HTTP unavailable
body[0x110:0x118] (parser+0x016C): OK
body[0x118:0x120] (parser+0x0174): OK
body[0x120:0x128] (parser+0x017C): HTTP unavailable
body[0x128:0x140] (parser+0x0184..0x019C): OK (3 chunks)
body[0x140:0x148] (parser+0x019C): HTTP unavailable
body[0x148:0x158] (parser+0x01A4..0x01B4): OK (2 chunks)
body[0x158:0x160] (parser+0x01B4): HTTP unavailable
body[0x160:0x168] (parser+0x01BC): HTTP unavailable
body[0x168:0x170] (parser+0x01C4): HTTP unavailable
(scan stopped: 3 consecutive unavailable results)
```

**Sensitive offsets (parser-relative):**
0x013C, 0x0144, 0x0154, 0x0164, 0x017C, 0x019C, 0x01B4, 0x01BC, 0x01C4

**Spacing between sensitive offsets:**
8, 16, 16, 24, 32, 24, 8, 8 bytes

**What this establishes:** Zeroing specific 8-byte regions while keeping the
rest as 0x41 correlates with HTTP unavailability. The irregular spacing
(8, 16, 16, 24, 32, 24, 8, 8) is inconsistent with regularly-spaced allocator
metadata headers (expected at 24-byte intervals for nn::lmem::ExpHeap).

**What this does NOT establish:** That these offsets are pointer fields, that
NULL dereference is the failure mode, or what data structures occupy these
locations. This is a **content-sensitivity map**, not a pointer map.

**Confound:** The heap layout changes after each unavailability event (sysmodule
restart), so later entries in this scan may reflect different heap layouts. The
scan should be repeated with a fresh sysmodule state for each test to eliminate
this.

---

## 6. Two-Stage Behavior

**Method:** Send overflow frames (stage 1), wait a variable time, then send
a second set of frames (stage 2). Check HTTP availability.

**Results (2026-11-24, live_exploit2.json):**

| Stage 1 | Gap | Stage 2 | Result |
|---------|-----|---------|--------|
| 0x41 fill, 0x800 | 2s | same | HTTP unavailable after S2 |
| 0x41 fill, 0x800 | 0.5s | 0xBB fill, 0x800 | HTTP available |
| 0x41 fill, 0x800 | 1s | 0xBB fill, 0x800 | HTTP unavailable |
| 0x41 fill, 0x800 | 2s | 0xBB fill, 0x800 | HTTP unavailable |
| 0x41 fill, 0x800 | 5s | 0xBB fill, 0x800 | HTTP available |

**Fake FR header placement tests:**

| Body offset | Parser offset | Stage 1 | Stage 2 | Result |
|-------------|---------------|---------|---------|--------|
| 0x100 | 0x015C | 0x41+FR | — | HTTP unavailable (S1) |
| 0x300 | 0x035C | 0x41+FR | 0x100 body | HTTP available |
| 0x500 | 0x055C | 0x41+FR | 0x100 body | HTTP unavailable (S2) |
| 0x700 | 0x075C | 0x41+FR | — | HTTP unavailable (S1) |

**Observations:**
- Two-stage HTTP unavailability occurs consistently with 1-2 second gaps
- 0.5s gap: too short — the first parser may not have been freed yet
- 5s gap: too long — cleanup may have occurred
- Fake FR headers at certain offsets (0x100, 0x700) cause immediate
  unavailability on stage 1
- Fake FR at offset 0x500 survives stage 1 but causes unavailability on stage 2

**What this establishes:** There is timing-dependent behavior where sending
overflow frames, waiting 1-2 seconds, and sending more frames causes HTTP
unavailability that single-stage overflow does not. This is consistent with
the parser being freed (allocator processes corrupted metadata), but the
exact mechanism is not independently confirmed.

---

## 7. Evidence Classification

### Established (directly observed)

1. **Overflow copy of controlled data past parser allocation** — the body is
   copied to parser+0x5C, which is 0x14 bytes past the 0x48-byte allocation.
   (Evidence: RE analysis + live frame delivery confirmed by HTTP availability
   monitoring)

2. **Content-sensitive HTTP availability** — different byte patterns in the
   overflow region cause different outcomes (0x41 OK, 0xFF unavailable, NULL
   at specific offsets unavailable).
   (Evidence: live_exploit2.json, null_ptr_probe.json)

3. **Timing-dependent two-stage behavior** — specific time gaps between
   overflow frame sets cause HTTP unavailability.
   (Evidence: live_exploit2.json)

4. **Heap layout non-determinism** — the positions of sensitive structures
   adjacent to the parser change across sysmodule restarts.
   (Evidence: heap_boundary_test.json vs heap_reprobe.py vs live_exploit.py)

5. **Type 3 body bypasses all integrity checks** — no SHA-256, no size cap,
   no AES-GCM.
   (Evidence: RE analysis of FUN_71000398b0)

### Inferred (consistent with observations but not independently confirmed)

1. The "HTTP unavailable" results are caused by sysmodule crashes (could be
   assertion failures, signal handlers, or other mechanisms)
2. The sensitive offsets correspond to pointer fields in heap objects
3. The two-stage behavior is caused by allocator processing corrupted metadata
4. The 0xFF crash is caused by invalid pointer values (could be other field types)

### Not demonstrated

1. Arbitrary write primitive (write-what-where)
2. Control over crash/fault address
3. ASLR bypass
4. Code execution
5. Specific identification of which heap objects are adjacent to the parser

---

## 8. Methodology Limitations

### Oracle limitation
Our only observation channel is HTTP endpoint availability at 192.168.0.1:80.
This is a binary signal (responds/doesn't respond) with no information about:
- Which process or thread failed
- What memory address was accessed
- What the CPU state was at time of failure
- Whether allocator metadata was specifically corrupted

### Frame delivery
`send_frame()` returns nl80211 error codes, but the test scripts do not
consistently validate or record these return values. We cannot independently
confirm that all intended frames were accepted by the WiFi driver and
transmitted.

### Heap layout confound
Each HTTP unavailability event potentially restarts the sysmodule with a new
heap layout. Sequential tests within a single scan may operate on different
heap layouts. To eliminate this confound, each test should start from a known
clean state.

### Timing precision
Frame transmission timing depends on Python execution speed and nl80211
processing. The 2ms inter-frame delay is nominal. Actual frame delivery
timing at the Switch is unknown.

---

## 9. Open Questions

1. **What objects are adjacent to the parser on the heap?**
   RE analysis of the ldn binary could identify what types of objects are
   allocated near the parser and what their field layouts are. Correlating
   with the sensitive offsets from the NULL scan could identify specific
   pointer fields.

2. **Can we get a richer oracle?**
   - WiFi management frame responses from the Switch
   - Different HTTP endpoints returning different data
   - Timing analysis of when HTTP becomes unavailable
   - WiFi AP stability (ping vs HTTP availability)

3. **Is the heap layout deterministic from a truly fresh state?**
   If the Switch is rebooted (not just sysmodule restart), does the heap
   layout always start the same? If so, we can rely on the initial layout.

4. **Can we spray the heap to create a deterministic layout?**
   Sending many frames of a specific size before the attack might fill the
   heap in a predictable way.

5. **What happens at the sensitive offsets with controlled non-NULL values?**
   We know NULL crashes, 0x41 survives. What about values that could be
   valid pointers into the overflow data itself?

---

## 10. File Index

### Evidence (JSON)
| File | Description |
|------|-------------|
| `heap_boundary_test.json` | First discovery of crash boundary at parser+0x7AC |
| `heap_boundary_bsearch.json` | Binary search refinement of crash boundary |
| `header_probe.json` | Identification of FR magic (0x4652) at crash boundary |
| `overflow_control_test.json` | Full 596-byte overflow control with 0x41 fill |
| `heap_overlap_test.json` | Forged free block sizes (0x20-0x40000) all accepted |
| `two_stage_heap.json` | Two-stage attack results (all patterns crashed) |
| `clean_stage_test.json` | Post-restart verification (layout changed) |
| `live_exploit2.json` | Comprehensive live tests: fills, two-stage, fake FR |
| `null_ptr_probe.json` | NULL-sensitive 8-byte offset scan |
| `vuln_analysis.json` | Initial vulnerability analysis |
| `http_range_dos_confirmed.json` | Range header DoS confirmation |

### Analysis Scripts (Python)
| File | Description |
|------|-------------|
| `live_exploit.py` | Phase 1-4 exploit: probe, reconstruct, overflow, two-stage |
| `live_exploit2.py` | Fill tests, fake FR headers, timing tests |
| `null_ptr_probe.py` | 8-byte chunk NULL scan of overflow region |
| `heap_reprobe.py` | Re-probe heap layout after restarts |
| `overflow_control_test.py` | 64-byte chunk crash boundary mapping |
| `heap_overlap_test.py` | Forged free block size acceptance test |
| `two_stage_heap.py` | Two-stage heap corruption attack |
| `clean_stage_test.py` | Clean-state verification after crashes |

### RE Analysis (Markdown)
| File | Description |
|------|-------------|
| `cve_2026_82079_analysis.md` | Main CVE analysis document |
| `aslr_bypass_analysis.md` | ASLR analysis (17-bit, 2MB-aligned) |
| `http_server_analysis.md` | HTTP server (cpp-httplib) analysis |
| `firmware_acquisition.md` | Firmware extraction notes |
