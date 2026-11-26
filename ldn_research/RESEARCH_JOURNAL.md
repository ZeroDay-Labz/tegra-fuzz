# LDN Memory-Corruption Research — Journal (Chronological)

This document preserves the research history, including hypotheses that were
later invalidated. It is NOT the authoritative technical reference — see
[TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) for current findings only.

Entries marked **[SUPERSEDED]** were invalidated by later work. The correction
is noted inline.

---

## Phase 1: Initial Analysis (Nov 2026)

### Hypothesis: DHCP Server Stack Overflow

**Source:** CVE description, HackerOne H1:3770768, Switchbrew 23.0.0 diff

**Hypothesis:** The lp2p DHCP server in the ldn sysmodule copies incoming DHCP
option data to a stack buffer without size validation. Oversized vendor-class-
identifier options (>253 bytes) overflow the stack buffer and overwrite the saved
return address.

**Investigation:**
- Captured live DHCP exchange from Switch (confirmed DHCP server responds)
- Identified BuildVendorIE function at 0x99d80 as the memcpy location
- Mapped stack layout: 253 bytes to x29, 261 bytes to x30
- vendor_class=222 triggered HTTP unavailability
- NetworkManager adds ~32 bytes of DHCP overhead (explains NM-only crash)

**Documents:** `cve_2026_82079_analysis.md`, `vuln_function_0x99d80.md`

### [SUPERSEDED] BuildVendorIE Exploitation Model

**Hypothesis:** vtable[15] at 0x99d80 contains an unbounded memcpy that copies
attacker-controlled data to a stack buffer. By controlling DHCP option data, we
overflow the stack buffer and overwrite the saved x30 (return address).

**Why superseded (2026-11-23):**
- vtable[4] performs fixed-size AES-128 encryption, NOT variable-length memcpy
- The variable-length value in x2 is overwritten before the copy
- vtable[3] has bounds checks
- The builder's final length stays below the return-address overwrite threshold
- The 21.0.0 parser fix blocks the original data-flow path
- Not exploitable on 22.5.0 through this chain

**Lesson:** Carefully verify each step of a data flow chain against actual
instructions, not decompiler pseudocode alone. The decompiler's representation
of AES operations can look like variable-length copies.

---

## Phase 2: DHCP Crash Investigation

### vendor_class >= 222 Crash

**Observation:** Sending DHCP DISCOVER with vendor_class_identifier >= 222 bytes
caused HTTP unavailability.

**Investigation (4 sessions):**
- ldn DHCP code proven clean — the DHCP handler has proper bounds checking
- Raw DHCP injection (bypassing NetworkManager) does NOT reproduce the crash
- NetworkManager overhead (~32 bytes of additional options) is required
- The crash is pre-DHCP: it occurs before the DHCP server processes the packet

**Conclusion:** The vendor_class >= 222 crash is NOT in the ldn DHCP handler.
The root cause is likely in WiFi driver or frame processing, not application-
level DHCP. Requires empirical testing with crash monitoring.

**Documents:** `evidence/dhcp_attack/`, `crash_monitor.py`, `nm_local_ap_test.py`
**Memory:** `project-dhcp-crash.md`

---

## Phase 3: HTTP Server Analysis

### Range Header DoS

**Finding:** `Range: bytes=0-9223372036854775808` (INT64_MAX + 1) causes
the ldn HTTP server to crash with error 2162-0002. The server uses cpp-httplib
which doesn't validate range boundary values.

**Assessment:** Denial of Service only. The crash is in string formatting, not
in a memory copy. No path to code execution.

**Documents:** `http_server_analysis.md`, `evidence/action_frame_overflow/http_range_dos_confirmed.json`
**Memory:** `project-http-range-dos.md`

### GET + Body Crash

**Finding:** GET requests with a body of certain sizes caused HTTP unavailability
during marathon testing. NOT reproducible in isolation (16 sizes tested).
Likely accumulated heap stress.

**Assessment:** Low priority. Not reliably triggerable.

**Documents:** `evidence/lp2p_dhcp/marathon_results.json`
**Memory:** `project-get-body-crash.md`

---

## Phase 4: Action Frame Overflow (Current)

### Discovery: Type 3 Body Bypasses All Checks

**Finding (confirmed by RE):** Action frame bodies with type byte = 0x03 at
body[0x21] bypass all integrity checks:
- No SHA-256 hash verification (type 1 requires this)
- No payload_size cap (type 1 caps at 385 bytes)
- No AES-GCM encryption required
- Only check: body[0x22:0x24] == BE(body_size - 0x38)

**Documents:** `evidence/action_frame_overflow/vuln_analysis.json`
**Memory:** `project-action-frame-overflow.md`

### Discovery: Parser Allocation is 0x48 bytes

**Finding (confirmed by RE of FUN_7100044120):** The parser object is allocated
with `allocate(0x48, 8)` — only 72 bytes. The body copy starts at parser+0x5C,
which is 0x14 bytes past the allocation end. The ENTIRE body (up to 0x800 bytes)
is overflow into adjacent heap memory.

This was initially assumed to be 0x5D8 based on earlier analysis. The correct
size was discovered by reading the decompiled code of the parser creation function.

### Heap Boundary Discovery

**First heap instance:** A free block header (magic=0x4652 "FR") was found at
parser+0x7AC (body offset 0x750). Zero-filling past this offset caused HTTP
unavailability unless the FR magic was preserved.

- FR header: magic=0x4652, attr=0x0001, size=0x0020
- Preserving this header allowed full 0x41 fill (596 bytes of controlled data)
- Forging the size field to any value (0x20 through 0x40000) did not cause
  HTTP unavailability

**Documents:** `heap_boundary_test.json`, `heap_boundary_bsearch.json`,
`header_probe.json`, `overflow_control_test.json`, `heap_overlap_test.json`

### Heap Layout Instability

**Finding:** After multiple sysmodule restarts, the heap layout changed. The
FR header at parser+0x7AC was no longer present. Different heap instances showed
different crash boundaries, and some showed no boundaries at all.

**Documents:** `heap_reprobe.py`, `clean_stage_test.json`, `live_exploit.py`

### Two-Stage Behavior

**Finding:** Sending overflow frames, waiting 1-2 seconds, then sending more
frames reliably causes HTTP unavailability. This timing window is consistent
with the parser being freed and the allocator processing corrupted metadata.

**Documents:** `two_stage_heap.json`, `live_exploit2.json`

### Content-Sensitivity Map (Zero-Probe Scan)

**Finding (2026-11-24):** Zeroing individual 8-byte chunks in the overflow
region (while filling the rest with 0x41) reveals offsets where zeroing
correlates with HTTP unavailability. Nine sensitive offsets found in the first
0x170 bytes of overflow, with irregular spacing (8-32 bytes). The irregular
spacing is inconsistent with allocator metadata headers.

**What this does NOT establish:** That these are pointer fields, that NULL
dereference is the failure mode, or what structures are at these offsets.

**Caveat:** Each unavailability event restarts the sysmodule, potentially
changing the heap layout for subsequent tests. Later entries may reflect
different layouts.

**Documents:** `null_ptr_probe.json`

---

## Open Research Threads

1. **Identify adjacent heap objects via RE** — correlate NULL-sensitive offsets
   with actual object layouts from the binary
2. **Heap spraying** — deterministic layout before the overflow
3. **Information leak** — AdvertiseData or other side channels for ASLR bypass
4. **Richer oracle** — frame delivery validation, timing analysis, AP stability
5. **Peripheral attack surfaces** — Bluetooth, NFC, Joy-Con, other sysmodules
