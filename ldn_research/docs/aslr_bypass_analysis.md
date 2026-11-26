# ASLR Bypass Analysis for CVE-2026-82079

## Executive Summary

**CVE-2026-82079 is NOT EXPLOITABLE on FW 22.5.0. ALL paths dead.**

### CRITICAL CORRECTION (2026-11-23)

The builder overflow chain documented previously was based on **incorrect identification of vtable[4]**:

1. **vtable[4] at 0x96e90 does FIXED-SIZE AES-128 encryption** (16 bytes plaintext, confirmed by disassembly). The x2 register (data_size from FUN_0009c0c0) is OVERWRITTEN at 0x96ecc before the crypto call. It does NOT perform a variable-size memcpy.
2. **vtable[3] at 0x96e00/0x96d30 has BOUNDS CHECKING** (branch at 0x96e3c / 0x96d64 skips write if it would overflow the buffer). Both Type 1 and Type 2/3 builders are bounded.
3. **finalize (vtable[5]) returns max ~208** (48 + write_pos for Mode 2/3, 28 + write_pos for Mode 1). This is well under the 253-byte threshold needed for BuildVendorIE's memcpy to reach x30.
4. **The two-buffer amplification chain CANNOT work** because vtable[4] never overflows the builder buffer — it writes a fixed crypto block.

The original CVE-2026-82079 attack vector (parser → unbounded data → BuildVendorIE overflow) was **fixed in 21.0.0** (parser input validation). The 23.0.0 fix to BuildVendorIE was **defense-in-depth**. On 22.5.0, the parser fix is active and BuildVendorIE is unreachable with overflow data.

## Detailed Findings

### 1. Builder Buffer Zeroing (CONFIRMED)

Both advertise buffer builders properly zero their buffers via memset:

- **Type 1 init (0x96cd0)**: vtable PTR_FUN_000e7700, calls `FUN_000a3740(buffer, 0, size)` = memset
- **Type 2/3 init (0x96dd0)**: vtable PTR_FUN_000e7740, calls `FUN_000a3740(buffer, 0, size)` = memset
- **FUN_000a3740 IS memset**: confirmed by decompilation — standard byte-fill with aligned widening
- **ARM64 optimization**: third arg (size) stays in x2 from prior `param_1[2] = param_3` store

**Result**: No uninitialized memory in advertise buffers. No stale pointer leak path.

### 2. TLV Header Layout (CRITICAL)

The TLV builder (vtable[3] at 0x96e00) writes data at `buffer + header_offset`:
- **Plaintext mode** (flag=0): header = 0x14 (20 bytes)
- **Encrypted mode** (flag≠0): header = 0x30 (48 bytes)
- Both builder inits set flag=0 → **header is always 20 bytes**

The header is zeroed by memset and **never explicitly written** by any builder operation.
The finalize function (0x96f00) only returns `header_offset + write_pos`, does not fill the header.

### 3. Chain-Capable Gadget Status (UPDATED)

| Gadget | x30 offset | Buffer location | Content | Status |
|--------|-----------|-----------------|---------|--------|
| 0x95060 | [SP+0x28] | second_buf[0:8] | **ALL ZEROS** (header) | ★ DEAD |
| 0x96f74 | [SP+0x48] | second_buf[32:40] | Crypto param TLV data | Needs ASLR base |
| 0x95f48 | [SP+0xC8] | second_buf[160:168] | Deep TLV/app data | Needs ASLR base |
| 0x92430 | [SP+0x138] | first_buf[8:16] | **ALL ZEROS** (header) | ★ DEAD |
| 0x94238 | [SP+0x188] | first_buf[88:96] | TLV app data | Needs ASLR base |

### 4. Second Buffer Content Map

```
Offset  Content                           Source
------  --------------------------------  -------------------------
0x00    00 00 00 00 00 00 00 00          header (memset zeros)
0x08    00 00 00 00 00 00 00 00          header
0x14    21 NN xx xx xx xx xx xx          TLV: type=0x21, len=NN, crypto_data[0:6]
0x1C    xx xx xx xx xx xx xx xx          crypto_data[6:14]
0x20    xx xx xx xx xx xx xx xx          crypto_data[10:18] ← x30 source for 0x96f74!
0x26+NN [next TLV: app data]             from scan_entry+0x81
```

The crypto_data comes from `entry+0xb0` with length from `*(uint16*)(entry+0xae)`.
For Aes128Gmac networks, this is GMAC authentication parameters (attacker-influenced if attacker hosts the network).

### 5. COOP Vtable Dispatch Gadgets — ★ DEAD

Found 12 gadgets in page 9 that perform vtable dispatches through x20 or x19:

**x20-based**: 0x970c8, 0x970dc, 0x970f0, 0x97104, 0x97198 — ★ DEAD
- x20 is a plain C struct (scan_entry), NOT a polymorphic object
- `ldr x8, [x20]` loads zero/small int from struct start → segfault

**x19-based**: 0x9fe10 — USELESS
- Calls vtable[1] = deleting destructor (0x97db0), just frees memory

**All COOP paths dead**: x20 not polymorphic, x19 only destructor, and all gadget epilogues read x30 from stack (ASLR-dependent).

### 6. Aes128GmacAdvertiseParser Vtable (DECODED)

Vtable at 0xe78c0 (16 entries):
```
[0]  0x0021f0  destructor
[1]  0x097db0  deleting destructor (frees object)
[2]  0x097de0  
[3]  0x097ea0  
[4]  0x097eb0  
[5]  0x097fb0  
[6]  0x0980b0  
[7]  0x0980d0  
[8]  0x098100  
[9]  0x098310  
[10] 0x098320  
[11] 0x098790  
[12] 0x098880  
[13] 0x099320  
[14] 0x099c00  
[15] 0x099d80  BuildVendorIE (VULNERABLE)
```

### 7. FUN_00096ff0 Frame Analysis

The function containing the COOP gadgets (0x96ff0-0x97243):
```
Prologue: sub sp, sp, #0x80
          stp x29, x30, [sp, #0x40]
          stp x24, x23, [sp, #0x50]
          stp x22, x21, [sp, #0x60]
          stp x20, x19, [sp, #0x70]

Epilogue: ldp x20, x19, [sp, #0x70]
          ldp x22, x21, [sp, #0x60]
          ldp x24, x23, [sp, #0x50]
          ldp x29, x30, [sp, #0x40]  ← x30 from [SP+0x48] = second_buf[32]!
          add sp, sp, #0x80
          ret
```

The epilogue x30 offset ([SP+0x48]) matches gadget 0x96f74 exactly.

### 8. Stack Pointer Values (POTENTIAL)

The stack at known offsets contains absolute addresses:
```
[SP+0x00] = pointer to SP+0x28 (absolute stack address)
[SP+0x08] = 0x100 (buffer size)
[SP+0x10] = pointer to SP+0x130 (absolute stack address)  
[SP+0x18] = 0x100 (buffer size)
```

These are the ONLY absolute addresses on the stack. No standard epilogue gadget reads x30 from [SP+0x00] or [SP+0x10] directly (post-index gadgets read x30 from [SP+8] = 0x100).

### 9. Builder Buffer Overflow (ROOT CAUSE — NEW)

**The empirical crash at vendor_class >= 222 is NOT from BuildVendorIE.**

For Type 2/3 (Mode 2/3, encrypted):
- vtable[4] (0x96e90) writes variable data at buffer + 62 WITHOUT bounds check
- vtable[5] (0x96f00 finalize) returns only 62 (doesn't count vtable[4] data)
- BuildVendorIE receives data_length=62 → copies 62 bytes → NO overflow in BVE

The overflow is in the BUILDER BUFFER itself:
- Buffer = 256 bytes at SP+0x130 (first) or SP+0x28 (second)
- Variable data starting at offset 62 overflows at byte 194+
- Bytes 194-209 → saved x29 (8B) + saved x30 (8B) of FUN_00093b00
- Full 8-byte x30 control → arbitrary code execution

**Two-buffer amplification**: Second buffer vtable[4] overflow reaches first_data_length
at SP+0x128, enabling BuildVendorIE as a secondary exploit primitive.

See `caller_stack_layout.md` for the complete chain description.

### 10. Type 1 vs Type 2/3 Builder Analysis (NEW)

Type 1 (Mode 1, plaintext):
- vtable[4] = 0x021f0 (no-op) → NO variable data, NO overflow
- vtable[5] returns write_pos + 0x1C ≈ 42 → no BVE overflow

Type 2/3 (Mode 2/3, encrypted):
- vtable[4] = 0x96e90 (UNCHECKED) → overflow for data >= 194 bytes
- vtable[5] returns write_pos + 0x30 ≈ 62 → no BVE overflow

**Only Mode 2/3 is vulnerable.** The exploit requires the target network to use
Aes128Gmac encryption (security mode 2 or 3), which is the default for lp2p games.

## Paths Forward

### A. Brute-Force ASLR — ★ DEAD (CONFIRMED)
- ldn does NOT restart after crash — stays dead until system reboot
- System reboot = new ASLR for all processes (csrng on 22.5.0)
- **Result**: crash = lose ldn entirely. 1 attempt per boot. NOT convergent.
- **Source**: Atmosphere pm source (pm_process_manager.cpp) — no auto-restart logic.
  boot2 launches ldn with launch_flags=0, then exits. No supervisor.
  Switchbrew PM services — no restart mechanism documented.

### B. COOP for Side-Effect — ★ DEAD
- x20 is a plain C struct (scan entry), NOT polymorphic → all x20 COOP gadgets crash
- x19 COOP only reaches vtable[1] = deleting destructor (no side effects)
- Even if a COOP gadget worked, its epilogue reads x30 from stack = ASLR-dependent

### C. Cross-Process Info Leak (UNEXPLORED — BEST REMAINING PATH)
- Different HOS sysmodule leaks ldn's ASLR base
- bsd sysmodule AddrInfo deserialization bug (unfixed on 22.5.0) — most promising
- Could also leak through IPC shared memory, error responses, or logging
- Requires: separate vulnerability research on bsd/other system components

### D. HOS ASLR Weakness — ★ DEAD (CONFIRMED)
- Loader ASLR PRNG was weak pre-15.0.0 (32-bit seed from svcGetInfo, predictable)
- **Fixed in FW 15.0.0**: loader switched to csrng (Secure Monitor TRNG)
- User is on FW 22.5.0 — csrng in use, no weakness
- NRO ASLR (`ro` service) also fixed in 15.0.0 (was TinyMT, now csrng)
- **Source**: Switchbrew System_Flaws, 15.0.0 changelog

### E. Non-Crashing Protocol Probing — VIABLE (TOP PRIORITY)
- Non-crashing overflow (x30→0x93cb8) keeps ldn alive
- Invisible overflow (preserve x30) also keeps ldn alive
- Multiple attempts per boot with SAME ASLR base
- **Strategy**: redirect x30 to different page-9 functions that may:
  - Send WiFi frames containing internal pointers → ASLR leak
  - Produce observable protocol-level behavior differences
  - Write data to attacker-readable location
- Requires: systematic scan of all reachable functions in 0x90000-0x9FFFF

### F. Page-9 Data Leak Function Search — NEW (HIGH PRIORITY)
- 2-byte partial overwrite reaches any function in 0x90000-0x9FFFF
- 65,536 possible target addresses (2-byte range)
- Need to find a function that:
  - Sends data containing ASLR-dependent address over network
  - Returns internal pointer through lp2p protocol response
  - Writes to WiFi action frame with address content
  - Triggers IPC that exposes addresses to another process
- Key: function must work with the corrupted register state at the redirect point

## Unexplored Protocol Paths

- G2g packet builder/parser initialization gaps
- WiFi action frame echo/forwarding paths
- Error response paths (FUN_0009cef0) — may send error with internal address
- VendorSpecific DHCP option (0x2b) echoing
- IPC response buffer padding — may include uninitialized stack data with addresses

## HOS Sysmodule Lifecycle (CONFIRMED)

```
boot2 (launch_flags=0) → pm:shell LaunchProgram → loader DecideAddressSpaceLayout
  → GenerateSecureRandom(csrng) → svc::CreateProcess → ldn starts
  → boot2 EXITS (no supervisor)

If ldn crashes:
  → pm detects ProcessEvent::Crashed, clears process flag mask 4
  → pm signals ProcessEventWaiter (if NotifyExit flag set — NOT for ldn)
  → ldn process STAYS DEAD
  → Network connectivity features LOST until system reboot
  → System reboot → new boot2 → new ASLR for ldn
```

## Page-9 Data Leak Scan — ★ DEAD (EXHAUSTED)

**Completed systematic analysis of all functions in 0x90000-0x9FFFF. No ASLR data leak found.**

### Why no data leak is possible through the overflow:

1. **Heap copy is byte-truncated**: BuildVendorIE stores the IE to heap using `(data_length + 5) & 0xFF`
   as the size. For overflow data_length=263: heap copy = 12 bytes. The overflow region (positions
   253+: x29, x30) **never reaches the heap or WiFi broadcast**.

2. **Data pipeline is attacker-only**: attacker_data → stack → heap → WiFi. No ASLR addresses
   enter this pipeline at any point. The broadcast contains only attacker-supplied data.

3. **No useful page-9 redirect targets**: Of ~230 functions in 0x90000-0x9FFFF:
   - Functions with `ldr x8, [x19]` (17 hits) are all internal IPC handlers/reference counting
   - FUN_0009d320 (largest) is AcquireNetworkValues (socket ioctls)
   - FUN_0009b580 is a session table lookup
   - FUN_00098320 is scan results retrieval
   - None send data over WiFi with ASLR-dependent content

4. **Redirect to function entries crashes**: x0 = small int (BuildVendorIE return) → first
   dereference of param_1 segfaults. Mid-function redirects have wrong SP.

5. **Broadcast is asynchronous**: Advertisement broadcast happens via periodic callback
   (0x95160 → 0x94040), reading from heap data that was stored BEFORE the overflow.

### BuildVendorIE heap store (confirmed from disassembly at 0x99d80):
```
0x99e08: add  w26, w19, #5           ; total_ie_len = data_len + 5
0x99e0c: strb w26, [sp, #0xd]        ; header[1] = total_ie_len & 0xFF (BYTE TRUNCATION)
...
0x99e2c: bl   memcpy                  ; memcpy(SP+0x13, data, data_len) ← OVERFLOW
0x99e38: and  x3, x26, #0xff         ; heap_copy_size = total_ie_len & 0xFF
0x99e40: bl   store_vendor_ie         ; stores only heap_copy_size bytes to heap
```

For data_len=263: heap_copy_size = (263+5) & 0xFF = 268 & 0xFF = 12 bytes.
Only header + 5 data bytes reach heap. Overflow data at x29/x30 positions stays on stack only.

## Updated Recommendation

**ALL STATIC ASLR BYPASS PATHS ARE DEAD OR EXHAUSTED.**

| Path | Status | Detail |
|------|--------|--------|
| A: Brute-force | ★ DEAD | ldn dies, no restart, reboot = new ASLR |
| B: COOP gadgets | ★ DEAD | x20 plain struct, x19 destructor only |
| C: Cross-process leak | UNEXPLORED | bsd AddrInfo bug — **BEST REMAINING** |
| D: ASLR PRNG weakness | ★ DEAD | Fixed FW 15.0.0, user on 22.5.0 |
| E: Protocol probing | VIABLE but needs live testing | Timing oracle, behavior differences |
| F: Page-9 data leak | ★ DEAD (EXHAUSTED) | Full scan complete, no leak primitive |
| G: Heap copy overflow | ★ DEAD | Byte-truncated, 12B for 263B input |

**Remaining viable paths (prioritized):**

1. **Cross-Process ASLR Leak (Path C)**: Investigate bsd sysmodule AddrInfo deserialization bug
   (unfixed on 22.5.0) as an independent ASLR leak for ldn's code base. This is the last
   realistic path for a fully remote exploit chain.

2. **Dynamic Protocol Probing (Path E)**: Use non-crashing overflow with live WiFi monitoring
   to detect observable behavior differences. Requires user present + WiFi monitor adapter.

3. **Alternative vulnerability search**: Look for other bugs in ldn (format string, integer
   overflow, use-after-free) that might provide a direct ASLR info leak primitive.
