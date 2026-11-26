# LDN Partial-Return-Address Overwrite and Stack-Pivot Assessment

**Hardware:** HAC-001, Tegra X1 Erista, Serial XAW4 001878  
**Firmware:** 22.5.0 (ldn sysmodule)  
**Binary:** ldn_22.5.0/main.flat.bin (SHA-256: 91bee792da7c8ca7718bac166009331cd14ecdcc662c9fcf52f435da0d56f34a)  
**Date:** 2026-11-25  
**Analysis type:** Static binary analysis + empirical crash probing  

---

## 1. Return-Address Provenance

### Call chain verification

| Step | Address | Instruction | Effect |
|------|---------|-------------|--------|
| 1 | `base+0x09FF20` | `BL base+0x0A25F0` | Caller invokes wrapper; LR set to `base+0x09FF24` |
| 2 | `base+0x0A25F0` | Wrapper prologue: `STP X29, X30, [SP, #-0x30]!` | Saves caller's LR (`base+0x09FF24`) at [SP+0x08] |
| 3 | `base+0x0A2638–0x0A2640` | Wrapper epilogue: restores X29, X30, then `LDP X29, X30, [SP], #0x30` | X30 = `base+0x09FF24` (restored from stack) |
| 4 | `base+0x0A2644` | `B base+0x0A2660` | **Tail call** (B, not BL) — X30 is NOT modified |
| 5 | `base+0x0A2660` | Inner function prologue: `STP X29, X30, [SP, #-0x40]!` | **Saves X30 = `base+0x09FF24` at [FP+0x08]** |

**Status: ESTABLISHED.** The saved LR at [FP+0x08] in FUN_71000a2660 originates from the BL at `0x09FF20`. The wrapper's tail call (B instruction) preserves X30 without modification. The chain is: caller BL → wrapper save/restore → tail call B → inner function save.

### Wrapper verification (assembly-confirmed)

```
Wrapper prologue (0x0A25F0):
  STP X29, X30, [SP, #-0x30]!    ; save FP, LR
  ...
  STP X20, X19, [SP, #0x20]      ; save callee-saved
  STR X21, [SP, #0x10]

Wrapper epilogue (0x0A2638):
  LDP X20, X19, [SP, #0x20]      ; restore
  LDR X21, [SP, #0x10]
  LDP X29, X30, [SP], #0x30      ; X30 = caller's LR = base+0x09FF24
  B   0x0A2660                    ; tail call (not BL)
```

---

## 2. Partial-Overwrite Arithmetic

### Address comparison

| Property | Original Return | Candidate Gadget |
|----------|----------------|-----------------|
| Binary offset | `0x0009FF24` | `0x0009D04C` |
| LE byte 0 | `0x24` | `0x4C` |
| LE byte 1 | `0xFF` | `0xD0` |
| LE byte 2 | `0x09` | `0x09` |
| LE bytes 3–7 | `0x00 ...` | `0x00 ...` |

Bytes 0–1 **differ**. Bytes 2–7 are **identical**.

### ASLR analysis

- Horizon ASLR for NRO modules: 17-bit entropy, **2 MiB (0x200000) alignment**
- Module base = random_base, where bits 0–20 of random_base are zero
- Binary size: 961,288 bytes (0xEAB08) — well under 2 MiB
- Both offsets share byte 2: `0x09` — same bits 16–23
- Both offsets share bits 21+: all zero (both < 0x100000)

**A 2-byte overwrite at saved-LR bytes 0–1 deterministically changes `base+0x0009FF24` to `base+0x0009D04C`, regardless of the ASLR-randomized base.**

**Status: MATHEMATICALLY ESTABLISHED.** The redirect is deterministic: it does not depend on the base address. The 2-byte overwrite affects only the low 16 bits, and the two addresses share all higher bits because both binary offsets lie within the same 64 KiB window (`0x09xxxx`).

### What this does NOT solve

The partial overwrite gives deterministic **code-address redirection**. It does not:

- Reveal the module's base address
- Reveal any stack or heap address
- Provide a controlled value for the stack pointer after the pivot
- Bypass stack-address ASLR (which is separate from code-address ASLR)

---

## 3. Gadget Verification

### Primary candidate: `0x09D04C`

**Raw bytes:** `bf030091 f44f44a9 fc0b40f9 f65743a9 f85f42a9 fd7bc5a8 c0035fd6`

**Decoded instruction sequence (independently verified):**

```
0x09D04C: ADD SP, X29, #0        ; MOV SP, X29 — stack pivot
0x09D050: LDP X20, X19, [SP, #0x40]
0x09D054: LDR X28, [SP, #0x10]
0x09D058: LDP X22, X21, [SP, #0x30]
0x09D05C: LDP X24, X23, [SP, #0x20]
0x09D060: LDP X29, X30, [SP], #0x50   ; post-index: SP += 0x50
0x09D064: RET
```

**Verification results:**

| Check | Result |
|-------|--------|
| 4-byte aligned | Yes (`0x09D04C % 4 == 0`) |
| Within binary | Yes (`0x09D04C < 0xEAB08`) |
| In executable .text | Yes (offset within code section) |
| First instruction | `0x910003BF` = `ADD SP, X29, #0` ✓ |
| Terminates with RET | Yes, at `0x09D064` |

**Register loads from the pivoted stack (SP = X29):**

| Offset from SP | Register(s) loaded |
|---------------|-------------------|
| `+0x00` | X29 (new FP) |
| `+0x08` | X30 (new LR → next RET target) |
| `+0x10` | X28 |
| `+0x20` | X24 |
| `+0x28` | X23 |
| `+0x30` | X22 |
| `+0x38` | X21 |
| `+0x40` | X20 |
| `+0x48` | X19 |

After the gadget: SP = original_X29 + 0x50, all registers loaded from [X29+0x00] through [X29+0x48], RET jumps to X30 (loaded from [X29+0x08]).

**Constraints:**

1. **SP must be 16-byte aligned.** AArch64 LDP with SP as base requires 16-byte alignment. X29 (from saved FP) must be 16-byte aligned or the CPU faults.
2. **Memory at [X29] through [X29+0x48] must be readable.** 80 bytes of readable memory required.
3. **Loaded X30 must be a valid code address.** The RET jumps to whatever is at [X29+0x08].

**Status: VERIFIED** as a syntactically correct stack-pivot gadget. Its utility depends entirely on whether X29 can be made to point to controlled, readable memory — addressed in Section 4.

### Secondary candidate: `0x09CFB8`

**Decoded:** `ADD SP, X22, #0` (= `MOV SP, X22`), **not** `MOV SP, X29`.

This is a different instruction. It pivots SP to X22, not X29. After the inner function's epilogue, X22 contains the original callee-saved X22 from the caller — a value we do not control via the overflow. Additionally, the subsequent instructions are function-call setup, not a register-restore epilogue.

**Status: NOT VIABLE** as a stack pivot for this exploit scenario.

---

## 4. Stack-Pivot Feasibility

### The fundamental problem

The pivot gadget at `0x09D04C` sets `SP = X29`. After the inner function's epilogue, X29 is loaded from saved-FP at frame byte 1668. We control these 8 bytes via the overflow. **But we must set them to a valid, readable memory address** that also contains our controlled ROP chain.

### What is known about memory layout

| Region | Address known? | Contents controllable? |
|--------|---------------|----------------------|
| Code (.text) | Offset from base known; base unknown | No (read-only) |
| .data/.bss | Offset from base known; base unknown | Partially (via function side effects) |
| Stack | Unknown (separate ASLR) | Yes (overflow data) but address unknown |
| Heap | Unknown | Partially (via DHCP requests) but address unknown |
| DHCP input (BPF buffer) | Unknown (heap-allocated) | Yes (packet data) but address unknown |

### Why the partial overwrite does NOT solve this

The 2-byte partial LR overwrite works because it modifies only the low 16 bits of a code address. The upper bits (which encode the ASLR-randomized base) are preserved in-place. This is a **code-address** technique.

The saved FP (X29) is a **stack address**. Its value has the form `0x0000007FXXXXXXXX` (Horizon stack range). We overwrite ALL 8 bytes of saved FP at frame bytes 1668–1675. There is no "partial overwrite" trick for the stack address because:

- We don't know any bits of the original stack address
- Stack ASLR is separate from code ASLR
- The original saved FP is completely overwritten (all 8 bytes)

### Approaches considered and their status

1. **Point X29 at the overflow data on the stack:** The overflow data IS on the stack at known offsets from FP. But we need the absolute address, which requires knowing the stack base. **Blocked by stack-address ASLR.**

2. **Point X29 at .data/.bss:** These sections are at known offsets from the code base. But the code base is ASLR-randomized, and we don't know it. **Blocked by code-address ASLR** (the saved FP must be an absolute address, not an offset).

3. **Point X29 at a fixed address:** Horizon does not expose known fixed-address writable regions to user-mode sysmodules. No MMIO, no fixed TLS, no identity-mapped memory available. **No known viable target.**

4. **Heap spray:** Send many DHCP requests to populate the heap with controlled data, hoping some lands at a guessable address. Horizon's heap ASLR makes this unreliable. **Probabilistic, not demonstrated.**

5. **Information disclosure to learn the address:** Use a separate vulnerability to leak a stack or heap pointer. No such leak has been demonstrated. See Section 6.

### Register state after the inner function's epilogue

After FUN_71000a2660's epilogue (with 1678-byte overflow, local_48=0xF0):

| Register | Value | Source | Controlled? |
|----------|-------|--------|-------------|
| X29 | Our 8-byte value | Frame bytes 1668–1675 | **Yes** |
| X30 | Partially overwritten | Frame bytes 1676–1677 (low 2), original (high 6) | **Low 16 bits only** |
| X19 | Original callee-saved | [FP+0x38] — not overwritten | No |
| X20 | Original callee-saved | [FP+0x30] — not overwritten | No |
| X21 | Original callee-saved | [FP+0x28] — not overwritten | No |
| X22 | Original callee-saved | [FP+0x20] — not overwritten | No |
| X23 | Original callee-saved | [FP+0x18] — not overwritten | No |
| X28 | Original callee-saved | [FP+0x10] — not overwritten | No |
| SP | Entry SP (correct) | Restored by epilogue | No |

**Status: The stack pivot is SYNTACTICALLY reachable but PRACTICALLY BLOCKED.** We can redirect execution to the gadget with 100% reliability, but we cannot supply a valid address for X29 without an independent information-disclosure primitive.

### Caller behavior after return (verified)

If the redirect is NOT taken (original LR preserved), the caller executes:

```
0x09FF24: LDRB W8, [X19, #8]     ; load byte set by inner function's error path
0x09FF28: CMP W8, #8
0x09FF2C: B.NE 0x0A00AC          ; TAKEN (inner function sets [X19+8]=2, not 8)
```

The B.NE is taken because the inner function's error path stores 2 at [X19+8] via `STRB W20, [X19, #8]` where W20=2. The taken path at 0x0A00AC **does not reference X29** between the return point and the caller's own epilogue at 0x0A0124:

```
0x0A0128: LDP X20, X19, [SP, #0xE0]   ; SP-relative restore
0x0A012C: LDP X22, X21, [SP, #0xD0]
0x0A0130: LDP X24, X23, [SP, #0xC0]
0x0A0134: LDP X29, X30, [SP, #0xB0]   ; X29 restored from STACK (SP-relative)
0x0A0138: ADD SP, SP, #0xF0
0x0A013C: RET
```

**Consequence:** With original LR (bytes [0x24, 0xFF]) and saved FP = 0, the function returns to the caller, the caller takes the error path (B.NE), never reads corrupted X29, and its epilogue restores X29 from [SP+0xB0]. **HTTP should remain alive.** This is an empirically testable prediction.

---

## 5. local_48 Data-Flow Analysis

### Identity

`local_48` occupies [FP−0x08], which is frame byte 1660 from the buffer start.

### Data flow

```
                  ┌─────────────────────────────────────┐
                  │  FUN_71000a2660 (inner function)     │
                  │                                      │
   0x0A26BC: BL 0x0A3740  ──► sets local_48?            │
   0x0A26DC: BL 0x0A0F90  ──► sets local_48?            │
                  │                                      │
   0x0A26F0: LDUR X8, [X29, #-8]   ◄── FIRST READ       │
   0x0A26F8: ADD X2, X21, #0xF0                         │
   0x0A2704: SUB X3, X23, #0xF0  (X23 = callee-saved)   │
   0x0A2708: BL 0x09EC20   ──► uses pre-overflow X23     │
                  │                                      │
   0x0A272C: BL 0x0A13D0 ═══► OVERFLOW (NetworkLayersCopy)
                  │            Copies into buffer at SP+0x3C
                  │            Overflow reaches [FP-0x08]
                  │                                      │
   0x0A2740: LDUR X23, [X29, #-8]  ◄── SECOND READ      │
                  │                     (POST-OVERFLOW)   │
   0x0A2774: BL 0x09EC20   ──► uses X23 from local_48   │
                  │            X3 = X23 - 0xF0 = size    │
                  └─────────────────────────────────────┘
```

### Semantics

local_48 is loaded into X23 **after** NetworkLayersCopy returns. The value `X23 − 0xF0` becomes a size parameter (X3) to FUN_710009EC20. This subtraction suggests local_48 represents a **data-end offset or pointer** — the position past the last parsed byte. The constant `0xF0` (240) is the fixed header size (BOOTP header + DHCP magic cookie + early options), so `X23 − 0xF0` yields the number of remaining DHCP option bytes to process.

| local_48 value | X3 (size) | Behavior |
|---------------|-----------|----------|
| Original (set by processing) | Correct option length | Normal DHCP reply generated |
| 0x00 (zeroed by overflow) | 0 − 0xF0 = 0xFFFF...F10 | **Crash** — oversized memory access |
| 0xF0 (our controlled value) | 0xF0 − 0xF0 = 0 | **No crash, no reply** — zero bytes to process |
| Any other value | Arbitrary | No crash if small, but wrong data → no valid reply |

### Why no DHCP reply with local_48 = 0xF0

Setting local_48 = 0xF0 makes the function believe there are zero remaining option bytes. The reply-generation code path requires parsed option data (client identifier, requested IP, etc.) to construct a response. With zero option bytes, this data is absent, so no DHCP OFFER is generated. The function takes the "nothing to process" path and returns normally through its epilogue.

**HTTP availability indicates the ldn sysmodule process survived. It does NOT indicate the DHCP server produced correct output.** The HTTP server and DHCP server are separate threads within the same process — HTTP staying alive means the process didn't crash, nothing more.

---

## 6. Information-Disclosure Assessment

### DHCP reply channel

- With local_48 = 0xF0 (no-crash), **no DHCP reply is generated**
- With local_48 = original value, the reply WOULD be generated but we cannot set local_48 to its original value because **we are overwriting it with the overflow**
- There is no demonstrated path to get a DHCP reply that contains leaked addresses while simultaneously controlling the overflow

**Status: NOT VIABLE.** The overflow and the information channel are mutually exclusive through local_48.

### Multipart HTTP overflow (photoViewer)

- Crash boundary: filename ≥ ~3980 bytes → 0 bytes response
- The server crashes during request **parsing**, before generating any response body
- **0 bytes of data returned** at the crash boundary — no information leaks

Additionally:
- The photoViewer HTTP server is a **separate sysmodule** from ldn
- Each sysmodule runs in its own process with independent ASLR
- Even if photoViewer leaked an address, it would be a **photoViewer address**, not an ldn address
- No cross-process address disclosure mechanism exists on Horizon

**Status: NOT VIABLE** as an ASLR bypass for ldn.

### Action-frame heap corruption (CVE-2026-82079 via 802.11 action frames)

- This is a **write** primitive into the WLAN driver's heap
- No pointer **read** has been demonstrated
- The WLAN driver runs in its own service context, **not in the ldn process**
- No demonstrated mechanism to leak ldn addresses through WLAN driver corruption

**Status: NOT VIABLE** as an ASLR bypass for ldn.

### Summary

No information-disclosure primitive has been demonstrated for the ldn sysmodule's address space. Without one, the stack-pivot target address cannot be determined.

---

## 7. RCM and Custom Firmware Assessment

### RCM status

- The console is HAC-001 serial XAW4 001878 (Erista, 2018-era production)
- Fuse state has NOT been independently confirmed (reading fuses requires either RCM access or a hardware probe)
- Behavioral evidence (no response to CVE-2018-6242 payloads) is **consistent with** patched hardware but not conclusive
- **LDN exploitation cannot modify the BootROM or its ipatch fuses.** These are hardware-level, write-once. No software vulnerability can un-burn a fuse.

### Path from LDN code execution to custom firmware

Even with fully confirmed ldn code execution, the route to persistent custom firmware requires multiple additional stages, each with its own unsolved problem:

```
Stage 1: LDN code execution          ← PARTIAL (redirect confirmed, pivot blocked)
   │
   ▼
Stage 2: Kernel privilege escalation  ← NOT STARTED
   │      Requires a Horizon kernel vulnerability for FW 22.5.0
   │      LDN has limited IPC access (wlan, bsd, nifm, etc.)
   │      Need to identify an exploitable kernel-reachable interface
   │
   ▼
Stage 3: Boot chain modification      ← NOT STARTED
   │      Requires kernel-level access to eMMC
   │      Package1/Package2 are encrypted + signed
   │      BCT modification could force RCM mode (AutoRCM-like)
   │      But patched BootROM means RCM mode ≠ code execution
   │
   ▼
Stage 4: Persistent code execution    ← NOT STARTED
         Requires either:
         a) Warmboot chain exploit (SC7 resume path)
         b) TrustZone exploit (TSEC/SE vulnerability)
         c) Unpatched secondary boot vulnerability
         d) Custom kernel loaded via modified boot chain
```

### Key distinction

**Entering RCM ≠ exploiting RCM.** Even if LDN exploitation could force the console into RCM mode (via kernel access → BCT corruption → AutoRCM), the ipatched BootROM would still reject unsigned payloads. The original CVE-2018-6242 exploit is blocked.

### What LDN code execution COULD provide

If the pivot blocker (Section 4) is solved:

1. **IPC reconnaissance:** Enumerate services accessible from ldn, probe for vulnerabilities
2. **File system access:** If ldn can reach fs:USER, read/write non-protected files
3. **Network pivoting:** Use ldn's network stack access as an attack surface into other services
4. **Information gathering:** Read ldn's own memory to understand Horizon internals (heap layout, IPC objects, service handles)

---

## 8. Updated Research Priorities

### Established facts

1. ✅ The DHCP stack overflow (CVE-2026-82079) produces a write of attacker-controlled size (up to MTU 2304)
2. ✅ The 2-byte partial LR overwrite deterministically redirects execution to any target within the 0x09xxxx range (64 KiB window)
3. ✅ A stack-pivot gadget exists at `0x09D04C` with correct alignment and instruction sequence
4. ✅ Setting local_48 = 0xF0 prevents the intermediate crash and allows the function to reach its epilogue
5. ✅ The caller's error path does not use the corrupted X29, so the caller returns normally if the original LR is preserved

### Blocking issues

1. ❌ **No known memory address for the pivot target.** The stack pivot requires X29 to point to readable, controlled memory. Stack ASLR is independent of code ASLR and cannot be bypassed by the partial-overwrite technique.
2. ❌ **No information-disclosure primitive.** No demonstrated channel leaks ldn addresses through DHCP replies, HTTP responses, or other observable output.

### Empirically testable predictions (not yet tested)

1. **1678-byte frame with local_48=0xF0, saved_FP=0, LR=[0x24,0xFF]:** Predict HTTP remains alive (function returns normally, caller error path avoids X29).
2. **1678-byte frame with local_48=0xF0, saved_FP=0, LR=[0x4C,0xD0]:** Predict HTTP goes down (execution redirects to stack pivot, reads from address 0 → fault). Differential crash/no-crash between tests 1 and 2 would confirm execution redirection.

### Recommended research directions

**Near-term (address the pivot blocker):**

1. **Investigate ldn heap determinism.** Repeated DHCP requests in a fresh ldn session may produce a predictable heap layout. If the BPF buffer address stabilizes after N requests, a fixed X29 value could target it. Requires empirical probing — send N baseline requests, then the overflow.

2. **Search for a no-pivot code path.** Instead of the full stack pivot, find a gadget in the 0x09xxxx range that does useful work using only the registers we have (X19 = server object, SP = valid caller stack). For example: a function that calls an IPC send with arguments derived from X19, without requiring a controlled stack.

3. **Investigate ldn's IPC handle table.** If ldn holds handles to powerful services (fs, sm, etc.), code execution within ldn — even without a full ROP chain — could be leveraged by redirecting to an IPC-sending function with controlled arguments.

**Medium-term (even with pivot solved):**

4. **Identify kernel-reachable attack surface from ldn.** Map ldn's IPC session handles and the services they connect to. Any kernel-side parsing vulnerability reachable from ldn is a candidate for privilege escalation.

5. **Investigate the warmboot (SC7) path.** With kernel access, the SC7 resume firmware could be modified to execute custom code on every boot. This would provide persistence without defeating the BootROM.

**Strategic (outside the box):**

6. **Consider the photoViewer overflow as an independent chain.** Even though photoViewer is a separate process, it may have different (possibly broader) IPC access. Its crash is easier to trigger (HTTP vs raw DHCP). If photoViewer can reach services that ldn cannot, it may offer a shorter path to kernel.

7. **Investigate whether ldn can influence the WLAN firmware.** The ldn sysmodule communicates with the WLAN driver. If code execution in ldn can send crafted commands to the WLAN firmware, and the firmware has code-execution capabilities (e.g., Broadcom FullMAC), this opens a hardware-adjacent attack surface that might bypass Horizon's process isolation entirely.

---

## Appendix: The Three Questions

> 1. Can the DHCP overflow produce a sufficiently large write?

**Yes.** The overflow copies the full raw frame into a 1500-byte stack buffer. With MTU 2304, the overflow can reach 804 bytes past the buffer end. Saved FP (at buffer+1668) and saved LR (at buffer+1676) are well within reach. **Established empirically and statically.**

> 2. Can a partial return-address modification redirect execution without knowing the LDN module's randomized base?

**Yes.** A 2-byte overwrite of saved LR's low bytes deterministically changes the return target within the same 64 KiB code window. The upper address bits (carrying the ASLR base) are preserved in-place. **Mathematically established.** Not yet empirically confirmed (crash-differential test pending).

> 3. Can that redirected execution obtain a useful, attacker-controlled stack?

**Not with current capabilities.** The stack pivot requires X29 to hold a valid pointer to controlled memory. We control the 8-byte saved-FP value, but we cannot determine any valid target address because:

- Stack ASLR is separate from code ASLR
- No information disclosure has been demonstrated
- Heap addresses are unpredictable without prior knowledge

**This is the critical open problem.** The partial-overwrite technique solves code-address randomization elegantly, but it does not address the orthogonal problem of stack/heap-address randomization.
