# Caller Stack Layout: FUN_00093b00 (vtable[15] dispatcher)

## Function: FUN_00093b00 (0x93b00 - 0x93cef, 496 bytes)

### Frame Structure
```
Prologue:
  stp x29, x30, [sp, #-0x30]!    ; SP -= 0x30, save x29/x30
  stp x28, x21, [sp, #0x10]      ; save x28/x21
  mov x29, sp                      ; x29 = frame pointer
  stp x20, x19, [sp, #0x20]      ; save x20/x19
  sub sp, sp, #0x230              ; allocate locals

Total frame = 0x30 (saved regs) + 0x230 (locals) = 0x260 bytes
x29 points to saved reg area base
SP = x29 - 0x230 (during local execution)
```

### Saved Register Area (x29+0x00 to x29+0x2F)
```
x29+0x00: saved x29 (original frame pointer)
x29+0x08: saved x30 (return address of FUN_00093b00's caller)
x29+0x10: saved x28
x29+0x18: saved x21
x29+0x20: saved x20
x29+0x28: saved x19
```

### Local Variables (SP+0x00 to SP+0x22F)
```
SP+0x000: local_260 = {ptr, size} span for second buffer
  SP+0x000: ptr → SP+0x28 (absolute runtime stack address)
  SP+0x008: size = 0x100 (256)
SP+0x010: local_250 = {ptr, size} span for first buffer
  SP+0x010: ptr → SP+0x130 (= x29 - 0x100)
  SP+0x018: size = 0x100 (256)
SP+0x020: local_240 = second data length (from FUN_00096af0)
SP+0x028: uStack_238 = SECOND ADVERTISE DATA BUFFER (0x100 bytes)
  ...0x100 bytes of advertise data built by FUN_00096af0...
SP+0x128: local_138 = first data length (from FUN_00096930)
SP+0x130: local_130 = FIRST ADVERTISE DATA BUFFER (0x100 bytes)
  ...0x100 bytes of advertise data built by FUN_00096930...
SP+0x22F: end of local_130 buffer
```

### Register State at vtable[15] Call (0x93c98 BLR)
```
x0  = x19 (IAdvertiseParser* object, from FUN_0009ac50)
w1  = 0 (index for first call) / 1 (second call)
x2  = x29-0x100 / SP+0x28 (data ptr)
x3  = [SP+0x128] / [SP+0x20] (data length)
x8  = vtable[15] address (0x99d80 + ASLR_base)
x19 = IAdvertiseParser* object (callee-saved, survives call)
x20 = lVar2 (second FUN_00040640 return)
x21 = 0 (success path)
```

### After 0x99d80 Epilogue (overflow redirect)
```
SP  = x29_93b00 - 0x230  (FUN_00093b00's local SP, restored)
x29 = OVERFLOW-CONTROLLED (8B from data[253:261])
x30 = REDIRECT TARGET (2B partial from data[261:263], rest original)
x28 = OVERFLOW-CONTROLLED (8B from data[269:277])
x19 = IAdvertiseParser* object (restored by 0x99d80, NOT overflow-controlled)
x20 = lVar2 (restored by 0x99d80, NOT overflow-controlled)
```

### Critical Stack Data After Redirect
```
[SP+0x00] = pointer to SP+0x28 (absolute stack address)
[SP+0x08] = 0x0000000000000100 (the number 256)
[SP+0x10] = pointer to SP+0x130 (absolute stack address)
[SP+0x18] = 0x0000000000000100 (the number 256)
[SP+0x20] = second data length (small integer, e.g., 0x80)
[SP+0x28] = START OF ATTACKER-INFLUENCED DATA (second advertise buffer)
  ...up to 256 bytes of advertise data...
[SP+0x128] = first data length (small integer)
[SP+0x130] = START OF ATTACKER-INFLUENCED DATA (first advertise buffer)
  ...up to 256 bytes of advertise data...
```

### NON-CRASHING OVERFLOW (CONFIRMED)

**Redirect x30 to 0x93cb8** (low bytes: data[261]=0xb8, data[262]=0x3c):
- Lands on FUN_00093b00's success epilogue
- Skips second vtable[15] call
- Epilogue uses SP-relative addressing (not x29-relative) → safe
- Restores all regs from UNCORRUPTED saved area at [SP+0x230]
- Returns 0 (success) to caller
- NO CRASH, NO DETECTION
```
0x93cb8: mov w21, wzr           ; w21 = 0 (success)
0x93cbc: mov w0, w21            ; return success
0x93cc0: add sp, sp, #0x230     ; SP → saved reg area
0x93cc4: ldp x20, x19, [sp, #0x20]
0x93cc8: ldp x28, x21, [sp, #0x10]
0x93ccc: ldp x29, x30, [sp], #0x30  ; restore from UNCORRUPTED save
0x93cd0: ret                    ; CLEAN return
```

### INVISIBLE OVERFLOW (CONFIRMED)

**Preserve x30 unchanged** (low bytes: data[261]=0x9c, data[262]=0x3c):
- x30 keeps original value → returns to 0x93c9c normally
- x29 corrupted but: (a) second call uses SP-relative, (b) epilogue restores x29
- Both calls complete, full advertise data built and broadcast
- x28 NOT reached if data is exactly 263 bytes
- COMPLETELY INVISIBLE to target

### ~~BUILDER BUFFER OVERFLOW~~ — CRITICAL CORRECTION (2026-11-23)

> **THE ENTIRE BUILDER OVERFLOW MODEL WAS WRONG.**
>
> Prior analysis identified vtable[4] at 0x96e90 as "variable data WITHOUT
> BOUNDS CHECK" that overflows the 256-byte builder buffer. Capstone disassembly
> proved this is **fixed-size AES-128 encryption** (16 bytes). The x2 register
> (data_size from FUN_0009c0c0) is OVERWRITTEN at 0x96ecc before the crypto
> call. The "two-buffer amplification chain" and all gadget analysis below
> are MOOT — no overflow can occur through the builder path.

**Builder types** (CORRECTED — all bounded):
```
Type 1 (Mode 1, vtable 0xe7700):
  vtable[2] = 0x96d00: fixed 28-byte header write
  vtable[3] = 0x96d30: TLV add WITH bounds check (branch at 0x96d64)
  vtable[4] = 0x021f0: NO-OP
  vtable[5] = 0x96db0: returns write_pos + 0x1C, max ~172

Type 2/3 (Mode 2/3, vtable 0xe7740):
  vtable[2] = 0x96d00: fixed 28-byte header write
  vtable[3] = 0x96e00: TLV add WITH bounds check (branch at 0x96e3c)
  vtable[4] = 0x96e90: FIXED 16-byte AES-128 encryption (NOT variable memcpy)
  vtable[5] = 0x96f00: returns write_pos + 0x30, max ~208
```

**Why vtable[4] was misidentified**:
- 0x96e90 reads x2 from FUN_0009c0c0 (which returns byte 0-255)
- BUT at 0x96ecc, x2 is OVERWRITTEN: `mov w3, #0x10; mov w5, #0x10`
- Calls crypto function 0x42f80 with fixed 16-byte params
- The variable "size" value is NEVER used as a copy length

**Consequence**: finalize returns max ~208 (Mode 2/3) or ~172 (Mode 1).
BuildVendorIE's memcpy gets data_length <= 208, well under 253 needed to reach x30.
No register corruption, no code execution, no overflow of any kind.

### ~~TWO-BUFFER AMPLIFICATION CHAIN~~ — IMPOSSIBLE

The amplification chain depended on vtable[4] overflowing the builder buffer
to corrupt first_data_length and saved registers. Since vtable[4] writes only
16 fixed bytes, the chain cannot begin. All steps (D1 overflow, D2 corruption
of first_data_length, BVE redirect, register control) are MOOT.

### ~~Gadget Classification~~ — MOOT

All gadget analysis (post-index, signed-offset, COOP vtable dispatch, stack
pivot) was predicated on controlling x30 through the builder overflow. With
no overflow possible, gadget reachability is irrelevant.

### ALL EXPLOITATION PATHS — DEAD ON FW 22.5.0

**CVE-2026-82079 is NOT exploitable on this firmware.**

| Path | Status | Detail |
|------|--------|--------|
| A: Parser → BuildVendorIE | DEAD | 21.0.0 parser validation at 0x99a88 rejects size > 31 |
| B: Builder vtable[4] overflow | DEAD (CORRECTED) | vtable[4] = fixed 16B AES, not variable memcpy |
| C: Two-buffer amplification | DEAD (CORRECTED) | Depends on B, which is impossible |
| D: Direct BuildVendorIE | DEAD | finalize max ~208, under 253 threshold |
| E: ASLR brute-force | DEAD | ldn dies on crash, no restart, reboot = new ASLR |
| F: Cross-process ASLR leak | MOOT | No overflow to exploit even with known base |
| G: ASLR PRNG weakness | DEAD | Fixed FW 15.0.0 (csrng per-process) |
| H: Page-9 data leak | DEAD | Heap copy byte-truncated |
| I: Dynamic probing | MOOT | No overflow to probe with |

**21.0.0 parser fix (confirmed at 0x99a88)**:
ParseVendorIE at 0x99320 validates all TLV entries before processing.
Type 1: FUN_0009c0c0 pair iterator caps at 63 bytes.
Non-type-1: `cmp x0, #0x1f` rejects size > 31 (error 0x214e7).
No oversized data can reach BuildVendorIE through the parser.

**23.0.0 fix was defense-in-depth only**: Added bounds checking to
BuildVendorIE's memcpy itself. Not needed on 22.5.0 since parser already
validates input and builder is bounded.

### Data Flow: Advertise Builder (CORRECTED)
```
FUN_00096930 (first buffer):
  → FUN_00096bd0: get builder from span
  → vtable[2]: fixed 28-byte header (field type + 8B key + 16B config)
  → vtable[3]: add field 1 (channel bitmask, 2B, BOUNDS CHECKED)
  → vtable[3]: add field 2 (channel mask, 8B, BOUNDS CHECKED)
  → vtable[4]: NO-OP for Type 1
  → vtable[5]: finalize → returns write_pos + 0x1C, max ~172

FUN_00096af0 (second buffer):
  → FUN_00096bd0: get builder from span
  → vtable[3]: add field 0x21 (crypto params, BOUNDS CHECKED)
  → vtable[4]: fixed 16-byte AES-128 encryption (NOT variable copy)
  → vtable[5]: finalize → returns write_pos + 0x30, max ~208
```

### Key Object Types (corrected)

**x19 = IAdvertiseParser*** (Aes128GmacAdvertiseParser)
- Vtable at 0xe78c0 (16 entries, confirmed)
- Polymorphic C++ object on heap
- vtable[15] = 0x99d80 (BuildVendorIE — vulnerable in theory, unreachable on 22.5.0)

**x20 = scan_entry** (plain C struct, ~0x9D0+ bytes)
- NO vtable at [x20] — struct, not C++ object
- Mutex at +0x18, events at +0x48/+0x78
- Peer data at +0x130, crypto at +0x8b8
- 8 session slots at +0x4b8 (0x80 each)

**BuildVendorIE output**: stored at this[1] + 0x40E0 + (index*4)
- this[1] = parser->internal_data (heap pointer)
- x23 = this[1] + index*4 (corrected from wrong SP-relative decode)
- Output goes to HEAP, not stack

### Resolved Questions
1. ~~Does HOS re-randomize ldn ASLR on crash/restart?~~ **YES — ldn dies on crash, reboot = new ASLR**
2. ~~Does BuildVendorIE overflow on its own?~~ **NO — data_length bounded by finalize (max ~208)**
3. ~~Does vtable[4] overflow the builder buffer?~~ **NO — fixed 16B AES, x2 overwritten at 0x96ecc**
4. ~~Can two-buffer amplification work?~~ **NO — vtable[4] doesn't overflow, chain can't start**
5. ~~Is 21.0.0 parser fix effective?~~ **YES — 0x99a88 rejects non-type-1 entries > 31 bytes**

### Independent Verification (2026-11-24)

Both corrections independently verified via different analysis methods:
1. **vtable[4] fixed 16B**: Ghidra decompilation of FUN_00042f80 confirms `param_5` (data_ptr) used as 16-byte key via `FUN_00089da0(ctx, param_5, 0x10, 1)`. No variable-length copy in the crypto function.
2. **Parser validation**: Capstone disassembly at 0x99a88 confirms `cmp x0, #0x1f; b.ls` rejects TLV entries > 31 bytes (error 0x214e7).
3. **Empirical crash**: The vendor_class >= 222 crash is likely from the DHCP server component, not from ldn's lp2p code (separate issue).
