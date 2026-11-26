# Probe Results Analysis — 2026-11-19

## Summary

The bootROM's EP0 control transfer handler has **two confirmed bugs**:

1. **Information leak via GET_STATUS over-read (up to 255 bytes).** The
   bootROM returns exactly wLength bytes of internal memory for any
   wLength 0–255 when only 2 bytes of status should be returned. The
   leaked data contains IRAM pointers, bootROM code addresses, and
   high-entropy data that may be cryptographic material.

2. **wLength uint8 truncation.** The bootROM casts wLength to uint8,
   discarding the upper byte. wLength=256 returns 0 bytes (256 mod 256),
   wLength=257 returns 1 byte (257 mod 256), etc. This is a separate
   bug from the over-read and reveals how the bootROM's EP0 handler
   processes the wLength field internally.

Both bugs are on the EP0 GET_STATUS code path, distinct from the bulk OUT
DMA overflow in CVE-2018-6242. They may not be IPATCH-patched.

## Bug 1: GET_STATUS over-read

### Behavior

Asking for EP 0x81 (bulk IN) status with increasing wLength:

| wLength | Response | Notes |
|---------|----------|-------|
| 0–2 | 0–2 bytes | Normal (status is 2 bytes: `0000` = not halted) |
| 3–255 | Exactly wLength bytes | **Over-read: returns wLength bytes of IRAM** |
| 256 | 0 bytes | uint8 wrap: 256 mod 256 = 0 |
| 257 | 1 byte | uint8 wrap: 257 mod 256 = 1 |
| 512, 1024 | 0 bytes | uint8 wrap: mod 256 = 0 |
| 2048+ | 0 bytes | No error (corrected from first probe, which tested sparsely) |

**The maximum single-read leak is 255 bytes of contiguous IRAM.**

### Affected recipients

The over-read works on multiple GET_STATUS recipients, each leaking from
a different internal control structure:

| Recipient | bmRequestType | wIndex | Over-read (128B) |
|-----------|---------------|--------|------------------|
| EP IN 0x81 | 0x82 | 0x81 | Yes — USB transfer context |
| Interface 0 | 0x81 | 0x00 | Yes — different structure (wLength at offset 4) |
| EP OUT 0x01 | 0x82 | 0x01 | Yes — different IRAM pointers than EP IN |
| Device | 0x80 | 0x00 | No — returns exactly 2 bytes |

### Bounded handlers (not vulnerable)

GET_DESCRIPTOR is properly bounded: asking for 255 bytes of an 18-byte
DEVICE descriptor returns exactly 18 bytes. The over-read is specific to
GET_STATUS, not a general EP0 issue.

## Bug 2: wLength uint8 truncation

The bootROM's GET_STATUS handler casts wLength to uint8 before using it.
Evidence:

| wLength | Low byte | Response length |
|---------|----------|-----------------|
| 256 (0x0100) | 0x00 | 0 bytes |
| 257 (0x0101) | 0x01 | 1 byte |
| 259 (0x0103) | 0x03 | 3 bytes |
| 512 (0x0200) | 0x00 | 0 bytes |

The data at wLength=257 is identical to wLength=1, confirming the wrap.

## Leaked memory contents

### 255-byte over-read (EP 0x81, fresh RCM, session 2)

```
Offset  Value        Type
------  ----------   ----
  0     0x00000000   EP status (2 bytes: not halted)
  4     0x00000000   (padding)
  8     (wLength)    Reflected wLength — proves live structure
 12     0x4000FC94   IRAM: EP0 control context
 16     0x00000001   Flag
 20     0x40009000   IRAM: DMA buffer base (stable across sessions)
 24     0x00000000   (zero)
 28     0x40009000   IRAM
 32     0x40009000   IRAM
 36     0x40002990   IRAM: handler pointer (varies between sessions)
 40     0x001079DB   bootROM: code address (STABLE across sessions)
 44     0x00000001   Flag
 48     0x4000FCE0   IRAM: EP0 control context
 52     0x40009000   IRAM
 56     0x00107B23   bootROM: code address (varies)
 60     0x40005000   IRAM
 64     0x40002E30   IRAM
 68     0x40003114   IRAM
 72     0x00102AD1   bootROM: code address (varies)
 76     0x00880088   USB register value?
 80     0x00002101   Small value
 84     0x0010291B   bootROM: code address (varies)
 88     0x40003114   IRAM
 92     0x40002E50   IRAM
 96     0x40002E30   IRAM
100     0x00000238   Value: 568
104     0x00102929   bootROM: code address
108     0x44CE1618   High-entropy (possibly crypto/PRNG)
112–252 (high-entropy 4-byte values, all with 4/4 unique bytes)
```

### Cross-session comparison (21 of 32 dwords changed)

Comparing 128-byte over-reads from two separate RCM sessions (device
power-cycled between them):

**Stable across sessions:**
- Offset 0–8: status + padding + wLength reflection
- Offset 16: flag value 1
- Offset 20, 28, 32, 52: 0x40009000 (DMA buffer base)
- Offset 40: 0x001079DB (bootROM address — STABLE)
- Offset 44: flag value 1

**Changed between sessions:**
- Offset 12, 48: IRAM control context pointers (shifted by 0x10/0x04)
- Offset 36: IRAM handler (0x40002E58 → 0x40002990)
- Offset 56, 72: bootROM addresses (different call paths)
- Offsets 60–124: Extensive changes — structure layout shifts based
  on initialization code path

**Implication:** The bootROM has no ASLR (it's mask ROM), but its
stack/heap layout differs depending on initialization state. The
over-read is reading a live stack frame whose contents depend on the
exact sequence of operations the bootROM has performed.

### State-dependent data: before/after bulk write

After claiming the interface, reading the device ID, and writing 1024
bytes of `0xDEADBEEF` pattern to bulk OUT:

- **19 of 32 dwords changed**
- The DEADBEEF pattern was NOT found in the over-read (the DMA buffer
  at 0x40009000 is not adjacent to the leaked structure)
- The changes show a **stack frame shift**: values from before-offsets
  100–124 appeared at after-offsets 60–84, offset by ~40 bytes. This
  confirms the leaked data is a stack region — the bulk OUT handler
  pushed new frames, shifting the window.
- bootROM address at offset 40 (0x001079DB) remained stable even after
  the bulk write

### High-entropy region (offsets 108–252)

The 255-byte read reveals 36+ dwords of high-entropy data starting at
offset 108. Each 4-byte value has 4/4 unique bytes. Candidates:

1. **Cryptographic key material** — the bootROM decrypts payloads using
   AES keys derived from fuses. If these keys are on the stack during
   USB handling, the over-read leaks them.
2. **PRNG state** — the bootROM may use a PRNG for nonce generation.
3. **Uninitialized heap** — residual data from prior allocations.

Determining which requires cross-session stability analysis of the
255-byte read (the current test only compared 128 bytes across sessions).

## bootROM code addresses found

All addresses in the T210 bootROM range (0x00100000–0x00107FFF):

| Address | Sessions seen | Stability | Likely role |
|---------|--------------|-----------|-------------|
| 0x001079DB | Both | **Stable** (offset 40) | Core USB handler entry |
| 0x00107AE5 | Session 1 | Offset 56 | EP0 completion callback |
| 0x00107B23 | Session 2 | Offset 56 | EP0 completion callback (alt path) |
| 0x0010254B | Session 1 | Offset 72 | Control transfer dispatch |
| 0x00102AD1 | Session 2 | Offset 72 | Control transfer dispatch (alt path) |
| 0x0010293B | Session 1 | Offset 120 | Handler return address |
| 0x0010291B | Session 2 | Offset 84 | Handler return address |
| 0x00102929 | Session 2 | Offset 104 | Handler return address |

Cross-referencing these with published T210 bootROM dumps would reveal
the exact functions and their roles in the USB stack.

## Significance for exploitation

1. **The over-read is confirmed on a potentially-patched unit.** If
   IPATCH only covers the bulk OUT DMA overflow (CVE-2018-6242), this
   EP0 over-read and uint8 truncation survive the patch.

2. **255 bytes of IRAM per read, from multiple recipients.** Each
   GET_STATUS recipient leaks from a different internal structure. This
   provides multiple windows into the bootROM's memory.

3. **Stack frame contents are leaked.** The data includes return
   addresses, function pointers, and buffer pointers — exactly the
   information needed to construct ROP chains or understand the
   bootROM's internal state machine.

4. **High-entropy data at offset 108+** could be cryptographic key
   material. If the bootROM's AES decryption keys are on the stack
   during EP0 handling, this over-read leaks them directly.

5. **The uint8 truncation** may have implications for other code paths
   that use the same wLength parsing. If the bootROM consistently
   truncates wLength to 8 bits, it affects all transfer size checks.

## Completed investigation items

- [x] Fine-grained wLength sweep: boundary is 255, not 128; uint8 wrap at 256
- [x] Cross-session comparison: 21/32 dwords differ; stack layout varies
- [x] State after bulk write: 19/32 dwords change; stack frame shift observed
- [x] Multiple recipients: EP IN, Interface, EP OUT all over-read; Device does not
- [x] Descriptor handler: properly bounded (not vulnerable)

## Next steps

- [ ] Cross-session comparison of full 255-byte read (not just 128)
- [ ] Identify the high-entropy data at offset 108+: crypto keys vs PRNG vs heap
- [ ] Cross-reference bootROM addresses with published T210 bootROM dumps
- [ ] Test GET_STATUS on other wIndex values (non-existent endpoints)
- [ ] Investigate whether the uint8 truncation affects the bulk OUT path
- [ ] Map the DMA buffer at 0x40009000 — can we read it via different wIndex?
