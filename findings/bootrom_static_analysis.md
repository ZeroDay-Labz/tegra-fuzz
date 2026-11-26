# T210 BootROM Static Analysis — IPATCH & Vulnerability Map

## Device: Nintendo Switch XAW4 001878 (Tegra X1 Erista, Early Patch v1)
## Date: 2026-11-20
## Binary: Tegra_X1_BootROM_Nintendo_T210.bin (96 KB, SHA256: 1c629af8...)
## Source: GitHub (q3k dump + IDC annotations)

---

## IPATCH Target Map (All Three CVE-2018-6242 Patches)

### Patch 1 — Message Length Cap
- **Location**: Near 0x1024D6 (in `rcm_receive_message_check_len_insecure`)
- **Original**: `ldr r1, [0x102810]` loads max = **0x302A8** (197,288 bytes)
- **Effect**: Changes max accepted message length to **0x30298** (197,272 bytes)
- **Why needed**: Original max allows payload to fill IRAM to the last byte.
  Payload dest = 0x40010000, IRAM end = 0x40040000, max payload = 0x30000.
  With header 0x2A8: total = 0x302A8. Exact fit = no room for error.

### Patch 2 — DMA Transfer Size Cap
- **Location**: 0x10247A (in `rcm_receive_message_check_len_insecure`)
- **Original**: `lsls r1, r1, #14` → r1 = 1 << 14 = **0x4000** (16 KB)
- **Patched**: `lsls r1, r1, #12` → r1 = 1 << 12 = **0x1000** (4 KB)
- **Why needed**: DMA buffer A at 0x40005000 (4 KB). With 16 KB DMA, writes
  through 0x40006000-0x40008FFF, overwriting the **stack at 0x40008000**.
  This IS the CVE-2018-6242 exploit vector (fusee-gelee).

### Patch 3 — EP0 wLength Masking
- **Location**: 0x10769A (in `usbd::handle_ep0_control_transfer`)
- **Original**: `lsls r1, r1, #8` → wLength = lo | (hi << 8) = full 16-bit
- **Patched**: `movs r1, #0` → wLength = lo | 0 = **uint8 only** (max 255)
- **Why needed**: GET_STATUS response copies wLength bytes from stack to
  response buffer. Full 16-bit wLength → stack contents leak / buffer overflow.

---

## Decompiled Function Map

### USB Layer (0x107xxx)
| Address | Name (from IDC) | Purpose |
|---------|-----------------|---------|
| 0x10767C | `usbd::handle_ep0_control_transfer` | EP0 request dispatcher |
| 0x107860 | (USB interrupt loop) | Polls DWC2 interrupt status |
| 0x107926 | `usb_device_write_ep1_in_sync` | Sync write to EP1 IN |
| 0x107978 | `usb_device_read_ep1_out_sync` | Sync read from EP1 OUT |
| 0x1079A8 | `usbd::handle_ep0_pending_control_transfer` | Pending EP0 handler |
| 0x1079DA | (not in Ghidra function) | Leaked at EP0 offset 40 |
| 0x107A64 | `usb_device_read_ep1_out` | Async read from EP1 OUT |
| 0x107ABA | `usb_device_reset_ep1` | Reset EP1 endpoints |
| 0x107B4C | (SET_ADDRESS/SET_CONFIG) | USB enumeration completion |
| 0x107CC0 | (unknown) | Called from warm boot path |

### RCM Protocol (0x102xxx)
| Address | Name (from IDC) | Purpose |
|---------|-----------------|---------|
| 0x1023FC | `rcm_prot_send_errorcode` | Send error code via EP1 IN |
| 0x102436 | `rcm_receive_message_check_len_insecure` | Receive + length check |
| 0x102604 | `rcm_msg_validate` | CMAC/hash/signature verify |
| 0x1026F0 | `rcm_prot_handle_message` | Process RCM command |
| 0x10278A | `load_rcm_aes_key` | Load AES key from fuses |
| 0x102896 | `try_load_from_rcm` | Main RCM orchestrator |
| 0x102A80 | `rcm_send_initial_hwinfo_after_connection` | Send hw info to host |
| 0x102AD6 | `rcm_error_and_reset_ep1` | Error handler + EP reset |

### Boot Flow (0x101xxx)
| Address | Name (from IDC) | Purpose |
|---------|-----------------|---------|
| 0x10142A | `main` | Boot flow entry |
| 0x101134 | `normal_boot` | Normal cold boot |
| 0x101E1C | `try_load_from_storage` | Boot from eMMC/SD |
| 0x101F6C | `configure_sdram` | Cold boot SDRAM setup |
| 0x1045A2 | `try_load_warmboot` | Warm boot (SC7 wake) |
| 0x100590 | `apply_bootrom_patches_thumb` | IPATCH application |
| 0x1007B0 | `software_interrupt_handler` | SVC handler (IPATCH) |

---

## Key Constants from Binary

| Address | Value | Meaning |
|---------|-------|---------|
| 0x102804 | 0x40002E30 | RCM state struct base |
| 0x102808 | 0x40002990 | DMA double-buffer pointer array |
| 0x10280C | 0x40010000 | Payload copy destination |
| 0x102810 | 0x000302A8 | **Original max message length** |
| 0x40004C24 | (IRAM) | g_warmboot_start |
| 0x40004C28 | (IRAM) | g_warmboot_entry |
| 0x40004C2C | (IRAM) | g_warmboot_size |
| 0x40004C30 | (IRAM) | IPATCH SVC handler code |

---

## RCM Protocol Flow (from decompiled code)

```
main() → try_load_from_rcm()
  │
  ├── rcm_send_initial_hwinfo_after_connection()  ← HOST READS THIS
  │
  ├── rcm_receive_message_check_len_insecure()
  │     ├── Length check: msg_len < max (IPATCH'd)
  │     ├── DMA receive: 0x1000 per transfer (IPATCH'd)
  │     └── Double-buffer ping-pong copy to destination
  │
  ├── [PKC mode] RSA signature verification
  │     ├── Hash public key from message → compare with fuse hash
  │     └── RSA verify message signature
  │
  ├── rcm_msg_validate()
  │     ├── Length field consistency check
  │     ├── Payload length check
  │     └── CMAC/hash verification
  │
  ├── rcm_prot_handle_message()
  │     ├── Process RCM command (SYNC/DL_CODE/QUERY)
  │     └── Send response error code
  │
  └── [If not done] Loop for next message
```

---

## RCM Error Codes (from IDC)

| Code | Name | Meaning |
|------|------|---------|
| 0x04 | INVALID_LOWSEC_KEY | CMAC key mismatch |
| 0x08 | INVALID_LEN_INSECURE | Message length rejected |
| 0x0A | LEN_MISMATCH | Header length != actual |
| 0x0B | PAYLOAD_LEN_MISMATCH | Payload length field wrong |
| 0x0F | LEFTOVER_DATA | Extra bytes in last USB chunk |
| 0x13 | NO_PUBKEY_LOADED | PKC mode but no key |
| 0x15 | INVALID_KEYINDEX | Bad key index |
| 0x16 | INVALID_SIGNATURE | RSA/CMAC verify failed |

---

## Switchbrew Erista-Only Bugs — Reachability Assessment

### 1. SDRAM Config Arbitrary Writes
- **Mechanism**: EMC spare parameters used as bootROM write addresses
- **Path**: `try_load_warmboot()` → PLL/EMC config from PMC scratch registers
- **Reachable from USB?** NO — requires PMC scratch register control
- **Requires**: Prior code execution to set PMC registers before deep sleep

### 2. SE Context Validation (Last Block Only)
- **Mechanism**: Only final block of SE context MAC'd during SC7 save
- **Path**: Warm boot SE context restore
- **Reachable from USB?** NO — requires modifying IRAM/PMC during deep sleep
- **Requires**: Prior code execution or hardware access during sleep

### 3. strapwn (Boot Straps Not Relatched)
- **Mechanism**: Watchdog reset doesn't relatch boot device straps
- **Path**: `main()` → watchdog timeout → reset → boot from new strap values
- **Reachable from USB?** PARTIALLY — could trigger watchdog, but strap
  change requires hardware pin manipulation
- **Requires**: Hardware strap modification (physical access)

---

## NEW FINDINGS: Crypto Implementation Bugs

### BUG 1: Timing-Variable Public Key Hash Comparison (FUN_001043a2)
- **Location**: 0x1043A2, called from try_load_from_rcm at ~0x1029xx
- **Bug**: Standard memcmp with **early exit on first mismatching byte**
- **Impact**: SHA-256(our_pubkey) vs fuse_pubkey_hash is timing-variable
- **TESTED**: Timing baseline = ~86 µs mean, ~10 µs stdev over USB
- **Signal**: ~100-260 ns per matching byte (BPMP ARM7TDMI @ 38-102 MHz)
- **VERDICT: NOT EXPLOITABLE via USB** — 1 measurement per RCM entry (30s cycle),
  device does NOT auto re-enter RCM, need millions of measurements
- **Still useful**: Could verify known candidate keys if found elsewhere

```c
// FUN_001043a2 — NOT constant-time!
while (true) {
    if (param_3 <= uVar3) return 1;  // All matched
    if (*param_1 != *param_2) break;  // EARLY EXIT
    param_1++; param_2++; uVar3++;
}
return 0;
```

### BUG 2: Timing-Variable RSA-PSS Hash Comparison (FUN_00103698)
- **Location**: Inside RSA-PSS verify at 0x103698, final comparison loop at 0x103898
- **Bug**: Final 20-byte hash comparison also uses early-exit loop
- **Impact**: After SE modular exponentiation + MGF1, hash compared with early exit
- **Note**: Only reachable if pubkey hash check passes first
- **ASSEMBLY CONFIRMED**: `cmp r2, r6; beq continue; movs r0, #0x26` (early exit)

### Finding: RSA Skip on Invalid Pubkey (Design Flaw, Mitigated)
- In try_load_from_rcm: if pubkey hash doesn't match, RSA check is SKIPPED
- Execution falls through without error from the RSA block
- **BUT**: msg_validate independently checks pcVar1[-0xc] (pubkey_loaded flag)
- Returns error 0x13 (NO_PUBKEY_LOADED) → redundant check blocks exploit
- **pubkey_loaded at 0x40002E44** — explicitly cleared at function entry (`= '\0'`)
- Flag persists across loop iterations (goto LAB_001028fe), but RSA failure exits loop

### Finding: PKCS Padding Check is Format-Only (FUN_00104386)
- msg_validate checks 5 & 6 verify `0x80 0x00 0x00...` patterns
- This is message formatting, NOT cryptographic verification
- We CAN satisfy these checks by putting 0x80 at the right offset

### Finding: Security Mode (FUN_00102030)
- Fuse-cascade decision tree: mode 1-6 based on burned fuses
- Mode 6 = PKC (RSA) — retail Switch units are ALWAYS mode 6
- Mode 4/5 = ODM open/secure with CMAC — only dev/test units
- Cannot be changed without fuse manipulation

---

## DEEP DIVE: RSA-PSS Implementation Audit (FUN_00103698)

**Date**: 2026-11-19
**Result**: Implementation is CRYPTOGRAPHICALLY CORRECT. No exploitable bugs found.

### RSA-PSS Parameters (confirmed from assembly)
| Parameter | Value | Source |
|-----------|-------|--------|
| Key size | RSA-2048 (256 bytes) | param_2 = 0x800 bits |
| Public exponent | e = 65537 (0x10001) | DAT_00102b64 (hardcoded) |
| Hash algorithm | SHA-1 (20 bytes) | r4 = 0x14 (hardcoded) |
| emLen | 256 bytes | Set by SE dispatch thunk |
| hLen | 20 bytes | SHA-1 output size |
| sLen | 20 bytes | Same as hLen (standard) |
| dbLen | 235 bytes | emLen - hLen - 1 |
| MGF1 iterations | 12 | ceil(235/20) = 12 |

### Verification Steps (from assembly at 0x103698-0x1038B7)
1. **SE modular exponentiation** (via thunk at 0x1149a8 → ARM mode handler)
   - BX PC switches Thumb→ARM for SE dispatch
   - Inline parameters after BL encode operation details
   - Ghidra misidentified inline data as Thumb instructions
2. **Byte reversal** (0x1036EC-0x103706): Correct 256-byte endian swap, `& 0xFF` masking works
3. **0xBC trailer check** (0x103748): `ldrb r1, [buffer+255]; cmp r1, #0xbc` ✓
4. **High-bits masking** (0x10376E-0x103776): Correctly clears leftmost bits ✓
5. **MGF1 mask generation** (0x103792-0x1037DC):
   - 12 iterations of Hash(H || counter_be32)
   - SHA-1 blocks (20 bytes each), 240 bytes generated
   - FUN_00104372 = bswap32 for counter encoding ✓
6. **XOR unmask** (0x1037F2-0x1037FE): `eors r1, r3` for 235 bytes ✓
7. **DB padding check** (0x10381E-0x10383A): PS(zeros) || 0x01 || salt ✓
8. **M' construction** (0x10383C-0x103864):
   - memset(M', 0, 8): 8 zero bytes ✓
   - memcpy(M'+8, mHash, 20): message hash ✓
   - memcpy(M'+28, salt, 20): salt from DB ✓
   - Total = 48 bytes ✓
9. **H' computation** (0x103868-0x10388C): SHA-1(M') = 20 bytes ✓
10. **H vs H' comparison** (0x103898-0x1038B4): 20-byte EARLY-EXIT loop ← TIMING BUG

### Thunk Discovery (0x1149A8)
- `thunk_FUN_001149ac` starts with `BX PC` → Thumb-to-ARM mode switch
- The ARM code at 0x1149AC reads inline parameters from after the BL call site
- This is a classic ARM "embedded parameter" calling convention
- Ghidra decoded the inline data as Thumb instructions → garbled decompilation
- The `extraout_r1 * 0x10000000` in decompilation is an artifact of this confusion

### Fuse Hash Source (confirmed)
- FUN_00102112 reads from MMIO **0x7000F964** (FUSE_PUBLIC_KEY_0)
- Through **0x7000F980** (FUSE_PUBLIC_KEY_7)
- 8 × 32-bit words = 256-bit SHA-256 hash
- FUN_00102248 converts MMIO words to byte array (LE byte order)

### Key Constants in try_load_from_rcm (FUN_00102896)
| DAT Address | Value | Meaning |
|-------------|-------|---------|
| 0x102b48 | 0x40000000 | BCT base in IRAM |
| 0x102b4c | 0x40002E50 | State struct field ptr |
| 0x102b50 | 0x40003100 | SE linked-list area |
| 0x102b54 | 0x40010000 | Payload destination |
| 0x102b5c | 0x40002990 | DMA buffer ptr array |
| 0x102b60 | 0x40002D30 | Security mode struct |
| 0x102b64 | 0x00010001 | RSA exponent = 65537 |
| 0x102b68 | 0x40002F90 | Crypto context |

### Authentication Chain Summary
```
Message received via USB
  │
  ├── SHA-256(modulus) == FUSE_PUBLIC_KEY[0:7]?
  │     Source: MMIO 0x7000F964-0x7000F980
  │     Compare: FUN_001043a2 (timing-variable, 32 bytes)
  │     If NO: pubkey_loaded stays 0 → error 0x13
  │
  ├── [If hash matches] Load modulus+exponent into SE
  │     SE key slot 0, RSA-2048, e=65537
  │
  ├── [If pubkey_loaded] RSA-PSS-SHA1 verify
  │     S^65537 mod N → EM (256 bytes)
  │     PSS decode: 0xBC trailer, MGF1-SHA1, DB check
  │     H' = SHA1(0x0000000000000000 || mHash || salt)
  │     Compare H vs H' (timing-variable, 20 bytes)
  │     If NO: error 0x16 (INVALID_SIGNATURE), return
  │
  └── msg_validate (FUN_00102604)
        Checks pubkey_loaded flag independently
        Format checks (lengths, padding, etc.)
```

---

## RCM T210 Message Layout (Confirmed from NVIDIA rcm.h + decompilation)

Based on rcm40_msg_t + 36 extra bytes for T210:
```
Offset  Size  Field
0x000   4     len_insecure          (= 0x30298)
0x004   256   modulus               RSA-2048 public key
0x104   16    cmac_hash             AES-CMAC (non-PKC mode)
0x114   256   rsa_pss_sig           RSA-PSS signature
0x214   36    extra                 T210-specific extension
0x238   16    reserved
0x248   16    ecid                  Console unique chip ID
0x258   4     opcode                RCM command (1=SYNC, 4=DL, 5=QUERY)
0x25C   4     len_secure            Must match len_insecure
0x260   4     payload_len           msg_len - 0x2A8
0x264   4     rcm_version           0x00400001
0x268   48    args                  Command arguments
0x298   16    padding               Byte [8]=0x80 (PKCS marker)
0x2A8   ---   PAYLOAD START
```

RCM Commands (from rcm.h):
- RCM_CMD_SYNC = 0x1 (synchronization)
- RCM_CMD_DL_MINILOADER = 0x4 (download code)
- RCM_CMD_QUERY_BR_VERSION = 0x5
- RCM_CMD_QUERY_RCM_VERSION = 0x6

Operation Modes:
- 0x1 = PRE_PRODUCTION, 0x3 = DEVEL, 0x4 = ODM_SECURE
- 0x5 = ODM_OPEN, **0x6 = ODM_SECURE_PKC** (retail Switch)

---

## Remaining Attack Surface

### Immediately Actionable:
1. **Send properly formatted RCM message** (rcm_msg_send.py)
   - Use correct T210 layout with len_secure, PKCS padding
   - Expected: error 0x13 (NO_PUBKEY_LOADED) — confirms message accepted
   - Any other error = diagnostic for format issues
2. **Find the BCT RSA public key modulus**
   - BCT+0x210 in BOOT0 partition on NAND
   - briccmii (by rajkosto) reads/modifies this key
   - SHA-256(modulus) must match FUSE_PUBLIC_KEY0-7 (0x7000F964-0x7000F980)
   - Key is likely same across all Erista units
3. **Timing attack on memcmp** (once message format confirmed)
   - Extract fuse hash byte-by-byte via USB timing
   - ~3-5 ns per matching byte, need statistical averaging
   - Each test requires USB re-enumeration (~1-2 sec)
4. **RSA-PSS implementation analysis** (once pubkey known)
   - Look for bugs in modular exponentiation
   - Check if the 20-byte hash comparison truncates SHA-256

### Requires further RE:
5. **TSEC Falcon coprocessor** — 3 UNFIXED HW bugs confirmed (see below)
6. **Package1 / warmboot binary analysis**
7. **Boot chain downgrade**

---

## Storage Boot Path Audit (2026-11-21)

**RESULT: DEAD END #10 — Identical crypto to RCM**

FUN_00104ab8 (BCT block verifier) in the storage boot path uses the EXACT same
crypto chain as RCM:
- FUN_00103360 — SHA-256 of modulus at BCT+0x210 (0x100 bytes)
- FUN_00102112 — Read fuse hash from MMIO 0x7000F964
- FUN_001043a2 — Timing-variable 32-byte compare (same non-constant-time)
- FUN_0010359a — Load RSA key into Security Engine
- FUN_00103698 — RSA-PSS-SHA1 verify (same 530-byte function)
- DAT_00104c24 = 0x00010001 (e=65537, same exponent)

BCT structure (from Switchbrew + briccmii source):
- Block size: 0x4000 (can iterate up to 64 entries)
- Modulus: offset 0x210, 256 bytes
- Signature: offset 0x310
- Signed data: after offset 0x510
- Mode 6 (PKC/retail) = same RSA-PSS path
- Mode 3 (DEVEL) uses FUN_00104800 but requires DEVEL fuses

No weaker alternative path exists. The bootROM applies identical RSA-PSS
verification everywhere for retail units.

---

## TSEC Vulnerability Research (2026-11-21)

### Three UNFIXED Hardware Bugs (All Tegra210)

Source: Switchbrew System Flaws table + hexkyz/SciresM "Je Ne Sais Quoi"
(https://hexkyz.blogspot.com/2021/11/je-ne-sais-quoi-falcons-over-horizon.html)

**1. Crypto Register Leakage (Switchbrew Row 6)**
- Fix: NONE — hardware bug in Secure Boot ROM
- $c6/$c7 intermediates readable after signature verification
- Allows signature algorithm reconstruction from HS mode
- Discovered late 2018/early 2019, disclosed Aug 2020

**2. Fake-Signing / cauth Break (Switchbrew Row 7)**
- Fix: NONE — hardware design flaw in code authentication
- cauth uses AES-based MAC without proper seed validation
- $c3 = aes_enc(secret1, $c7); choosing known $c7 reveals $c3
- Result: sign arbitrary Heavy Secure microcode
- Impact: run own code in Falcon secure mode → derive per-console keys

**3. DMA Stack Overwrite ROP (Switchbrew Row 8)**
- Fix: NONE — Secure Boot ROM is execute-only, unfixable
- Affects ALL Tegra devices (not just Tegra210)
- ROM doesn't execute xdwait on entry → async DMA lands in stack
- IBRKPT (SKIP bit) maps ROM instruction boundaries
- TRACEPC leaks branch addresses from HS mode
- Final: overwrite cauth trailer block → pass csigcmp $c4,$c6
- Result: recover TSEC signing key via aes_enc(csecret1, $c7)

**4. SE Keyslot Partial Overwrite (Switchbrew Row 3)**
- Fix: NONE
- Reduces brute-force from 2^256 to ~2^35
- Requires code execution with SE MMIO access

### TSEC Exploitation Chain (from hexkyz blog)

1. nvhax (nvservices system module compromise) → TSEC MMIO + microcode upload
2. HOVI maconstack or call-vs-branch ROP → HS code execution
   - Pre-6.2.0: KeygenLdr stack overflow (attacker-controlled size field)
   - Pre-6.2.0: call-vs-branch (Falcon call pushes return addr, branch doesn't)
3. iowr gadget → arbitrary MMIO writes via TSEC_SCP_CMD
4. Extract secret 0x00 (crypto register leak: non-secure → HS spill)
5. Break cauth with known $c7 → sign arbitrary HS code
6. DMA stack overwrite → pass csigcmp in Secure Boot ROM
7. Compute TSEC signing key: aes_enc(csecret1, $c7)

### CRITICAL FINDING: All TSEC exploits require prior code execution

The initial entry point was nvhax, which itself started from a browser exploit.
The TSEC MMIO registers are accessible only to kernel-level code (via nvservices).
There is NO way to reach TSEC from the bootROM context alone.

---

## Attack Chain Assessment (2026-11-21)

### The Complete Picture for Patched Erista

Every remaining exploit requires INITIAL CODE EXECUTION. The bootROM/RCM USB
path is 100% exhausted (10 dead ends).

### FIRMWARE CONFIRMED: 22.5.0 (checked 2026-11-21)
- PegaScape (≤ 4.1.0): DEAD
- Deja Vu (≤ 7.0.1): DEAD
- CVE-2026-82079 (< 23.0.0): **LIVE — PRIMARY VECTOR**

**Stage 1: Initial Code Execution**
- PRIMARY: CVE-2026-82079 — CWE-121 stack overflow in `ldn` sysmodule lp2p DHCP server
  - Discovered by moehw (H1:3770768), reported 2026-05-30, published 2026-09-10
  - CVSS 4.0: 7.0 HIGH, CVSS 3.1: 8.4 HIGH, no public PoC
  - Bug: DHCP server copies frame data to stack without size validation
  - Attack: Send to Smartphone → WiFi AP → lp2p DHCP → oversized options → stack overflow
  - Switch AP: SSID switch_F3DCDB0100S, BSSID EC:C4:0D:F3:DC:DB, WPA2-PSK
  - 11 attack tools built (see ldn_research/analysis/)
  - Primary tool: lp2p_dhcp_overflow.py (5-second lease = rapid testing)
  - Bonus: ldn SendActionFrame heap overflow ALSO unfixed on 22.5.0 (fixed 23.5.0)
  - 23.0.0 added srepo:u service to ldn; 23.5.0 added 7 more ldn function fixes
- BACKUP: CivSwitch/Gezine (Nov 2026, XSS via Civ VII, userland only)

**Stage 2: Privilege Escalation**
- Kernel exploit (many historical, version-dependent)
- nvservices compromise → TSEC MMIO access

**Stage 3: TSEC Exploitation (ALL UNFIXED)**
- ANY FW: DMA stack overwrite → recover TSEC signing key

**Stage 4: Persistent Boot Control**
- TSEC signing key → derive per-console keys
- Sign custom TSEC firmware → control secure boot → custom ROM

---

## RCM Message Structure (from decompiled code)

```
Offset   Size   Field
0x000    4      msg_length (must be < max, >= 0x400, & 0xF == 8)
0x004    varies (header continues...)
0x128    256    RSA-2048 signature (in PKC mode)
0x228    varies Padding
0x260    4      payload_len
0x264    4      rcm_version
0x2A8    ---    END OF HEADER (680 bytes)
0x2A8+   varies Payload data (copied to 0x40010000)
```

Total message = header (0x2A8) + payload. Max = 0x30298.
Payload max = 0x30298 - 0x2A8 = 0x2FFF0 = 196,592 bytes.
