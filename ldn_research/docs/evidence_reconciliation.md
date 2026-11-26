# Evidence Reconciliation Audit

**Date:** 2026-11-25
**Purpose:** Separate established findings from inferences. Correct overclaimed evidence.
**Scope:** All exploitation-relevant claims across both attack paths.

---

## 1. Multipart Filename Overflow (photoViewer)

### ESTABLISHED: Crash with precise boundary

| Claim | Evidence | Confidence |
|-------|----------|------------|
| Filename >= 3985 bytes crashes photoViewer | `exploit_dev/exact_boundary_1795582218.json`: 3984 safe, 3985 crash | **Reproduced** |
| Persistent DoS (requires manual restart) | 3x reproduction across sessions | **Reproduced** |
| HTTP server becomes unavailable after crash | 0 bytes response, follow-up GET fails | **Reproduced** |
| Full byte range accepted below boundary | `exploit_dev/byte_control_1795585231.json`: 0x00-0xFF all return 404 at safe sizes | **Reproduced** |
| 0 bytes leaked at crash boundary | `exploit_dev/multipart_leak_*.json`: resp_len=0 at boundary, 2x tested | **Reproduced** |

### OVERCLAIMED: LR control

**Previous claim:** "LR control CONFIRMED — 2-byte partial overwrite tested."

**Actual evidence:** The crash boundary (3985 bytes) is consistent with a stack buffer overflow reaching saved registers, based on the ARM64 stack layout of `char buf[0x1000]` (4096 bytes) minus the multipart parsing overhead. However:

- **No differential crash test exists.** We have not demonstrated that writing different byte patterns at the LR position produces different crash behavior.
- **No register state observation.** We have no mechanism to read the exception registers after the crash.
- **The crash itself is the only observable.** The server returns 0 bytes and becomes unavailable. This is consistent with a stack smash, but also with any fatal error during parsing.

**Corrected status:** The multipart overflow is a **confirmed crash with characteristics consistent with stack buffer overflow.** LR control is **inferred from static analysis of the binary** (no stack canaries found, `char buf[0x1000]` at known stack offset), not demonstrated empirically.

### OVERCLAIMED: No stack canaries

**Previous claim:** "No `__stack_chk_guard` string in entire binary."

**Qualification:** Searching the binary for the string `__stack_chk_guard` and the GOT relocation confirms that the **toolchain did not link the standard canary mechanism** into this binary. This is strong evidence but does not rule out:
- A custom canary implementation not using the standard symbol
- A per-function mitigation using a different mechanism
- Hardware-assisted stack protection (not applicable on Erista, but should be stated)

**Corrected status:** Standard stack canaries (`__stack_chk_guard` / `__stack_chk_fail`) are **absent from the photoViewer binary**. No custom canary mechanism has been identified, but exhaustive absence has not been proven.

### OVERCLAIMED: No PAC

**Previous claim:** "PACIASP opcode absent from all bytes."

**Qualification:** The ldn binary was scanned for the PACIASP encoding (`0x7F2303D5`). This confirms PAC is not used **in that binary on that firmware version.** The photoViewer binary should be independently checked.

**Corrected status for ldn:** PAC instructions absent from the ldn sysmodule binary (FW 22.5.0). **photoViewer PAC status: not independently verified** (inferred from same SDK version).

---

## 2. CVE-2026-82079 / DHCP Overflow (ldn sysmodule)

### ESTABLISHED: Static analysis of vulnerable function

| Claim | Evidence | Confidence |
|-------|----------|------------|
| FUN_71000a13d0 has dead size parameter (x3) | Assembly analysis: x3 never referenced | **Static, verified** |
| memcpy destination is 1500-byte stack buffer | Prologue `sub sp, sp, #0x6c0`, buffer at `sp+0x3c` | **Static, verified** |
| Buffer-to-LR distance = 1676 bytes | Assembly-verified frame geometry | **Static, verified** |
| Call chain from BPF read to memcpy | 7-step call chain traced through binary | **Static, verified** |
| Stack pivot gadget at 0x09D04C | Instruction decode verified | **Static, verified** |
| 2-byte partial LR overwrite is ASLR-independent | Mathematical: both offsets share bits 16+ | **Mathematical proof** |

### ESTABLISHED: Live DHCP crash

| Claim | Evidence | Confidence |
|-------|----------|------------|
| DHCP vendor-class >= 222 bytes crashes something | 5x reproduced, boundary at 221/222 | **Reproduced** |
| Crash is NM-specific (raw UDP doesn't crash) | `EXPLOITATION_STATUS.json`: raw injection no-crash | **Reproduced** |

### NOT DEMONSTRATED: LR redirect on live device

**Previous claim:** "2-byte partial overwrite tested, differential crash expected."

**Actual evidence from `lr_redirect_*.json` and `lr_diagnostic_*.json`:**

- **Both LR redirect tests say "REFUTED"**: HTTP stayed alive for BOTH the control (original LR bytes) AND the redirect (pivot LR bytes)
- All "expected: crash" tests came back "match: false"
- The overflow data may not be reaching saved LR at all, OR the HTTP liveness oracle is not detecting ldn thread crashes

**Corrected status:** The partial LR overwrite has been **statically modeled** but **empirically REFUTED** on the live device. The DHCP overflow may not reach the stack frame we analyzed, or the frame layout differs from the static model.

### NOT ESTABLISHED: CVE correspondence

**CVE-2026-82079 public record:** "Stack-based buffer overflow in local wireless networking, affecting firmware before 23.0.0."

**Our evidence:** We found a dead size parameter in a DHCP-related memcpy within the ldn sysmodule. The DHCP vendor-class crash boundary at 222 bytes is consistent with reaching this overflow. However:

- The crash via NM but not via raw UDP is **unexplained** — if the overflow is in `NetworkLayersCopy`, raw UDP frames should trigger it too
- The CVE may describe a different vulnerable function in the same module
- The H1 report (H1:3770768) is restricted; we cannot verify correspondence

**Corrected status:** Our static finding of the dead size parameter in `NetworkLayersCopy` is a **plausible candidate** for CVE-2026-82079. The correspondence is **not confirmed**. The NM-only crash behavior is an unresolved contradiction.

---

## 3. Information Disclosure

### AdvertiseData leak

**Previous claim:** "yellows8-credited uninitialized stack data leak in LP2P scan responses, likely present on 22.5.0."

**Actual evidence:** Referenced from Switchbrew documentation of the `GetAdvertiseData` / `GetAdvertiseData2` IPC interface. The documentation describes a data structure containing an AdvertiseData field. **It does not explicitly document an uninitialized memory disclosure.**

**Corrected status:** **Unverified hypothesis.** No empirical test has been run. The Switchbrew documentation describes the interface structure, not a confirmed info leak.

### HTTP response leaks

**Evidence from `multipart_leak_*.json`:** At the crash boundary, the server returns exactly 0 bytes. No leaked data observed. Tested twice.

**Corrected status:** **No information disclosure demonstrated** through the HTTP attack surface.

---

## 4. Network Identifier Exposure in Repository

The following hardware/network identifiers appear in tracked files:

| Identifier | Type | Files | Risk |
|------------|------|-------|------|
| `EC:C4:0D:F3:DC:DB` | Switch BSSID | 23 files (scripts, evidence, docs) | Identifies specific hardware unit |
| `switch_F3DCDB0100S` | Switch SSID | 24 files | Derived from BSSID |
| `22:7c:ce:e0:bd:56` | Researcher's WiFi MAC | 12 files (evidence, scripts) | Identifies researcher's PC NIC |
| `192.168.0.1` | Switch local IP | Many files | Standard AP address, low risk |
| `192.168.44.35` | Switch IP (MITM test) | 2 files (MITM evidence) | Test network, low risk |
| `XAW4 001878` | Console serial | README, reports | Already public in repo description |

**Assessment:** The Switch BSSID and SSID are derivable from the serial number (already public). The researcher's WiFi MAC (`22:7c:ce:e0:bd:56`) in 12 files could identify the PC's wireless adapter. This is low-risk but noted.

---

## 5. Corrected Findings Matrix

| # | Finding | Type | Evidence | Status |
|---|---------|------|----------|--------|
| 1 | Multipart crash at filename >= 3985 | DoS | Live, 3x reproduced | **CONFIRMED** |
| 2 | Multipart persistent DoS | DoS | Live, 3x reproduced | **CONFIRMED** |
| 3 | Multipart stack overflow (memory corruption) | Vuln | Inferred from crash boundary + static layout | **PROBABLE** |
| 4 | Multipart LR control | Exploit primitive | Inferred from static analysis only | **UNDEMONSTRATED** |
| 5 | DHCP crash at vendor >= 222 | DoS | Live, 5x reproduced | **CONFIRMED** |
| 6 | DHCP crash is NM-specific | Behavioral | Live, raw injection no-crash | **CONFIRMED** |
| 7 | ldn NetworkLayersCopy dead size param | Vuln | Static binary analysis | **CONFIRMED (static)** |
| 8 | ldn buffer-to-LR = 1676 bytes | Layout | Static binary analysis | **CONFIRMED (static)** |
| 9 | ldn partial LR overwrite (ASLR-bypass) | Model | Mathematical proof | **CONFIRMED (theoretical)** |
| 10 | ldn stack pivot gadget | Gadget | Static binary analysis | **CONFIRMED (static)** |
| 11 | ldn LR redirect on live device | Exploit primitive | lr_redirect tests REFUTED | **REFUTED** |
| 12 | HTTP Range DoS | DoS | Live, reproducible | **CONFIRMED** |
| 13 | No stack canaries (ldn) | Mitigation absence | Binary string/byte scan | **STRONG EVIDENCE** |
| 14 | No PAC (ldn) | Mitigation absence | Binary opcode scan | **STRONG EVIDENCE** |
| 15 | No stack canaries (photoViewer) | Mitigation absence | Inferred from same SDK | **INFERRED** |
| 16 | CVE-2026-82079 correspondence | Attribution | Plausible match, not confirmed | **UNCONFIRMED** |
| 17 | AdvertiseData info leak | ASLR bypass | Switchbrew reference only | **UNVERIFIED** |
| 18 | ASLR ~18-bit entropy | Constraint | Switchbrew documentation | **DOCUMENTED ESTIMATE** |

---

## 6. Open Contradictions

1. **NM-only DHCP crash:** If the overflow is in `NetworkLayersCopy` (frame reassembly), raw DHCP packets should trigger it. They don't. Either the vulnerable function is not `NetworkLayersCopy`, or the NM connection flow triggers a different code path.

2. **LR redirect REFUTED:** The lr_diagnostic tests show no crash differential between control LR and redirect LR. Either the overflow does not reach the saved LR position on the live device, or the HTTP oracle cannot detect ldn thread crashes.

3. **Multipart crash vs corruption:** We observe a crash but cannot distinguish a stack-smash crash from an assertion, an exception, or a parser error. Without register state or a core dump, the crash mechanism is inferred.

---

## 7. Recommended Next Steps

1. **Resolve the NM-only crash contradiction** — instrument the DHCP attack to capture exactly what NM sends vs what raw injection sends, byte-for-byte
2. **Design a differential crash test for multipart** — vary specific bytes at the inferred LR offset and observe whether crash behavior changes (crash vs no-crash, or different error codes)
3. **Empirically test AdvertiseData** — scan for LP2P advertisements and check if the AdvertiseData field contains non-zero data suggestive of stack contents
4. **Independently verify photoViewer canary/PAC status** — scan the photoViewer binary directly, not by inference from ldn
