# Nintendo Switch Tegra X1 Security Research

**Hardware:** HAC-001 (serial XAW4 001878)  
**SoC:** Tegra X1 Erista (T210)  
**Firmware:** 22.5.0 (intentionally not updated)  
**Goal:** Persistent custom ROM — code execution → boot control → custom OS

Last updated: 2026-11-25

---

## Chain Status

The end goal requires four transitions, none of which have been demonstrated:

| Transition | Status |
|-----------|--------|
| 1. Initial code execution | Not demonstrated — multipart overflow has LR control, ASLR is the blocker |
| 2. Privilege escalation | Not reached — no demonstrated path from applet to kernel |
| 3. TSEC / secure-boot control | Documented theory from prior research, not demonstrated on this console |
| 4. Persistent boot control | Not reached — no signing-key recovery or modified boot path |

---

## Research Lanes

### 1. Multipart Filename Overflow — photoViewer (ACTIVE, CLOSEST TO EXPLOITATION)

**Status:** LR control confirmed. Vulnerable function identification in progress.

**Summary:** The photoViewer applet's "Send to Smartphone" HTTP server has a stack
buffer overflow in multipart filename parsing. Single unauthenticated HTTP POST
triggers persistent crash. 2-byte partial LR overwrite confirmed (ASLR-independent
redirect within 64KB window). No stack canaries.

**What is confirmed:**
- Stack overflow at filename ~4052 total bytes (boundary + CD prefix + filename)
- Saved FP at byte 3973, LR at byte 3981 (boundary="----TestBoundary9876")
- Full byte control: all 256 values survive including 0x00
- 2-byte partial LR overwrite gives deterministic code redirect
- Persistent DoS (3x reproduced, manual recovery required)
- No stack canaries (SDK toolchain analysis)
- No info leaks in HTTP responses (all static 117-byte bodies)

**Active blockers:**
- Vulnerable function not yet identified in binary (15+ candidates ruled out)
- ASLR (~18 bits entropy, 2 MiB alignment) — no bypass found
- FW version gap: binary analysis on FW 20.0.0, target runs 22.5.0
- Manual recovery between crashes (~30-60s each)

**Files:** `ldn_research/docs/multipart_overflow_status.md`,
`ldn_research/CVE-multipart-crash.md`, `ldn_research/scripts/multipart/`

---

### 2. CVE-2026-82079 — ldn WiFi Stack Overflow (CONFIRMED, harder path)

**Status:** Confirmed by independent static analysis. Harder to exploit than
multipart overflow.

**Summary:** Stack-based buffer overflow in ldn sysmodule's NetworkLayersCopy
function (FUN_71000a13d0). memcpy to 1500-byte stack buffer with dead size
parameter. Triggered via LP2P WiFi action frames.

**Why harder than multipart:**
- Requires monitor-mode WiFi + action frame injection (special hardware)
- ldn sysmodule has separate ASLR slide from photoViewer
- iwlwifi TX limitations for action frame delivery
- More complex protocol setup (LP2P handshake)

**Files:** `ldn_research/TECHNICAL_REPORT.md`,
`ldn_research/docs/cve_2026_82079_analysis.md`, `ldn_research/scripts/wifi/`

---

### 3. LDN Heap OOB Write (CONFIRMED, separate finding)

**Status:** Out-of-bounds heap copy in join handler demonstrated. Code execution
not achieved.

**Internal identifier:** LDN-HEAP-OOB-001

**Relationship to CVE-2026-82079:** Unresolved. The CVE is classified as CWE-121
(stack overflow); our finding is an OOB heap copy — materially different. May be
a separate vulnerability in the same subsystem.

**Files:** `ldn_research/FINDINGS.md`, `ldn_research/scripts/heap/`

---

### 4. RCM / USB Boot ROM (EXHAUSTED)

**Status:** No USB code-execution primitive demonstrated. Console behavior
consistent with hardware-patched Erista.

**Key findings:**
- CVE-2018-6242 (Fusée Gelée) does not produce code execution on this unit
- EP0 field map decoded (16 fields), double-buffer DMA confirmed
- GET_STATUS bounded info disclosure (up to 255 bytes)
- Destination address is hardcoded

**What is NOT established:**
- Direct IPATCH fuse readout confirming patch status
- That all USB attack paths have been tested

**Files:** `tegra_fuzz/` (fuzzer), `findings/` (evidence)

---

### 5. HTTP Server Bugs (CLOSED — DoS only)

- **Range header DoS:** `Range: bytes=0-SMAX+1` → HTTP unavailability (2162-0002)
- **GET + body:** Not reproducible in isolation, likely accumulated heap stress
- **DHCP:** ldn DHCP code proven clean (4 sessions)

---

### 6. TSEC Exploitation (BLOCKED — requires prior code exec)

Literature-derived findings only. 4+ documented hardware issues. Full chain
requires existing AP code execution, which we don't have. Becomes relevant after
achieving initial code exec through another path.

---

### 7. Peripheral / Alternative Entry Points (NOT STARTED)

Potential targets: Bluetooth, NFC, game card reader, Joy-Con protocol, browser
(captive portal / eShop), game save parsing, USB accessory driver bugs.

---

## Tools & Environment

- **PC:** Linux (Fedora, kernel 7.3.4-200.fc44.x86_64)
- **WiFi:** Intel iwlwifi (wlp5s0), raw frame injection via nl80211
- **Python:** 3.15, venv at project root
- **RE:** REA/Ghidra with MCP tools
- **Target binaries:**
  - `ldn_research/firmware/photoViewer_20.0.0/main.flat.bin` (9.7MB, arm64)
  - `ldn_research/firmware/ldn_22.5.0/main.flat.bin` (961KB, arm64)
- **Switch BSSID:** ec:c4:0d:f3:dc:db (channel 1, 2412 MHz)

## Constraints

1. **No firmware updates** — intentionally on 22.5.0
2. **Software only** — no hardware glitching, voltage fault injection
3. **No USB SET_ADDRESS** — bRequest=0x05 corrupts host xHCI controller
4. **No high-endpoint GET_STATUS** — wIndex >= 0x82 kills USB controller
5. **EP0 pre-claim required** — GET_STATUS read before claim_interface
6. **Evidence rigor** — distinguish established from inferred; HTTP availability
   is an indirect oracle; name findings by what was observed
