# Firmware Binary Acquisition Guide

## Objective
Obtain the `ldn` sysmodule binary (NSO) from FW 22.5.0 (vulnerable) and FW 23.0.0 (patched)
for binary diffing to locate the CVE-2026-82079 stack buffer overflow fix.

## Target Binary

| Field | Value |
|-------|-------|
| Title ID | `0100000000000018` |
| Module name | `ldn` |
| Type | System module (sysmodule) |
| Format | NSO (Nintendo Switch Object) inside NCA |
| FW 22.5.0 version | 22.5.0.480 |
| FW 23.0.0 change | Added `srepo:u` service access, KernelVersion 26.2→27.2 |

## CVE-2026-82079 Summary

- **CWE-121**: Stack-based Buffer Overflow in **lp2p DHCP server** thread
- **Discoverer**: moehw (HackerOne H1:3770768)
- **Reported**: 2026-05-30, **Published**: 2026-09-10
- **CVSS 4.0**: 7.0 HIGH (AV:A/AC:L/AT:N/PR:N/UI:P)
- **CVSS 3.1**: 8.4 HIGH (AV:L/AC:L/PR:N/UI:N — CISA-ADP scoring)
- **Affected**: All Nintendo Switch FW < 23.0.0
- **Fixed**: FW 23.0.0 (released 2026-09-10)
- **No public PoC exists** as of 2026-11-22
- **Bug**: DHCP server copies frame data to stack without size validation
- **Attack path**: Send to Smartphone → WiFi AP → lp2p DHCP server starts → oversized DHCP options → stack overflow
- **Bonus**: ldn SendActionFrame heap overflow ALSO unfixed on 22.5.0 (fixed 23.5.0)

## Extraction Pipeline

```
Firmware archive (.zip)
  └─> Individual NCA files
       └─> hactool + prod.keys
            └─> ExeFS directory
                 └─> main (the NSO binary)
                      └─> Ghidra / IDA with Switch loader
```

### Step 1: Obtain Firmware NCA Files

**Method A: Dump from own console (requires Atmosphère CFW)**
- Use `nxdumptool` homebrew to dump system titles
- Title ID filter: `0100000000000018`
- Output: NCA file(s) for the ldn module

**Method B: Extract from firmware archive**
- Firmware archives contain ~100+ NCA files per version
- Need to identify which NCA contains title `0100000000000018`
- Use `hactoolnet` to list NCAs: `hactoolnet -t switchfs --listncas <fw_dir>`
- Look for the entry with titleId `0100000000000018` and contentType `Program`

### Step 2: Extract Keys (prod.keys)

Keys are required to decrypt NCA files. Must be dumped from your own console.

**Method A: Lockpick_RCM (requires RCM exploit — N/A for patched units)**
- Not available on our patched Erista unit

**Method B: Lockpick (Atmosphère homebrew)**
- Requires CFW already running (chicken-and-egg problem for us)

**Method C: TegraExplorer**
- Same RCM requirement — not available

**Note**: This is a bootstrapping problem. We need code execution to dump keys,
but we're trying to get code execution. Options:
1. Obtain keys from a separate unpatched unit (if available)
2. Use community-documented key derivation algorithms with fuse values
3. Acquire the binary through the CVE-2026-82079 exploit itself (once developed)
4. Use SwitchBlade or similar tools that work with pre-extracted NSOs

### Step 3: Decrypt NCA → Extract ExeFS

```bash
# List NCA contents
hactool -k prod.keys --info <ldn_program.nca>

# Extract ExeFS (contains the NSO binary)
hactool -k prod.keys --exefsdir=./ldn_exefs <ldn_program.nca>

# The main binary will be at ./ldn_exefs/main
```

### Step 4: Load NSO in Analysis Tool

**Ghidra (recommended)**:
- Install Ghidra-Switch-Loader (https://github.com/Adubbz/Ghidra-Switch-Loader)
  - Requires JDK 21
- Load `main` NSO file — loader handles NSO header, decompression, relocation
- Apply SDK symbols from ghidra-nn-stuff (https://github.com/averne/ghidra-nn-stuff)
  - Pattern files for automatic function labeling

**SwitchBlade (alternative)**:
- Python 3.10+, no Ghidra needed
- `python3 loader.py /path/to/ldn.nso` — parses NSO header, extracts .text/.rodata/.data
- `python3 diff.py` — diffs two firmware versions to find patched functions
- `python3 analyzer.py` — finds SVCs, labels Horizon OS syscalls
- `python3 cfg.py` — builds control flow graphs
- Web UI: `pip install fastapi uvicorn capstone`
- Note: targets FW 20.1.5 by default, but should work with other versions

**IDA Pro**:
- Use nxo64.py loader from ReSwitched (https://reswitched.github.io/awesome/)
- Supports NRO/NSO/KIP1 formats

### Step 5: Binary Diff (22.5.0 vs 23.0.0)

**Goal**: Find what changed in the ldn module to fix CVE-2026-82079.

**SwitchBlade diff.py**:
```bash
python3 diff.py --old /path/to/22.5.0/ldn.nso --new /path/to/23.0.0/ldn.nso
```

**Diaphora (Ghidra/IDA plugin)**:
- Export both versions as SQLite databases
- Run diff to find modified/added/removed functions
- Focus on functions related to: advertisement parsing, auth frame processing,
  SendActionFrame, buffer copy operations

**BinDiff (alternative)**:
- Google's binary diffing tool, works with IDA exports

### What to Look For in the Diff

**CONFIRMED: The CVE is in the lp2p DHCP server** (Switchbrew: "copies frame data to
stack without size validation"). HackerOne H1:3770768 by moehw.

1. **DHCP frame parsing** — The lp2p DHCP server thread (started by nn.lp2p.StateMachine
   during CreateGroup) copies incoming DHCP option data to a stack buffer. The fix adds
   size validation before this copy.
2. **Stack buffer size changes** — Local variables enlarged or moved to heap
3. **DHCP option length checks** — DHCP options are TLV (type + length + value, max 255B
   per option). Multiple options combined can exceed the stack buffer.
4. **Also look for**: Advertisement size field (0x22), SendActionFrame heap overflow
   (separate bug, fixed in 23.5.0 not 23.0.0), auth payload size validation

### Known 23.0.0 ldn Changes (from Switchbrew)

- Added `srepo:u` service access
- KernelCap KernelVersion: 26.2 → 27.2
- CVE-2026-82079 fix (details not documented)
- 23.5.0 added additional ldn fixes: "max-size check for frame_size" on 7 functions

## Alternative Analysis Paths (No Keys Required)

### A. Analyze ldn_mitm Source Code
- `ldn_mitm` (https://github.com/DefenderOfHyrule/ldn_mitm, program ID 0x4200000000000010)
  intercepts LDN IPC calls
- Its source reveals the IPC interface and data structures the real ldn module uses
- `ryu_ldn_nx` specifically targets FW 22.5.0 + Atmosphere 1.11.2

### B. Analyze the LDN Protocol Directly
- Fully documented at https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol
- Advertisement frames, auth frames, and disconnect frames are all parseable
- The overflow is likely in one of these frame handlers
- Our `wifi_frame_inject.py` and `ldn_frame_fuzzer.py` tools target this

### C. SDK Symbols + Known Patterns
- ghidra-nn-stuff provides pattern files that label SDK functions in sysmodule binaries
- Once functions are labeled, search for `nn::ldn::*` namespace functions
- The vulnerable function likely calls `memcpy` or similar with an unchecked size from
  a received frame

### D. Switchbrew Documentation
- LDN services IPC: https://switchbrew.org/wiki/LDN_services
- Switch System Flaws: https://switchbrew.org/wiki/Switch_System_Flaws
  - Documents SendActionFrame overflow (may be the CVE-2026-82079 root cause)
- 23.0.0 changelog: https://switchbrew.org/wiki/23.0.0
- 23.5.0 changelog: https://switchbrew.org/wiki/23.5.0 (additional ldn validation)

## Bootstrapping Strategy

Since we can't dump keys without code execution, and we need the binary to develop
the exploit for code execution, the practical path is:

1. **DHCP overflow first**: Send crafted DHCP DISCOVER packets with oversized options
   to the lp2p DHCP server. The 5-second lease time allows rapid testing. Binary search
   for the exact stack buffer boundary. Tool: `lp2p_dhcp_overflow.py`.
2. **Measure the crash**: When the overflow triggers, the Switch will disconnect/freeze.
   This confirms the buffer boundary without seeing the code.
3. **Build ROP chain**: Once buffer size is known, need ldn sysmodule binary for gadget
   addresses. Obtain binary via step 4, or use known SDK function addresses.
4. **Obtain binary after exploit**: Once we have code execution via CVE-2026-82079,
   dump keys and extract the binary for the full TSEC chain.
5. **Alternative**: If a separate unpatched unit is available, dump its keys to bootstrap
   the analysis. Or use community RE resources that may have the NSO available.

## Priority Actions (Offline, No Switch Required)

- [x] Document firmware acquisition pipeline (this file)
- [x] Build lp2p DHCP overflow probe (`lp2p_dhcp_overflow.py`) — PRIMARY CVE TOOL
- [x] Build DHCP general probe (`dhcp_probe.py`)
- [x] Build LDN action frame fuzzer (`ldn_action_frame_fuzzer.py`)
- [x] Build LDN protocol-aware frame fuzzer (`ldn_frame_fuzzer.py`) — 69 test cases
- [x] Build LDN authenticated fuzzer (`ldn_authenticated_fuzzer.py`)
- [x] Build LDN pcap parser (`ldn_pcap_parser.py`) — tested on 824 beacons
- [x] Build HTTP overflow probe tool (`http_overflow_probe.py`)
- [x] Build HTTP deep recon tool (`http_deep_recon.py`) — 13 test modules
- [x] Build HTTP path traversal probe (`http_path_traversal.py`)
- [x] Build WiFi frame injection tool (`wifi_frame_inject.py`)
- [x] Build QR credential extractor (`qr_credential_extractor.py`)
- [x] Complete CVE-2026-82079 analysis (`cve_2026_82079_analysis.md`)
- [x] Complete HTTP server analysis (`http_server_analysis.md`)
- [x] Complete pcap analysis (`pcap_analysis.md`)
- [x] Analyze ldn_mitm source — IPC command table extracted (cmds 0-402), no lp2p code
- [x] Analyze kinnay/LDN source — monitor mode impl, AES-CCM data frames, ETH_P_OUI=0x88B7
- [x] Document Switch exploit mitigations (NO canaries, NO PAC on Erista, ASLR 17-bit)
- [x] Build stack layout mapper + exploit builder (`dhcp_stack_mapper.py`)
- [x] Build ASLR infoleak scanner (`ldn_infoleak_scanner.py`)
- [x] Extract full lp2p IPC interface from Switchbrew (ISfService cmds 0-1560)
- [ ] Clone and evaluate SwitchBlade for firmware diffing
- [ ] Clone ghidra-nn-stuff for SDK symbol matching
