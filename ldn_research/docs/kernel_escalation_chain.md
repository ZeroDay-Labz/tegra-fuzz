# Kernel Escalation Chain: FW 22.5.0 (ldn → kernel → persistent CFW)

## Overview

This documents the full exploit chain from CVE-2026-82079 (ldn userland) to kernel
access on Nintendo Switch FW 22.5.0, with paths to persistent custom firmware.

**Device**: HAC-001 Erista, Serial XAW4 001878, FW 22.5.0
**Entry point**: CVE-2026-82079 (lp2p Vendor-Specific IE builder, 0x99d80)
**Goal**: userland → kernel → persistent CFW (no modchip)

---

## Stage 1: ldn Code Execution (CONFIRMED)

**CVE-2026-82079** — Stack buffer overflow in lp2p Vendor-Specific IE builder

- **Function**: 0x99d80 (288 bytes)
- **Bug**: `memcpy(sp+0x13, attacker_data, attacker_length)` with no bounds check
- **Trigger**: WiFi AP → DHCP → vendor-class-identifier ≥222 bytes
- **Overflow**: 253B to x29, 261B to x30, 34B max overflow
- **Mitigations**: No canaries, no PAC, no CFI, NX stack (ROP only), ASLR 17-bit 2MB
- **Strategy**: 2-byte partial x30 overwrite, ~128 brute-force attempts average
- **Status**: Vulnerable function confirmed, gadget DB built (2,692 frame pops)

**Blockers**: Live probe needed to confirm NM overhead, capture original x30 value

---

## Stage 2: ROP → Payload Download (PLANNED)

After controlling x30, the ROP chain:

1. **Stack pivot** to controlled data region (7 stack pivot gadgets available)
2. **Call SVC 0x21** (SendSyncRequest) via existing bsd:s handle
3. **Open TCP socket** back to PC at 192.168.0.2
4. **Download stage 2 payload** (larger ROP chain or data-only payload)
5. **Call SVC 0x02** (SetMemoryPermission) to make heap region RW
6. **Copy payload to heap** via memcpy gadgets
7. Continue execution from heap-based ROP chain

**Key insight**: ldn already has open bsd:s handles. The ROP chain can reuse
them without needing to call ConnectToNamedPort or go through sm.

---

## Stage 3: Kernel Escalation Paths

### ldn's IPC Attack Surface (confirmed from binary strings)

**Client services (ldn uses)**:
| Service | Description | Kernel relevance |
|---------|-------------|-----------------|
| bsd:s/a/u | BSD sockets | **HIGH** — unfixed bug on 22.5.0 |
| wlan:p | WiFi private/privileged | **HIGH** — raw WiFi HW access |
| nifm:u/a/s | Network interface mgmt | LOW — network config only |
| spl:mig | Security processor | MEDIUM — crypto/key derivation |
| set:sys | System settings | MEDIUM — persistence helper |

**Server services (ldn provides)**:
| Service | Clients | Use |
|---------|---------|-----|
| ldn:u | Games/apps | LDN multiplayer |
| ldn:s | System | LDN system control |
| ldn:m | Manager | LDN management |

**NOT accessible**: fsp-srv (filesystem), nvdrv (GPU), audio, loader

### Path A: bsdsocket Exploitation (BEST CANDIDATE)

**Bug**: AddrInfo deserialization vulnerability (fixed 23.5.0, unfixed on 22.5.0)
**Reachable**: YES — ldn has bsd:s/a/u handles
**Chain**: ldn ROP → craft malicious AddrInfo IPC → bsd sysmodule overflow

The bsd sysmodule runs at higher privilege and has access to:
- Kernel network stack (direct SVC interaction)
- Potentially additional services not available to ldn

From bsd, the kernel attack surface expands significantly. BSD sysmodule
processes run with network-related kernel SVCs and may have:
- MapPhysicalMemory access
- Larger SVC whitelist
- Direct access to network hardware DMA regions

**Research needed**: Extract bsd sysmodule binary, analyze AddrInfo handler,
confirm exploitability, map bsd's SVC and IPC surface.

### Path B: wlan:p WiFi Firmware Exploitation

**Service**: wlan:p provides privileged WiFi hardware access
**Attack**: Send raw 802.11 management frames through wlan:p IPC
**Target**: Broadcom BCM4356 WiFi firmware on the Switch

Broadcom WiFi chips have extensive vulnerability history:
- Broadpwn (CVE-2017-9417)
- Many NitroHack/Over-The-Air exploits
- DMA-based kernel memory access from WiFi firmware

**Chain**: ldn code exec → wlan:p IPC → raw frame inject → WiFi FW exploit
        → DMA to kernel memory → kernel code execution

**Advantage**: WiFi firmware bugs are hardware-level, often not patched by
Nintendo OS updates (requires separate WiFi FW update)

**Research needed**: Dump WiFi firmware via wlan:p, identify BCM4356 version,
check against known Broadcom vulns, test DMA capabilities.

### Path C: Kernel SVC Fuzzing (DISCOVERY)

All KNOWN kernel SVC bugs are fixed on 22.5.0 (latest was 16.0.0). But the
kernel attack surface from sysmodule context includes 41 SVCs:

**High-value SVCs to fuzz from ldn context**:
- SVC 0x02: SetMemoryPermission — permission transitions
- SVC 0x04: MapMemory — memory mapping edge cases
- SVC 0x06: QueryMemory — information disclosure
- SVC 0x1C: WaitForAddress — thread synchronization (had UAF in 7.0.0)
- SVC 0x1D: SignalToAddress — thread synchronization
- SVC 0x25: CreateTransferMemory — shared memory creation
- SVC 0x40: CreateSession — IPC session creation (unusual for sysmodule)
- SVC 0x52: ManageNamedPort — port management (unusual for sysmodule)

**Strategy**: Systematic SVC fuzzing from ldn context, focusing on:
- Race conditions in memory management SVCs
- Edge cases in handle management
- Thread synchronization primitives

### Path D: spl:mig Key Extraction → TrustZone

**Service**: spl:mig provides crypto key derivation
**Attack**: Derive or extract keys used for boot chain verification

If we can extract the per-console keys through spl:mig:
- Derive Package2 encryption key → decrypt kernel
- Derive BIS (Built-in Storage) keys → read/write NAND
- Potentially forge signatures (if signing keys accessible)

**Research needed**: Map spl:mig IPC commands available to ldn, test what
key operations are permitted from ldn's permission level.

---

## Stage 4: Persistence Strategies

### Strategy 1: WiFi-Tethered (Works Now, No Kernel Needed)

This is achievable with JUST Stage 1 + Stage 2:

1. PC runs WiFi AP with exploit DHCP server
2. Switch connects → CVE-2026-82079 triggers automatically
3. ROP chain downloads payload → arbitrary ldn code execution
4. Payload runs in ldn context (network, WiFi, settings access)
5. **Re-exploits every boot** when Switch connects to WiFi

**Uses set:sys to persist WiFi settings**:
- Ensure auto-connect to our AP is configured
- Set DNS to our server for additional control
- No kernel access needed for this level of control

**Capabilities with ldn-only access**:
- Full network interception/redirection (bsd:s)
- WiFi frame injection/monitoring (wlan:p)
- System settings modification (set:sys)
- Crypto operations (spl:mig)
- Arbitrary code exec on every WiFi connect

### Strategy 2: Save Game Exploit Chain (Needs fs Access)

Not directly reachable from ldn (no fsp-srv). Would require:
1. ldn → bsd → chain to process with fs access → save game modification
2. Modified save game triggers secondary exploit on boot

### Strategy 3: DNS/Captive Portal Re-Trigger

1. Use set:sys from ldn to point DNS to our server
2. On next boot, captive portal detection hits our server
3. Server returns exploit page (if browser-based vuln exists)
4. Or: DNS redirects NTP/update checks to deliver exploit data

### Strategy 4: Full NAND Write (Needs Kernel)

Requires Path A/B/C to reach kernel first:
1. Kernel code exec → map NAND physical memory
2. Write modified sysmodules to NAND
3. Modified sysmodules persist across reboots
4. True persistent CFW without modchip

---

## Recommended Attack Plan

### Phase 1: WiFi-Tethered Exploit (Immediate)
1. ✅ Vulnerable function identified (0x99d80)
2. ✅ Gadget database built (2,692 gadgets)
3. ⬜ Live probe: confirm x30 offset and NM overhead
4. ⬜ Build ROP chain: stack pivot → bsd socket → download payload
5. ⬜ Build stage 2: network loader that runs in ldn context
6. ⬜ Build DHCP exploit server on PC
7. **Result**: Code exec in ldn on every WiFi connect

### Phase 2: Lateral Movement (Medium Term)
1. ⬜ Extract bsd sysmodule from FW 22.5.0
2. ⬜ Analyze AddrInfo deserialization (unfixed on 22.5.0)
3. ⬜ Build bsd exploit triggered via ldn's bsd:s handle
4. ⬜ Map bsd's SVC and IPC surface
5. **Result**: Code exec in bsd sysmodule

### Phase 3: Kernel Access (Research)
1. ⬜ From bsd context, fuzz kernel SVCs
2. ⬜ Dump and analyze WiFi firmware via wlan:p
3. ⬜ Research Broadcom BCM4356 vulnerabilities
4. ⬜ Test DMA capabilities from WiFi firmware
5. **Result**: Kernel code execution

### Phase 4: Persistent CFW (End Goal)
1. ⬜ With kernel access, derive NAND encryption keys
2. ⬜ Dump and modify system partition
3. ⬜ Write custom boot payload
4. ⬜ Build custom Atmosphere-style CFW for 22.5.0
5. **Result**: Persistent CFW without modchip

---

## Known Unfixed Bugs on FW 22.5.0

| Bug | Service | Fixed In | Reachable from ldn? |
|-----|---------|----------|-------------------|
| CVE-2026-82079 (stack overflow) | ldn | 23.0.0 | ENTRY POINT |
| SendActionFrame unbounded size | ldn | 23.5.0 | YES (self) |
| memcpy size not clamped to 0x540 | ldn | 23.5.0 | YES (self) |
| AES-GCM frame_size no max check | ldn | 23.5.0 | YES (self) |
| Loop bound unchecked (inw3) | ldn | 23.5.0 | YES (self) |
| AddrInfo deserialization | bsd | 23.5.0 | YES (bsd:s) |
| fs PathNormalizer (ns2jb) | fs | 23.5.0 | NO (no fsp) |
| Audio RequestUpdate | audio | 23.0.0 | NO (no audio) |

---

## SVC Map (41 SVCs available to ldn)

```
Memory:  0x02 SetMemoryPermission, 0x03 SetMemoryAttribute,
         0x04 MapMemory, 0x05 UnmapMemory, 0x06 QueryMemory
Thread:  0x07 ExitProcess, 0x08 CreateThread, 0x09 StartThread,
         0x0a ExitThread, 0x0b SleepThread, 0x0c GetThreadPriority,
         0x0f SetThreadCoreMask
Sync:    0x11 SignalEvent, 0x12 ClearEvent, 0x14 ResetSignal,
         0x15 WaitSynchronization, 0x16 CancelSynchronization,
         0x17 ArbitrateLock, 0x18 ArbitrateUnlock,
         0x19 WaitForAddress, 0x1a SignalToAddress
IPC:     0x1b ArbitrateUnlock(?), 0x1c WaitForAddress(?),
         0x1d SignalToAddress(?), 0x1f ConnectToNamedPort,
         0x21 SendSyncRequest, 0x22 SendSyncRequestWithUserBuffer
Handle:  0x25 CreateTransferMemory, 0x26 CloseHandle,
         0x27 Break, 0x28 OutputDebugString, 0x29 ReturnFromException
Info:    0x34 GetInfo, 0x35 FlushProcessDataCache, 0x36 ?,
         0x52 ManageNamedPort
Session: 0x40 CreateSession, 0x41 AcceptSession,
         0x43 ReplyAndReceive, 0x44 ReplyAndReceiveWithUserBuffer,
         0x45 CreateEvent
```

Note: SVC 0x1F (ConnectToNamedPort) means ldn CAN connect to sm: at runtime!
This potentially allows accessing ANY service, not just those with pre-opened handles.
