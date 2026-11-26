# Switch Security Research — Master Status

**Hardware**: HAC-001, Tegra X1 Erista, Serial XAW4 001878 (patched V1)  
**Firmware**: 22.5.0 (intentionally not updated)  
**Goal**: Persistent custom firmware via software-only exploitation  
**Date**: 2026-11-25  

---

## Exploitation Paths Summary

### Path 1: photoViewer Multipart Overflow (ACTIVE — most promising)

**Status**: Exploit primitives confirmed, vulnerable function not yet identified in binary  
**Attack surface**: WiFi (Send to Smartphone HTTP server)  
**Primitive**: Stack buffer overflow via multipart filename → FP/LR control  

What's confirmed:
- Crash boundary at 3972/3973 bytes
- Saved FP at byte 3973, LR at byte 3981
- 2-byte partial LR overwrite works (deterministic redirect within 64KB window, ASLR-independent)
- Persistent DoS (3x reproduced)

Blockers:
- Haven't identified the specific vulnerable function in the binary (see `multipart_overflow_status.md`)
- Don't know the original LR value (needed for gadget window mapping)
- FP=0 problem: overwritten FP=0x00 may cause issues in caller's frame access
- ASLR: full 8-byte address leak not available (no info leak found in HTTP responses)

Exploitation chain (theoretical):
1. Partial LR overwrite → redirect to gadget in 64KB window
2. Gadget must set up further control (stack pivot or register control)
3. Need to chain to larger ROP or code exec

**Detailed docs**: `multipart_overflow_status.md`

### Path 2: CVE-2026-82079 WiFi Action Frame Overflow (CONFIRMED but harder)

**Status**: Vulnerability confirmed through independent static analysis  
**Attack surface**: WiFi (LP2P action frames, monitor mode required)  
**Primitive**: memcpy to 1500-byte stack buffer with attacker-controlled size (dead parameter)  

What's confirmed:
- FUN_71000a13d0 (NetworkLayersCopy) in ldn sysmodule
- memcpy with dead size parameter `x3` (always overwritten by callee)
- Target buffer is 1500 bytes on stack
- Secondary finding: FUN_710003e020 ring buffer handlers

Blockers:
- ASLR bypass needed (ldn sysmodule has separate ASLR slide)
- Requires WiFi monitor mode + action frame injection
- More complex attack setup than photoViewer path
- DHCP crash investigation proved the ldn DHCP code is clean (crash was pre-DHCP)

**Detailed docs**: `cve_2026_82079_analysis.md`, `action_frame_overflow_status.md` (if exists)

### Path 3: HTTP Range DoS (LOW VALUE)

**Status**: Confirmed but DoS-only, no code execution  
**Attack surface**: WiFi (Send to Smartphone HTTP server)  
**Primitive**: `Range: bytes=0-<SMAX+1>` causes HTTP unavailability (error 2162-0002)  
**Library**: cpp-httplib  
**Value**: DoS only, not useful for custom firmware  

### Path 4: Multipart Send-to-Smartphone Persistent DoS (LOW VALUE)

**Status**: Confirmed 3x  
**Attack surface**: WiFi (Send to Smartphone HTTP server)  
**Primitive**: Same overflow as Path 1, but as a DoS rather than code exec  
**Value**: Less interesting than Path 1 since same trigger, but confirms the bug is real  

### Path 5: RCM (EXHAUSTED)

**Status**: Patched hardware, not viable  
**Notes**: This is a patched V1 Switch. RCM-based approaches (fusee-gelee, ShofEL2) don't work. T210 message format confirmed working (error 0x13) but BCT RSA public key is the blocker. All RCM approaches are exhausted.

### Path 6: TSEC/Horizon/Peripheral Research (LITERATURE ONLY)

**Status**: Literature review complete, no active exploitation  
**Notes**: 4+ documented HW issues in TSEC, but full chain requires prior AP code execution (which we don't have yet). This becomes relevant AFTER achieving initial code exec through another path.

---

## Attack Infrastructure

### WiFi Setup
- Switch creates LP2P WiFi network during "Send to Smartphone"
- DHCP server: 192.168.0.1, subnet /24, no gateway/DNS
- HTTP server: 192.168.0.1:80
- Interface: `wlp5s0` (must bind with `SO_BINDTODEVICE`)

### HTTP Server Profile
- No Server header, no Date header
- Always `Connection: close`
- Supports: GET, HEAD, Range, POST (multipart)
- Content types: text/html, text/plain (for JSON), image/jpeg, text/css
- mDNS: no services advertised

### Networking Code Pattern
```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')  # SO_BINDTODEVICE
s.connect(('192.168.0.1', 80))
```

---

## "Think Outside the Box" — Alternative CFW Approaches

Ideas for reaching custom firmware beyond the current overflow:

### A. Chain from photoViewer to kernel
1. Get code exec in photoViewer via multipart overflow
2. Use photoViewer's IPC permissions to attack other sysmodules
3. Escalate from sysmodule to kernel (known Horizon kernel vulns on older FW)
4. Patch boot chain from kernel

### B. Browser exploit (if accessible)
- Switch has a hidden browser (used for captive portal, eShop, etc.)
- Historically rich attack surface for console exploitation
- Would need a way to trigger browser navigation to attacker-controlled page
- Could potentially be triggered via DNS hijacking on the LP2P network

### C. Game save exploitation
- Some games have had save file parsing vulnerabilities
- Requires a game with known vuln on this FW version
- Save files can sometimes be injected via microSD

### D. USB gadget / accessory attacks
- Switch USB-C port in host mode (dock) or device mode
- Fake USB accessories could potentially trigger driver bugs
- Would need USB protocol fuzzing infrastructure

### E. Bluetooth attacks
- Switch has Bluetooth for controllers
- BT stack bugs are common in embedded devices
- Would need BT fuzzing setup

### F. Chain: WiFi overflow → ldn sysmodule → kernel
1. Use CVE-2026-82079 to get code exec in ldn sysmodule
2. ldn has network-facing IPC → pivot to other services
3. Kernel exploit from privileged sysmodule position

**Current best bet**: Path 1 (photoViewer multipart overflow) is closest to exploitation. It has confirmed control primitives, relatively simple attack setup (just WiFi + HTTP), and the remaining work is binary analysis to find the vulnerable function and map the gadget window.

---

## Key Constraints (MUST PRESERVE)

- **NO firmware updates** — user is intentionally on older FW
- **NO hardware glitching** — software-only research
- **NO USB SET_ADDRESS** — corrupts host xHCI
- **NO GET_STATUS with wIndex >= 0x82** — kills USB controller
- **RCM is EXHAUSTED** — patched hardware
- **Evidence rigor** — HTTP availability is indirect oracle, not crash proof
- **Manual recovery** — user manually restarts Switch between crashes
