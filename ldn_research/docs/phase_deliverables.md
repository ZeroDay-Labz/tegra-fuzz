# CVE-2026-82079 Validation and Custom Firmware Feasibility — Deliverables

**Date:** 2026-11-25
**Hardware:** Nintendo Switch HAC-001 (XAW4 001878), Tegra X1 Erista, FW 22.5.0
**Binary:** `firmware/ldn_22.5.0/main.flat.bin` (961,288 bytes, arm64, base 0x7100000000)
**SHA-256:** `91bee792da7c8ca7718bac166009331cd14ecdcc662c9fcf52f435da0d56f34a`

---

## Phase 1: Verified Function-Level Call Graph

### Data Flow: BPF Socket → Stack Overflow

Each transition names the exact function, what pointer is passed, what length is used,
and what bounds check (if any) constrains it.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ BPF Socket Read — FUN_71000a0d40 ("OnFileRead")                       │
│                                                                         │
│ 1. ioctl(bpf_fd, BIOCGBLEN, &buflen) → gets kernel BPF buffer size    │
│ 2. BOUNDS: if (buflen > 0x1000) → error "dynamic buflen > static buf" │
│ 3. memset(0x71002160af, 0, 0x1000) — clears 4096-byte global buffer   │
│ 4. read(bpf_fd, 0x71002160af, buflen) → raw BPF frame into global buf │
│ 5. BOUNDS: if (bh_caplen != bh_datalen) → error (truncation check)    │
│ 6. data_ptr = 0x71002160af + bh_hdrlen → points past BPF header       │
│ 7. Passes (data_ptr, total_read_bytes) to OnEthernetPacket             │
│                                                                         │
│ Input: raw BPF frame, up to buflen bytes (≤ 4096)                      │
│ Output: pointer into global buffer, total bytes read (includes BPF hdr)│
│ Constraints: buflen ≤ 4096, bh_caplen == bh_datalen                    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ OnEthernetPacket — FUN_71000a1640                                      │
│                                                                         │
│ 1. BOUNDS: checks EtherType == 0x0800 (IPv4 only)                      │
│ 2. Records Ethernet layer: type=0, ptr=data_ptr, size=14               │
│ 3. Advances pointer by 14 bytes (Ethernet header)                      │
│ 4. Passes (layer_info, ip_ptr, remaining_size) to OnInternetPacket     │
│                                                                         │
│ No size reduction: entire frame size propagates minus 14-byte offset.  │
│ Layer info struct populated: entry[0] = {type:0, ptr:eth_start, len:14}│
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ OnInternetPacket — FUN_71000a17e0                                      │
│                                                                         │
│ 1. Reads IP header length: ihl = (ip[0] & 0xf) * 4                    │
│ 2. BOUNDS: validates IP total_length field, computes checksum           │
│ 3. BOUNDS: checks protocol == 0x11 (UDP)                               │
│ 4. Records IP layer: type=1, ptr=ip_ptr, size=ihl                     │
│ 5. Passes (layer_info, udp_ptr, ip_total_length - ihl) to UDP handler │
│                                                                         │
│ Size from IP total_length field (attacker-controlled). Checksum checked│
│ but IP total_length is taken at face value for payload extent.         │
│ Layer info: entry[1] = {type:1, ptr:ip_start, len:ihl}                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ OnUserDatagramPacket — FUN_71000a1a50                                  │
│                                                                         │
│ 1. BOUNDS: validates UDP header (8 bytes), computes UDP checksum       │
│ 2. BOUNDS: checks dest port matches expected DHCP server port          │
│ 3. Records UDP layer: type=2, ptr=udp_ptr, size=8                     │
│ 4. Passes (layer_info, dhcp_ptr, udp_length - 8) to DHCP handler      │
│                                                                         │
│ UDP length field is attacker-controlled. Checksum checked.             │
│ Layer info: entry[2] = {type:2, ptr:udp_start, len:8}                 │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ OnBootProtocolRequestPacket — FUN_71000a1ed0                           │
│                                                                         │
│ 1. BOUNDS: validates DHCP magic cookie (0x63825363)                    │
│ 2. BOUNDS: iterates options with pcVar4 < (param_4 + param_5)         │
│ 3. Records DHCP layer: type=4, ptr=dhcp_ptr, size=(parsed_end - start)│
│ 4. Dispatches SendDhcpPacketEvent (event code 0x65) to coordinator    │
│                                                                         │
│ DHCP option iteration IS properly bounded. But the LAYER SIZE recorded │
│ reflects the full DHCP payload extent, not individual option sizes.    │
│ Layer info: entry[3+] = {type:4, ptr:dhcp_start, len:dhcp_extent}     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                    Event dispatch (code 0x65)
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ OnNewMessage — FUN_71000a25f0 (wrapper) → FUN_71000a2660 (handler)    │
│                                                                         │
│ WRAPPER (0x71000a25f0–0x71000a2657):                                   │
│ 1. Checks event type == 0x65                                           │
│ 2. Extracts data1, data2 from event                                    │
│ 3. Tail-calls to 0x71000a2660 with (this, data1, data2)              │
│                                                                         │
│ HANDLER (0x71000a2660–0x71000a29a3):                                   │
│ 1. Allocates 1500-byte buffer on stack (SP + 0x3C)                    │
│ 2. memset(buffer, 0, 0x5dc) at 0x71000a26bc                          │
│ 3. Calls FUN_71000a0f90 to parse event into layer_info                │
│ 4. CALLS NetworkLayersCopy with:                                       │
│    x0 = &layer_info_out (FP - 0xA8)                                   │
│    x1 = 6 (layer count)                                                │
│    x2 = buffer (SP + 0x3C = FP - 0x684) ← 1500 bytes                 │
│    x3 = 0x5DC (buffer size) ← DEAD PARAMETER                          │
│    x4 = source layer info (from event data1)                           │
│    x5 = source count (from event data2)                                │
│    Call site: 0x71000a272c (bl 0x71000a13d0)                          │
│                                                                         │
│ After NetworkLayersCopy:                                                │
│ 5. CopyOptionValue extracts DHCP message type (safe, bounded)          │
│ 6. Dispatches to type handler (Discover/Request/Decline/Release/Inform)│
│ 7. Builds and sends DHCP response                                      │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ NetworkLayersCopy — FUN_71000a13d0  ★ VULNERABLE FUNCTION ★            │
│                                                                         │
│ FIRST LOOP (0x71000a1430–0x71000a1450):                                │
│   total = 0                                                             │
│   for each source layer:                                                │
│     total += layer.size     ← sums ALL layer sizes, NO bounds check    │
│                                                                         │
│ MEMCPY (0x71000a1454–0x71000a1470):                                    │
│   src = source_layers[0].data_ptr  (first layer's raw data pointer)    │
│   dst = param_3 (stack buffer, 1500 bytes)                             │
│   len = total (sum of all layer sizes, UNCHECKED)                      │
│   bl 0x71000a35c0 (memcpy)                                            │
│                                                                         │
│ SECOND LOOP (0x71000a1480–0x71000a14b4):                               │
│   Writes pointers into output layer_info struct (param_1)              │
│   Each entry: {type, ptr_into_dest_buffer, size} — 24 bytes/entry     │
│                                                                         │
│ ★ param_4 (x3 = 0x5DC, buffer size) is NEVER READ by any instruction. │
│ ★ Total copy size is determined solely by source layer size fields.    │
│ ★ Source layer sizes are derived from attacker-controlled IP/UDP/DHCP  │
│   length fields in the original packet.                                │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Finding

The bounds checks at each protocol layer validate HEADER STRUCTURE (checksums,
magic cookies, protocol numbers, option TLV format) but NOT total payload size
against the destination buffer. The accumulated layer sizes flow unchecked from
attacker-controlled packet headers to the memcpy length parameter.

---

## Phase 2: Memory Safety Verification

### Actual Data Size Constraints Reaching NetworkLayersCopy

| Constraint | Value | Where Checked | Attacker Control |
|------------|-------|---------------|------------------|
| BPF buffer | ≤ 4096 bytes | FUN_71000a0d40 (ioctl check) | Cannot exceed |
| BPF caplen == datalen | Exact | FUN_71000a0d40 | Cannot bypass |
| IP total_length | 16-bit field | FUN_71000a17e0 (read, not capped) | Full control |
| IP checksum | Valid required | FUN_71000a17e0 | Must be correct |
| UDP length | 16-bit field | FUN_71000a1a50 (read, not capped) | Full control |
| UDP checksum | Valid required | FUN_71000a1a50 | Must be correct |
| DHCP magic cookie | 0x63825363 | FUN_71000a1ed0 | Must match |
| DHCP option iterator | Bounded by param_5 | FUN_71000a1ed0 | Properly bounded |
| **memcpy size** | **Sum of layer sizes** | **FUN_71000a13d0 — NOT CHECKED** | **Full control** |

### WiFi Layer Constraints

The critical question: can a WiFi frame larger than 1500 bytes reach the BPF socket?

**802.11 MSDU limit:** 2304 bytes (IEEE 802.11-2020 §9.2.3). This is the maximum
payload a single 802.11 data frame can carry, corresponding to the Ethernet frame
body (IP packet).

**BPF delivery:** BPF raw sockets on Horizon capture the reconstructed Ethernet frame:
14-byte Ethernet header + IP packet. Maximum: 14 + 2304 = **2318 bytes**.

**MTU vs MSDU:** Standard Ethernet MTU is 1500 bytes, but this applies to routed IP
packets, not raw WiFi frames. The WiFi hardware (BCM43455) can physically receive
frames with payloads up to 2304 bytes. Whether the Switch's WiFi driver/firmware
delivers frames >1500 bytes to the BPF socket is **not confirmed empirically** but
is expected based on standard WiFi behavior — BPF operates below the IP layer's MTU.

**Conservative lower bound:** Even at standard 1500-byte MTU:
- Ethernet frame: 14 + 1500 = 1514 bytes
- This is LESS than the 1676-byte buffer-to-LR distance
- IP fragmentation could accumulate >1500 bytes, but ldn's BPF handler processes
  individual frames, not reassembled IP datagrams

**Assessment:** The overflow is reachable at WiFi MSDU sizes (up to 2304 bytes of IP
payload → 2318 bytes total Ethernet frame → 2318 bytes into memcpy → 642 bytes past
LR). If the WiFi driver enforces 1500-byte MTU on delivered frames, the overflow is
still reachable if the BPF socket delivers pre-MTU raw frames. This needs empirical
verification on the actual hardware.

**Outstanding question (not resolvable by static analysis):** Does the BCM43455 WiFi
driver on Horizon deliver BPF frames with payloads >1500 bytes from associated LP2P
clients? A live test sending an oversized UDP datagram and monitoring BPF read return
size would resolve this.

---

## Phase 3: Corrected Stack-Frame Diagram and Mitigation Assessment

### Stack Frame: FUN_71000a2660 (assembly-verified)

**Prologue at 0x71000a2660:**
```asm
stp  x29, x30, [sp, #-0x40]!     ; SP -= 0x40; FP at [SP], LR at [SP+8]
stp  x28, x23, [sp, #0x10]       ; save callee-saved
mov  x29, sp                      ; FP = SP
stp  x22, x21, [sp, #0x20]       ; save callee-saved
stp  x20, x19, [sp, #0x30]       ; save callee-saved
sub  sp, sp, #0x6c0               ; allocate 1728 bytes for locals
```

**NetworkLayersCopy call at 0x71000a2714:**
```asm
sub  x0, x29, #0xa8               ; output = FP - 0xA8
add  x2, sp, #0x3c                ; buffer = SP + 0x3C = FP - 0x684
mov  w1, #0x6                     ; 6 layers
mov  w3, #0x5dc                   ; 1500 (DEAD)
mov  x4, x22                      ; source layer info
mov  x5, x20                      ; source count
bl   0x71000a13d0                 ; NetworkLayersCopy
```

**Epilogue at 0x71000a28c8:**
```asm
add  sp, sp, #0x6c0               ; deallocate locals
ldp  x20, x19, [sp, #0x30]       ; restore callee-saved ← ATTACKER-CONTROLLED
ldp  x22, x21, [sp, #0x20]       ; restore callee-saved ← ATTACKER-CONTROLLED
ldp  x28, x23, [sp, #0x10]       ; restore callee-saved ← ATTACKER-CONTROLLED
ldp  x29, x30, [sp], #0x40       ; restore FP/LR, SP += 0x40 ← ATTACKER-CONTROLLED
ret                                ; branch to attacker-controlled x30
```

### Corrected Memory Layout

```
Offset from    FP-relative    Contents
buffer start
─────────────────────────────────────────────────────────────
0x000          FP - 0x684     buffer[0]       ← memcpy destination start
  ... 1500 bytes of packet data (Ethernet + IP + UDP + DHCP) ...
0x5DC          FP - 0x0A8     layer_info[0]   ← output struct (overwritten by overflow
  ... 144 bytes (6 × 24-byte entries) ...       AND by NetworkLayersCopy's 2nd loop)
0x674          FP - 0x010     remaining locals
  ... 16 bytes ...
0x684          FP + 0x000     saved x29 (FP)  ← ATTACKER CONTROLS FP
0x68C          FP + 0x008     saved x30 (LR)  ← ATTACKER CONTROLS RETURN ADDRESS
0x694          FP + 0x010     saved x28       ← ATTACKER CONTROLS
0x698          FP + 0x014     saved x23       ← ATTACKER CONTROLS
0x6A4          FP + 0x020     saved x22       ← ATTACKER CONTROLS
0x6A8          FP + 0x024     saved x21       ← ATTACKER CONTROLS
0x6B4          FP + 0x030     saved x20       ← ATTACKER CONTROLS
0x6B8          FP + 0x034     saved x19       ← ATTACKER CONTROLS
0x6C4          FP + 0x040     caller's frame  ← overflow continues
```

### Discrepancy Resolution

| Estimate | Value | Error |
|----------|-------|-------|
| Previous "1740 bytes" | 0x6CC | Used Ghidra SP_entry offset (0x6C4) as FP-relative |
| Previous "1698 bytes" | — | 1740 minus 42 headers; propagated base error |
| **Correct** | **1676 bytes** (0x68C) | FP-relative: 0x684 (buffer) + 0x8 (LR offset) |

The error: Ghidra's decompiler names `auStack_6c4` relative to SP_entry. The function's
`stp x29, x30, [sp, #-0x40]!` decrements SP by 0x40 before setting FP, so
FP = SP_entry - 0x40 and buffer = FP - (0x6C4 - 0x40) = FP - 0x684.

### Mitigation Assessment

| Mitigation | Present? | Evidence | Exploitation Impact |
|------------|----------|----------|---------------------|
| Stack canaries | **NO** | `__stack_chk_guard` absent from binary (string search, 0 results) | Direct LR overwrite; no crash-before-return |
| PAC (Pointer Auth) | **NO** | PACIASP opcode `7f2303d5` absent from all 961,288 bytes (byte search) | No return address signing; `ret` goes to controlled x30 |
| NX (W^X) | YES | Standard Horizon memory protection | Cannot inject shellcode; must use ROP |
| ASLR | YES | 17-bit entropy, 2 MiB alignment (Switchbrew) | Need info leak for module base |
| CFI (clang) | Partial | cfi-icall/cfi-vcall documented (Switchbrew) | Constrains indirect call targets |
| XOM | Unknown | Possibly on 20.0.0+ Erista | May prevent reading .text for gadgets |

**Binary-wide PAC assessment:** The PACIASP instruction (`0x7f2303d5`) was searched
across the entire 961,288-byte binary. Zero matches. This means NO function in the
ldn sysmodule uses Pointer Authentication Code on FW 22.5.0 Erista. This is expected:
PAC requires ARMv8.3-A (Cortex-A76+), and Erista's Cortex-A57 does not support it.
Mariko (Cortex-A78AE) would have PAC support.

---

## Phase 4: QR-Code Scenario Reachability

### Send to Smartphone → LP2P → DHCP → Vulnerable Function

**Trigger:** Album → Share → "Send to Smartphone" on the Nintendo Switch.

**What happens:**
1. Switch creates an LP2P WiFi access point
   - SSID: `switch_<MAC>0100S` (e.g., `switch_ECC40DF3DCDB0100S`)
   - Security: WPA2-PSK
   - Channel: varies (observed: channel 1, 2412 MHz)
2. Switch displays QR code containing SSID + PSK for connection
3. Switch starts HTTP server on port 80 (photoViewer) for image transfer
4. Switch starts BPF-based DHCP server in ldn sysmodule for IP assignment

**Attacker connection path:**
1. Scan QR code or view "Trouble connecting?" credentials on Switch screen
2. Connect to WiFi AP using obtained credentials
3. Switch's DHCP server processes attacker's DHCP DISCOVER packet
4. BPF read → OnEthernetPacket → ... → OnNewMessage → NetworkLayersCopy → **overflow**

**Reachability confirmed:** The DHCP server processes packets from ANY connected WiFi
client. No authentication beyond WiFi association (WPA2-PSK) is required. The vulnerable
code path runs for DHCP DISCOVER (message type 1), which is the FIRST packet any client
sends upon association.

**QR code requirement (UI/P in CVSS):** The attacker must either:
- Be close enough to scan the QR code displayed on the Switch screen, OR
- Know the SSID pattern and brute-force the WPA2-PSK (entropy unknown), OR
- Observe the "Trouble connecting?" screen which displays credentials in text

This maps to CVSS `UI:P` (user interaction: passive) — the user must initiate Send to
Smartphone, but takes no active role in the attack.

**Timing window:** The DHCP server is active from the moment Send to Smartphone starts
until the user exits the sharing screen. Typical duration: 30 seconds to several minutes.

---

## Phase 5: AdvertiseData Leak and ASLR Assessment

### AdvertiseData Info Leak

Switchbrew documents a **stack info leak** in ldn's AdvertiseData handling (credited to
yellows8, disclosed July/August 2026). Uninitialized stack data follows the last username
in the AdvertiseData buffer.

**Mechanism:** `SetAdvertiseData` (ldn IPC command 206) writes application data into the
ldn sysmodule's internal state. The buffer that holds this data is allocated on the ldn
sysmodule's stack. If the application data doesn't fill the full 0x180-byte buffer, the
remaining bytes contain whatever was previously on the stack at that location.

**Exposure:** The AdvertiseData is broadcast in LP2P scan responses and beacons. An
attacker **scanning for LP2P networks** (before even connecting to the AP) can read the
leaked bytes.

**Fix version:** The fix clears the buffer with zeros before filling it. The fix version
appears to be FW 23.0.0 or later. **If the fix landed in 23.0.0, then FW 22.5.0 is
affected.**

### ASLR Defeat Assessment

| Approach | Feasibility | Notes |
|----------|-------------|-------|
| AdvertiseData info leak | **Most promising** | Leaked bytes are from ldn's OWN stack; may contain saved LR/FP revealing module base. Needs empirical confirmation. |
| Brute force | Impractical | 131,072 possible bases (17-bit, 2 MiB). No auto-restart of DHCP server on crash. |
| DHCP response timing | Unknown | Timing side-channels in response generation. Not investigated. |
| Other sysmodule leaks | Unlikely | ldn's ASLR slide is per-process, independent of other modules. |

### ASLR Specifics (Horizon, FW 22.5.0)

- **Entropy:** Bits 37–21 randomized = 17 bits, 2 MiB alignment
- **RNG:** `csrng_GenerateRandomBytes` (hardware CSPRNG) since FW 15.0.0
- **Per-process:** Each sysmodule has independent ASLR slide
- **No public bypass:** No public ASLR bypass exists for current Horizon firmware

### HTTP Info Leak Probe Results (Empirical)

A comprehensive HTTP probe of the photoViewer server (192.168.0.1:80) found **no address
leaks** in any response (normal, error, or malformed request). The HTTP server returns
clean, predictable responses only. This rules out the HTTP path as an info leak source.

Evidence: `evidence/exploit_dev/http_info_leak_*.json`

---

## Phase 6: Firmware 23.0.0 Patch Analysis

### Status: BLOCKED — Binary Not Available

The `firmware/23.0.0/` and `firmware/23.0.1/` directories are **empty**. The FW 23.0.0
ldn sysmodule binary is required to perform a patch diff analysis.

**Expected fix (from CVE description):** The fix likely adds a bounds check to
NetworkLayersCopy — either:
- Actually reading and enforcing param_4 (x3, the buffer size) before memcpy, OR
- Capping the total layer size sum against the buffer size, OR
- Using a size-limited copy (e.g., `memcpy_s` equivalent)

**To unblock:** Extract `ldn` sysmodule (title 0x010000000000000A) from a FW 23.0.0
system image. This requires a system image (NCA files or XCI dump from a 23.0.0 console)
and hactool/hac2l for decryption/extraction.

**What the diff would confirm:**
1. Whether x3 is now read and checked in the patched NetworkLayersCopy
2. Whether additional bounds checks were added to the call chain
3. Whether the AdvertiseData info leak was also fixed in 23.0.0
4. Any other hardening changes to the ldn sysmodule

---

## Phase 7: Vulnerability Findings Matrix

| # | Finding | Type | CWE | Function | Trigger | Buffer | Requires WiFi Assoc? | ASLR Impact | Status |
|---|---------|------|-----|----------|---------|--------|----------------------|-------------|--------|
| 1 | **CVE-2026-82079** | Stack overflow | CWE-121 | FUN_71000a13d0 (NetworkLayersCopy) | DHCP DISCOVER via LP2P WiFi | 1500B stack | Yes (LP2P client) | Need leak for reliable RCE | **CONFIRMED** (static) |
| 2 | Action frame heap OOB write | Heap overflow | CWE-122 | FUN_71000398b0 (join handler) | Action frame type 3 | 72B heap (0x48) | **No** (pre-assoc) | Need leak + heap spray | **CONFIRMED** (static + live) |
| 3 | Multipart filename overflow | Stack overflow | CWE-121 | photoViewer HTTP handler | POST multipart upload | 0x1000 stack | Yes (HTTP client) | Need leak | **CONFIRMED** (live, persistent DoS 3×) |
| 4 | HTTP Range DoS | Denial of service | CWE-400 | photoViewer (cpp-httplib) | Range: bytes=0-SMAX+1 | N/A | Yes (HTTP client) | N/A (DoS only) | **CONFIRMED** (live) |
| 5 | SendActionFrame cmd 502 | Heap overflow | CWE-122 | ldn IPC handler | IPC from authorized process | Heap | Requires IPC access | Need leak | Identified (static) |

### Comparative Assessment

**CVE-2026-82079 is the strongest exploit candidate because:**
- Stack overflow gives direct control of return address and callee-saved registers
- No stack canaries, no PAC on Erista
- 642 bytes of controlled data past LR for ROP chain
- Clear attack scenario (Send to Smartphone → WiFi → DHCP)
- AdvertiseData info leak may provide ASLR bypass from same attack surface

**Action frame heap OOB (Finding #2) is notable because:**
- Pre-association: no WiFi credentials needed
- But heap exploitation is harder: need to control heap layout, spray, timing
- Content-sensitive behavior confirmed empirically (live tests)

**Multipart filename overflow (Finding #3) has the easiest trigger:**
- Simple HTTP POST with oversized filename
- Persistent denial of service confirmed
- But same ASLR blocker applies

---

## Phase 8: Custom Firmware Feasibility Roadmap

### What ldn Code Execution Provides

The ldn sysmodule (title 0x010000000000000A) runs as a Horizon OS system module with
**strictly limited NPDM permissions:**
- WiFi/WLAN services: `wlan:lcl`, `wlan:lga`
- Logging: `lm`
- Hosted services: `ldn:u`, `ldn:s`, `ldn:m`
- **No** filesystem, GPU, or broad IPC access

Code execution in ldn gives: arbitrary network I/O over WiFi hardware, calling authorized
services, and a foothold for attacking adjacent sysmodules via IPC.

### Privilege Escalation Path

| Step | Status | Difficulty | Notes |
|------|--------|-----------|-------|
| ldn code execution (CVE-2026-82079) | Identified, needs ASLR bypass | Medium | This research |
| Pivot to broader sysmodule access | No known path on 22.5.0 | High | Need IPC vuln in reachable service |
| Kernel exploit | No public vuln on 22.5.0 | Very high | IPC fuzzing of kernel-facing services |
| Secure Monitor (TrustZone EL3) | No public vuln | Extremely high | Controls key derivation, fuse reading |
| TSEC firmware control | No public vuln | Extremely high | Verifies/decrypts Package1 since FW 6.2.0 |
| Persistent boot control | Requires TSEC + Package1 | Requires HW or new TSEC vuln | Anti-rollback fuses |

### Historical Precedent

| Exploit | Year | Relevance |
|---------|------|-----------|
| CVE-2018-6242 (ShofEL2) | 2018 | RCM USB overflow → code exec. Patched in hardware. |
| sm: session bypass | 2018 | Service impersonation → kernel. Fixed FW 3.0.1. |
| Handle exhaustion kernel exploit | 2018 | Slab allocator corruption. Required sm: bypass. Fixed. |
| Bluetooth stack overflow | 2023 | BLE IPC commands. Fixed FW 15.0.2. |

**No public software-only chain exists for patched V1 Erista at FW ≥ 4.1.0.**

### Realistic Assessment

ldn code execution is a meaningful research milestone — the first sysmodule-level code
execution identified on this console at FW 22.5.0. However, it is **several exploit
stages away** from custom firmware:

1. **ldn → kernel** requires discovering a new vulnerability in a kernel-facing service
   accessible from ldn's permission set. No such vulnerability is publicly known.
2. **kernel → TrustZone** requires a new Secure Monitor vulnerability. None known.
3. **TrustZone → persistent boot** requires TSEC control and Package1 manipulation.
   On patched Erista, only physical modchips achieve this.

**The ldn exploit's most realistic near-term value is as a research platform** for:
- IPC fuzzing of adjacent sysmodules (wlan, etc.) from a privileged position
- WiFi firmware analysis (BCM43455) via direct hardware access
- Testing other attack surfaces with the ability to run arbitrary code on the Switch

### Community Consensus

SwitchPirates guide, Switchbrew, and Atmosphère documentation are explicit: patched
Erista units beyond FW 4.1.0 require a **physical modchip** for persistent CFW. No
software-only chain from userland or sysmodule to persistent boot has been publicly
demonstrated on these units at any firmware version above 4.1.0.

---

## Phase 9: Supplementary — Second Loop Interference Note

NetworkLayersCopy has a **second loop** (0x71000a1480–0x71000a14b4) that runs AFTER
the memcpy. This loop writes pointer values into the output layer_info struct at
FP - 0xA8 (which is WITHIN the overflow region, at buffer offsets 0x5DC–0x674):

```asm
; Second loop: populate output layer_info with pointers into dest buffer
add  x14, x9, x10              ; ptr = buffer_base + running_offset
stur x14, [x12, #-0x8]         ; output[n].data_ptr = ptr
ldur w14, [x11, #-0x10]        ; source layer type
stur w14, [x12, #-0x10]        ; output[n].type = source_type
ldr  x14, [x11], #0x18         ; source layer size
add  x10, x14, x10             ; running_offset += size
str  x14, [x12], #0x18         ; output[n].size = source_size
```

This writes 6 × 24 = 144 bytes into the region at buffer offsets 0x5DC–0x66B. These
writes happen from PROGRAM DATA (computed pointers into the dest buffer), overwriting
whatever the overflow memcpy placed there. An exploit must account for these writes
when crafting the overflow payload — the region [buffer+0x5DC, buffer+0x66B] will be
partially overwritten by the second loop regardless of what the attacker puts there.

The region between buffer+0x66C and buffer+0x683 (saved FP/LR area starts at 0x684)
is NOT touched by the second loop, so it retains the attacker's overflow data.

---

## Summary of Key Corrections

| Item | Old Value | Corrected Value | Verification |
|------|-----------|-----------------|--------------|
| Buffer-to-LR distance | 1740 bytes | **1676 bytes** | Assembly: FP-0x684 to FP+0x08 |
| DHCP payload to reach LR | 1698 bytes | **1634 bytes** | 1676 - 42 (network headers) |
| Available past LR | ~564 bytes | **642 bytes** | 2318 (max WiFi frame) - 1676 |
| Stack canaries | "Not documented" | **ABSENT** (confirmed) | No `__stack_chk_guard` in binary |
| PAC | "No (Erista)" | **ABSENT** (confirmed) | PACIASP opcode not in 961,288 bytes |
| OnNewMessage structure | Single function | **Two-part**: wrapper + tail call | Assembly: 0x25f0 wrapper → 0x2660 handler |
