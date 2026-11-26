# CVE-2026-82079 — Stack Buffer Overflow in DHCP Server NetworkLayersCopy

> **Status: CONFIRMED by static analysis.** The vulnerable function has been identified
> as FUN_71000a13d0 ("NetworkLayersCopy"), called from FUN_71000a25f0 ("OnNewMessage"
> / DhcpManager event coordinator). The buffer size parameter is passed but never
> checked — a classic unused-safety-argument bug.
>
> **Previous note:** Earlier sessions (4 total) marked this SUPERSEDED after failing
> to find the stack overflow. Those sessions analyzed the DHCP option parsing path
> (FUN_71000a1ed0 / OnBootProtocolRequestPacket), which IS properly bounded. The actual
> vulnerability is in the event coordinator's frame reassembly, not in option parsing.

## Summary

**Stack-based buffer overflow in the lp2p DHCP server** within the Nintendo Switch
`ldn` sysmodule. The DHCP server event coordinator (`OnNewMessage`) allocates a
1500-byte stack buffer and calls `NetworkLayersCopy` to reassemble the parsed
network layers (Ethernet + IP + UDP + DHCP) into it. The function accepts a buffer
size parameter but **never reads it** — it computes the total layer size from the
parsed packet structure and performs an unbounded memcpy.

- **CVE**: CVE-2026-82079
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS 4.0**: 7.0 (High), AV:A/AC:L/PR:N/UI:P
- **Discoverer**: moehw
- **HackerOne**: H1:3770768 ("Remote stack buffer overflow in the LDN/LP2P DHCP server leads to control-flow hijack")
- **Reported**: 2026-05-30
- **Fixed**: FW 23.0.0 (2026-09-10)
- **Disclosed**: 2026-10-15 (Switchbrew)

## Vulnerable Function

**FUN_71000a13d0** ("NetworkLayersCopy") at file offset `0xa13d0` in `ldn` sysmodule
(FW 22.5.0, SHA-256: `91bee792da7c8ca7718bac166009331cd14ecdcc662c9fcf52f435da0d56f34a`).

### Calling convention (AArch64)

| Register | Parameter | Value at call site | Used in function? |
|----------|-----------|-------------------|-------------------|
| x0 | param_1: dest layer info | &local_e8 (output structure) | YES |
| x1 | param_2: layer count | 6 | YES |
| x2 | param_3: dest buffer | auStack_6c4 (1500-byte stack buf) | YES (memcpy dest) |
| **x3** | **param_4: buffer size** | **0x5dc (1500)** | **NO — DEAD PARAMETER** |
| x4 | param_5: source layer info | parsed packet structure | YES |
| x5 | param_6: source layer count | varies | YES |

### The bug (assembly at 0x71000a1430–0x71000a1470)

```asm
; First loop: sum all layer sizes into x8
mov     x8, xzr                    ; total = 0
add     x9, x4, #0x10              ; x9 = &source_layers[0].size
mov     w10, #1                     ; counter = 1
.loop:
ldr     x11, [x9], #0x18           ; x11 = layer_size; x9 += 24
cmp     x1, w10, UXTW              ; compare count with counter  
add     w10, w10, #1
add     x8, x11, x8                ; total += layer_size
b.hi    .loop

; THE OVERFLOW: memcpy with computed size, no bounds check
ldr     x9, [x4, #0x8]             ; x9 = source data pointer
mov     x0, x2                      ; dest = stack buffer (1500 bytes)
mov     x2, x8                      ; size = total (UNCHECKED against x3!)
mov     x1, x9                      ; src = packet data
bl      memcpy                      ; 0x71000a1470 → 0x71000a35c0
```

**x3 (buffer size = 0x5dc) is never referenced by any instruction in the function.**

## Call Chain

```
BPF socket read (FUN_71000a0d40, "OnFileRead")
  → read(fd, global_buf_4096, bpf_buflen)       ; up to 4096 bytes
  → FUN_71000a1640 ("OnEthernetPacket")          ; strips 14-byte Ethernet header
    → FUN_71000a17e0 ("OnInternetPacket")        ; validates IP header + checksum
      → FUN_71000a1a50 ("OnUserDatagramPacket")  ; validates UDP header + checksum
        → FUN_71000a1ed0 ("OnBootProtocolRequestPacket")  ; validates DHCP, iterates options
          → SendDhcpPacketEvent dispatched (event code 0x65)
            → FUN_71000a25f0 ("OnNewMessage" / DhcpManager coordinator)
              → FUN_71000a13d0 ("NetworkLayersCopy")  ← OVERFLOW HERE
                → memcpy(stack_buf_1500, packet_data, total_layers_size)
              → FUN_710009ec20 ("CopyOptionValue") — extracts message type (safe, has bounds check)
              → FUN_71000a29b0 ("OnDhcpDiscover") — message type 1
              → FUN_71000a2f00 — message type 3 (DHCP REQUEST)
              → FUN_71000a3150 — message type 8 (DHCP INFORM)
              → FUN_71000a2e10 — message type 4 (DHCP DECLINE)
              → FUN_71000a3270 — message type 7 (DHCP RELEASE)
              → FUN_71000a2bb0 ("SendDhcpResponse") — builds and sends reply
```

## Stack Layout in FUN_71000a2660 (inner handler, tail-called from FUN_71000a25f0)

**Assembly-verified prologue (0x71000a2660):**
```asm
stp  x29, x30, [sp, #-0x40]!     ; SP -= 0x40; save FP at [SP], LR at [SP+8]
stp  x28, x23, [sp, #0x10]       ; save callee-saved regs
mov  x29, sp                      ; FP = SP (= SP_entry - 0x40)
stp  x22, x21, [sp, #0x20]
stp  x20, x19, [sp, #0x30]
sub  sp, sp, #0x6c0               ; allocate 1728 bytes for locals
```

**Corrected frame layout** (addresses relative to FP, verified from assembly):
```
FP - 0x6C0: SP (bottom of local space)
  ... 0x3C bytes of small locals (60 bytes) ...
FP - 0x684: buffer start [1500 bytes]       ← OVERFLOW DEST (add x0, sp, #0x3c)
  ... 0x5DC bytes (1500) ...
FP - 0x0A8: layer_info output struct         ← param_1 of NetworkLayersCopy (sub x0, x29, #0xa8)
  ... 6 entries × 24 bytes = 144 bytes ...
FP - 0x018: remaining locals
  ... 24 bytes ...
FP + 0x000: saved FP (x29)                  ← overwritten at buffer+1668
FP + 0x008: saved LR (x30)                  ← RETURN ADDRESS (buffer+1676)
FP + 0x010: saved x28, x23                  ← controlled registers (buffer+1684)
FP + 0x020: saved x22, x21                  ← controlled registers (buffer+1700)
FP + 0x030: saved x20, x19                  ← controlled registers (buffer+1716)
FP + 0x040: caller's frame
```

**Overflow geometry (CORRECTED — resolves 1698/1740 discrepancy):**
- Buffer start: FP - 0x684 (Ghidra: SP_entry - 0x6C4)
- Buffer end: FP - 0x684 + 0x5DC = FP - 0x0A8
- Saved LR: FP + 0x008
- **Bytes from buffer start to saved LR: 0x684 + 0x8 = 0x68C = 1676 bytes**
- Bytes of controlled data to reach LR: 1676 (Ethernet + IP + UDP + DHCP payload)
- Net DHCP payload to reach LR: 1676 - 42 (headers) = 1634 bytes
- Net DHCP options to reach LR: 1634 - 236 (BOOTP fixed) = 1398 bytes

**Previous estimates were wrong:**
- "1740 bytes" error: used Ghidra's SP_entry-relative offset (0x6C4) as FP-relative,
  then added +8 for LR. Correct FP-relative offset is 0x684 (= 0x6C4 - 0x40).
- "1698 bytes" error: 1740 minus headers, propagating the base error.

## Sizes and Limits

| Component | Size | Source |
|-----------|------|--------|
| BPF read buffer | 4096 bytes (0x1000) | Global at 0x71002160af, memset at FUN_71000a0d40 |
| Stack buffer | 1500 bytes (0x5dc) | `add x0, sp, #0x3c` + `mov w2, #0x5dc` at 0x71000a2688 |
| WiFi 802.11 max MSDU | 2304 bytes | IEEE 802.11-2020 §9.2.3 |
| Max Ethernet frame (WiFi) | 2318 bytes | 14 (Ethernet hdr) + 2304 (MSDU) |
| Buffer-to-LR distance | **1676 bytes** (0x68C) | Assembly-verified: FP-0x684 to FP+0x08 |
| DHCP payload to reach LR | 1634 bytes | 1676 - 14(eth) - 20(ip) - 8(udp) |
| DHCP options to reach LR | 1398 bytes | 1634 - 236 (BOOTP fixed fields) |
| Available past LR (WiFi) | **642 bytes** | 2318 - 1676; includes 48B callee-saved regs |

## Why Previous Analysis Missed This

Previous sessions focused on the DHCP option parsing path (FUN_71000a1ed0), which
processes individual TLV options and correctly bounds-checks iteration with
`pcVar4 < param_4 + param_5`. This led to the conclusion "DHCP code proven clean."

The actual overflow is NOT in option parsing — it's in the **event coordinator's
frame reassembly** that happens BEFORE option extraction. The coordinator copies
the ENTIRE raw frame (all network layers concatenated) into a stack buffer for
further processing. The option parser runs on the reassembled copy.

## Exploitation Properties

**On FW 22.5.0 (Erista) — all verified from binary analysis:**
- **No stack canaries:** No `__stack_chk_guard` string in entire binary (search_strings).
  No canary load/check in FUN_71000a2660 prologue/epilogue.
- **No PAC:** PACIASP opcode (`0x7f2303d5`) absent from all 961,288 bytes (search_bytes).
  No PACIASP/AUTIASP in any function prologue/epilogue in the entire binary.
- **ASLR:** ~17 bits entropy, 2 MiB alignment (Switchbrew Memory_layout). `csrng` CSPRNG
  since FW 15.0.0. 131,072 possible bases.
- **NX (W^X):** Yes — no shellcode, ROP required.
- **No automatic crash recovery** for DHCP server thread.
- **Full byte control:** DHCP payload allows arbitrary bytes 0x00–0xFF.
- **Callee-saved register control:** Overflow past LR controls x28, x23, x22, x21, x20, x19
  (restored by epilogue `ldp` sequence). These persist across function calls → useful as
  ROP gadget parameters.

**Attack scenario:**
1. Switch user opens "Send to Smartphone" (or starts Mario Kart Live)
2. Switch creates LP2P WiFi AP and starts DHCP server thread
3. Attacker scans QR code or manually connects to the WiFi AP
4. Attacker sends crafted DHCP DISCOVER with >1676 bytes total frame data
5. BPF socket delivers the frame to the protocol stack
6. OnNewMessage calls NetworkLayersCopy → memcpy overflows 1500-byte stack buffer
7. Attacker controls saved LR at byte 1676 → code execution in ldn sysmodule context
8. Callee-saved registers (x19–x23, x28) controlled by bytes 1684–1731

**ASLR bypass needed:** The main remaining obstacle. Potential approaches:
- **AdvertiseData stack info leak** (Switchbrew, yellows8 credit): uninitialized stack data
  from ldn sysmodule leaks in LP2P scan responses. Fix version may be 23.0.0+, meaning
  FW 22.5.0 is likely affected. Would directly reveal ldn module base. Needs empirical
  confirmation.
- Brute force: 131,072 attempts, impractical without auto-restart of DHCP server.
- Heap metadata leak through DHCP response timing: not investigated.

## Relationship to Other Findings

| Finding | Type | Function | Status |
|---------|------|----------|--------|
| **CVE-2026-82079 (this)** | Stack overflow | FUN_71000a13d0 | CONFIRMED (static) |
| Heap OOB write (action frame type 3) | Heap overflow | FUN_71000398b0 | Confirmed (static) |
| SendActionFrame cmd 502 | Heap overflow | (IPC handler) | Identified (static) |
| Multipart filename overflow | Stack overflow | photoViewer | Confirmed (live) |

## Evidence

- Binary: `firmware/ldn_22.5.0/main.flat.bin` (SHA-256: 91bee792...)
- Vulnerable function: FUN_71000a13d0 at offset 0xa13d0 (252 bytes)
- memcpy call: instruction at 0x71000a1470
- Dead parameter: x3 (buffer size) never referenced in function body
- Caller: FUN_71000a25f0 at offset 0xa25f0 (stack frame ~0x700 bytes)
- BPF read: FUN_71000a0d40 reads up to 4096 bytes into global buffer
