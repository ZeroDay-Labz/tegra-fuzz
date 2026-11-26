# LDN Parser Vtable Analysis — Verified Disassembly

**Binary**: main.flat.bin (ldn sysmodule, FW 22.5.0)
**SHA-256**: 91bee792da7c8ca7718bac166009331cd14ecdcc662c9fcf52f435da0d56f34a
**Tool**: Ghidra 12.1.3 + Capstone (AArch64)
**Date**: 2026-11-24

## Parser Factory (FUN_7100044120)

Three vtable types, allocated based on factory config and param_2:

| Condition | Alloc Size | Vtable Record | Vtable PTR |
|-----------|-----------|---------------|------------|
| factory[2]==1 OR param_2==3 | 0x48 (72 B) | 0x71000e2358 | 0x71000e2368 |
| param_2==1∨2, sec_mode==2 | 0x5D8 (1496 B) | 0x71000e23e8 | 0x71000e23f8 |
| param_2==1∨2, sec_mode==3 | 0x5D8 (1496 B) | 0x71000e2478 | 0x71000e2488 |

## Type 1 Parser Layout (0x48 bytes)

```
+0x00: vtable pointer (8 bytes)
+0x08: parsed header fields (~56 bytes, set by FUN_7100046690)
+0x40: raw frame data pointer (8 bytes, set by FUN_71000456b0)
+0x48: END OF ALLOCATION
```

## Stack Overflow Path (CVE-2026-82079 / CWE-121)

### Call Chain

```
FUN_71000398b0 (join handler)
  → allocates local_998 (0x798 bytes ON STACK)
  → FUN_7100044120 → creates parser (stored at param_1+0x12310)
  → FUN_710003c6b0 (ring buffer reader, 500ms timeout)
    → FUN_710003b470 (frame extractor)
      → parser->vtable[4] (get_size)  → returns attacker-controlled size
      → parser->vtable[3] (get_ptr)   → returns attacker-controlled data ptr
      → memcpy(stack_buf + 0x78, data_ptr, size)
```

### Type 1 Payload Size Getter — Capstone-verified

Thunk at 0x7100044ce0:
```asm
add  x0, x0, #0x40          ; adjust this → parser+0x40
b    #0x7100045cb0           ; tail-call implementation
```

Implementation at 0x7100045cb0:
```asm
ldr  x8, [x0]               ; x8 = *(parser+0x40) = frame_data_ptr
ldrh w8, [x8, #0x1da]       ; w8 = LE16(frame_data[0x1DA])
rev  w8, w8                  ; byte-reverse (BE→LE conversion)
lsr  w0, w8, #0x10          ; extract upper 16 bits
ret                          ; return BE16(frame_data[0x1DA])
```

**Result**: Returns `BE16(body[0x1DA:0x1DC])` — DIRECTLY attacker-controlled.

### Type 1 Payload Pointer Getter — Capstone-verified

Thunk at 0x7100044cd0:
```asm
add  x0, x0, #0x40
b    #0x7100045d70
```

Implementation at 0x7100045d70:
```asm
ldr  x8, [x0]               ; x8 = *(parser+0x40) = frame_data_ptr
add  x0, x8, #0x1dc         ; return frame_data + 0x1DC
ret
```

**Result**: Returns `&body[0x1DC]` — attacker-controlled data.

### Overflow Arithmetic

- Stack buffer: 0x798 bytes (allocated as local_998 in FUN_71000398b0)
- Memcpy destination: stack_buf + 0x78 (param_1 + 0xf, where param_1 is long*)
- Available space: 0x798 - 0x78 = **0x720 (1824 bytes)**
- Copy size: BE16(body[0x1DA:0x1DC]) — 16-bit, max 0xFFFF
- **Stack overflow when BE16(body[0x1DA]) > 0x720**
- Overflow extent: min(size, available_data) - 0x720 bytes past stack buffer

### Frame Construction for Stack Overflow

```python
# Current test frames (DO NOT overflow stack):
struct.pack_into(">H", body, 0x1DA, 0x0100)  # size = 256 < 1824

# To trigger stack overflow:
struct.pack_into(">H", body, 0x1DA, 0x0721)  # size = 1825 → 1-byte overflow
struct.pack_into(">H", body, 0x1DA, 0x0800)  # size = 2048 → 224-byte overflow
struct.pack_into(">H", body, 0x1DA, 0xFFFF)  # max → depends on available data
```

## Type 3 Parser (0x5D8 bytes) — Different Mechanism

Thunks add 0x5D0 (not 0x40), and implementations use indexed table lookup:

Size getter (0x71000460F0):
```asm
ldr    x8, [x0]             ; x8 = *(parser+0x5D0)
mov    w9, #0x30             ; entry size = 48
ldrsb  x10, [x8, #0x27]     ; x10 = signed index from ptr+0x27
smaddl x8, w10, w9, x8      ; x8 = ptr + index * 48
ldrh   w8, [x8, #0x28]      ; load size from entry+0x28
rev    w8, w8                ; BE conversion
lsr    w0, w8, #0x10
ret
```

Ptr getter (0x7100046290):
```asm
ldr    x8, [x0]
mov    w9, #0x30
ldrsb  x10, [x8, #0x27]
smaddl x8, w10, w9, x8
add    x0, x8, #0x2a         ; return ptr + index*48 + 0x2A
ret
```

Type 3 uses a table of 0x30-byte entries, indexed by a signed byte at ptr+0x27.
Size and data pointer are relative to the selected entry.

## Main Event Loop Architecture (FUN_7100035f60)

The ldn sysmodule's main thread dispatches on 5 event sources:

| Event Offset | Source | Handler |
|-------------|--------|---------|
| 0x810 | IPC server commands | FUN_7100036230 |
| 0x850 | Timer | FUN_71000363e0 |
| 0x798 (queue) | IPC message queue | **FUN_7100036560** (IPC dispatcher) |
| 0x890 | Ring buffer 1 (0x30f8) | Type 0x101 → **FUN_710003e3d0** |
| 0x8d0 | Ring buffer 2 (0x91f8) | Type 0x03 → FUN_710003dcc0, Type 0x02 (state==3) → FUN_710003ddc0 |

**KEY**: Ring buffers 1 & 2 receive data from wlan/hardware asynchronously (NOT through IPC).
The IPC handlers (cases 7, 0xf) also read from ring buffer 1 SYNCHRONOUSLY during operations.
The vulnerable FUN_710003b470 is ONLY reached through IPC-initiated paths (cases 7, 0xf),
NOT through the direct ring buffer event handlers.

## IPC Dispatcher Mapping (FUN_7100036560)

Case 7 → FUN_7100037dc0 (scan results): calls FUN_710003b470 with CALLER-PROVIDED buffer.
Case 8 → FUN_7100038410 (25k code units): session data SET handler, ANALYZED.
  - Does NOT call FUN_710003b470 (vulnerable memcpy)
  - Processes 0x508-byte IPC buffer as structured session config
  - 24 indirect vtable calls (plVar18+0x38, +0x60, +0x90, etc.)
  - Entry checks: session match (0x920) and state==2 (0x968)
  - FUN_710003b9f0 (9740 units) is largest callee, also no vuln memcpy
  - Conclusion: application-level config handler, not a WiFi frame processor
Case 0xf → FUN_71000398b0 (join): calls FUN_710003b470 with STACK buffer.

FUN_710003b470 callers (complete list):
1. FUN_710003c6b0 — from join handler (case 0xf), stack destination, single call
2. FUN_7100037dc0 — from scan results (case 7), caller buffer destination
3. FUN_710003cb50 — from join handler (case 0xf), **peer discovery LOOP**
   - Caller-provided buffer from join handler
   - Loops until match or timeout (param_7 iterations)
   - Vulnerable memcpy fires BEFORE peer validation checks
   - Multiple overflows possible from single join operation
   - Uses same parser at *(param_1 + 0x12310)

Parser factory (FUN_7100044120) has ONLY ONE caller: FUN_71000398b0 (case 0xf).

## Live Test Results (2026-11-24)

### METHODOLOGY INVALIDATED — Frame injection failure

**All nl80211 CMD_FRAME tests returned -107 (ENOTCONN).** No frames were transmitted
over the air. Linux kernel rejects CMD_FRAME on STA-mode interfaces for action frames.
This was confirmed by frame_path_mapper.py testing 15 frame variations across 4 groups.

**Prior conclusions withdrawn:**
- Stack overflow threshold test: INVALID (frames never reached Switch)
- Observed HTTP unavailability: NOT caused by injected frames
- Differential probe results: INVALID basis for reachability conclusions

**To perform actual frame injection:**
- Monitor-mode interface with TX injection (radiotap raw sockets), OR
- P2P-GO/AP-mode interface where CMD_FRAME is permitted, OR
- Off-channel TX with appropriate interface setup

### Likely explanation
Our frames are processed by wlan/lp2p BEFORE reaching the ldn IPC dispatcher.
The ldn sysmodule's IPC handlers (cases 7 and 0xf) are triggered by APPLICATION
requests (scan/join), not by incoming WiFi frames. The observed HTTP unavailability
originates in a different component.

## Direct Ring Buffer Handler Analysis

### FUN_710003e3d0 (Ring Buf 1, Type 0x101, State==5)
- Guards: state==5, 6-byte MAC check, vtable[2] returns 0, 32-byte session ID match
- Calls vtable[11](parser, &stack_buf, 8) to fill 0x580-byte stack buffer (8×0xb0 entries)
- Then indexes entries by `param_1[0x9c0] * 0xb0`
- Calls FUN_710003d050 (9 unresolved indirect calls) on match
- Stack overflow potential: depends on vtable[11] respecting entry count limit

### FUN_710003dcc0 (Ring Buf 2, Type 0x03, State==5) — CLEAN
- Guards: state==5, 6-byte MAC check against peer at param_1+0xa48
- Parses frame with FUN_7100047020, extracts disconnect reason code
- Calls FUN_710003a610 (disconnect handler) with reason code
- No memcpy, no large buffers — this is a simple disconnect notification handler

### FUN_710003ddc0 (Ring Buf 2, Type 0x02, State==3)
- Guards: state==3, 6-byte MAC check against peer at param_1+0xa48
- Calls FUN_710003e020 (frame parser) then builds response via vtable chain
- Response sent via vtable[30] on session object at param_1+0x938
- **This is the connected-state data handler**: processes peer frames during active sessions

### FUN_710003e020 (Type 0x02 Frame Parser)
- Called from FUN_710003ddc0 (type 0x02 handler)
- Initializes parser via FUN_7100042520 + FUN_7100042530
- Multiple validation stages: frame parse → field extract → session match → peer lookup
- **Notable**: `thunk_FUN_71000a8540(lVar9+200, &local_3b0, 0x300)` — fixed 0x300-byte memcpy
  from stack to heap peer entry. Stack buffer filled by parser vtable[5].
- 14 unresolved vtable calls on parser object
- Reachable directly from WiFi through ring buffer 2 (no IPC required)

### Attack Model (CVE-2026-82079)
1. Attacker broadcasts malicious LP2P frames as spoofed game host
2. Victim opens game → app calls IPC join (case 0xf)
3. Join handler reads ring buffer 1 synchronously → gets attacker's frame
4. FUN_710003b470 memcpy overflows 0x798-byte stack buffer
5. FUN_710003cb50 loops = multiple overflows from one join

## Relationship Summary

| Finding | Mechanism | Evidence Level |
|---------|-----------|---------------|
| CVE-2026-82079 (CWE-121) | Stack overflow in FUN_710003b470 memcpy | **Confirmed by static analysis** — attacker-controlled size to stack buffer |
| Same memcpy (case 7) | Buffer overflow in caller-provided buffer | **Confirmed by static analysis** — same FUN_710003b470, different destination |
| LDN-HEAP-OOB-001 | Body copy to parser+0x5C | **NOT CONFIRMED** for type 1 parser — body is referenced by pointer, not copied |
| Live test behavior | Unknown mechanism | **Observed but NOT in ldn** — HTTP unavailability; no correlation with ldn overflow threshold |
