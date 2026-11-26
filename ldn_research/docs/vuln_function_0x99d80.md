# [SUPERSEDED] CVE-2026-82079: BuildVendorIE Analysis

> **This document is SUPERSEDED.** The BuildVendorIE exploitation model was
> invalidated on 2026-11-23. vtable[4] performs fixed-size AES-128 encryption,
> not a variable-length memcpy. See [../TECHNICAL_REPORT.md](../TECHNICAL_REPORT.md)
> for the current exploitation model (action frame type 3 heap overflow).
>
> This document is preserved as research history.

## Function: 0x99d80 (lp2p Vendor-Specific IE Builder)

**Binary**: `ldn_research/firmware/ldn_22.5.0/main.flat.bin`
**Address**: 0x99d80 (288 bytes, 0x99d80 - 0x99e9c)
**Status**: Ghidra MISSED this function (not in procedure list)

## Stack Layout
```
Stack frame: 0x170 (368 bytes)
sp+0x00 - sp+0x0B : unused/alignment
sp+0x0C            : IE type (0xDD = Vendor Specific)
sp+0x0D            : IE total length ((data_len + 5) & 0xFF)
sp+0x0E - sp+0x11  : OUI (00:22:AA) + IE subtype (0x06) [Nintendo lp2p]
sp+0x12            : subtype flag (index != 0 ? 1 : 0)
sp+0x13 - sp+0x10C : DATA PAYLOAD (250 bytes designed, 253 to x29)
sp+0x110           : x29 (frame pointer) ← OVERFLOW TARGET
sp+0x118           : x30 (return address) ← OVERFLOW TARGET
sp+0x120           : x28
sp+0x130           : x26, x25
sp+0x140           : x24, x23
sp+0x150           : x22, x21
sp+0x160           : x20, x19
sp+0x170           : caller's SP
```

## Vulnerability Details
```c
// Pseudocode of the vulnerable path:
void build_vendor_ie(object *self, int index, void *data, size_t length) {
    char ie_buf[7 + 250];  // at sp+0x0C, 257 bytes intended

    ie_buf[0] = 0xDD;                          // Vendor Specific IE type
    ie_buf[1] = (uint8_t)(length + 5);          // BUG: truncates to byte!
    *(uint32_t*)&ie_buf[2] = 0x06AA2200;        // OUI 00:22:AA + type 06
    ie_buf[6] = (index != 0) ? 1 : 0;           // subtype

    // Zero-pad remainder (defensive but insufficient)
    size_t pad = (length > 249) ? 0 : (250 - length);
    memset(&ie_buf[7] + length, 0, pad);

    // *** THE BUG: NO BOUNDS CHECK ON length ***
    memcpy(&ie_buf[7], data, length);  // 0x99e2c: bl memcpy

    // Send frame via IPC
    send_vendor_ie(slot, 3, &ie_buf, (length + 5) & 0xFF);
}
```

## Overflow Arithmetic
- Buffer payload start: sp + 0x13
- x29 location: sp + 0x110
- Distance: 0x110 - 0x13 = 0xFD = **253 bytes**
- x30 location: sp + 0x118
- Distance to x30: 0x118 - 0x13 = 0x105 = **261 bytes**

## Crash Boundary Match
- vendor_class=221 → total_options≈253 → exact fit → NO crash
- vendor_class=222 → total_options≈254 → overflow 1 byte → CRASH
- vendor_class=255 → total_options≈287 → overflow 34 bytes = MAX
- NM overhead ≈ 32 bytes of additional DHCP options

## Why NM-only
- NetworkManager adds ~32 bytes of additional DHCP options (hostname, client-id,
  parameter request list) beyond the vendor-class-identifier
- Raw DHCP clients send fewer options → total stays under 253 → no overflow
- The exact overhead depends on NM's configuration (hostname length, etc.)

## Functions Called
- 0x7f540: Slot release (IPC virtual dispatch via vtable+0xD8)
- 0xa3740: memset (zero-pad buffer)
- 0xa35c0: memcpy thunk → 0xa8540 (THE OVERFLOW)
- 0x7f490: Send Vendor IE (IPC virtual dispatch via vtable+0xD0)
- 0x26c0: Abort/panic handler (error path)

## Class Identity (from RTTI)
- **Class**: `nn::lp2p::detail::Aes128GmacAdvertiseParser`
- **Base**: `nn::lp2p::detail::IAdvertiseParser`
- **Vtable**: 0xe78c0 (18 virtual methods, offset-to-top at 0xe78b0, RTTI at 0xe78b8)
- **Method index**: vtable[15] (offset 0x78 from vptr)
- **Sibling class**: `nn::lp2p::detail::PlaintextAdvertiseParser` (may share the same bug)
- **Builder counterpart**: `nn::lp2p::detail::Aes128GmacAdvertiseBuilder`

## Vtable at 0xe78c0 (all gap functions are methods of this class)
```
vtable[0]  = 0x021f0  (destructor/init)
vtable[1]  = 0x97db0
vtable[2]  = 0x97de0
vtable[3]  = 0x97ea0
vtable[4]  = 0x97eb0
vtable[5]  = 0x97fb0
vtable[6]  = 0x980b0
vtable[7]  = 0x980d0
vtable[8]  = 0x98100
vtable[9]  = 0x98310
vtable[10] = 0x98320
vtable[11] = 0x98790  ← GAP: SUB SP #0x170, ret at 0x98868
vtable[12] = 0x98880  ← GAP: SUB SP #0x1a0, ret at 0x9930c (1676B)
vtable[13] = 0x99320  ← GAP: SUB SP #0x140, memcpy at 0x99a20 (SAFE, bounded 63)
vtable[14] = 0x99c00  ← GAP: SUB SP #0x30, ret at 0x99d40
vtable[15] = 0x99d80  ← VULNERABLE: unbounded memcpy at 0x99e2c
vtable[16] = 0x99e80
vtable[17] = 0x99e90
```

## Data Flow (DHCP → Overflow)
```
1. Attacker sends DHCP DISCOVER with large vendor-class-identifier
2. nn::dhcps processes DISCOVER, extracts options (all safe)
3. FUN_00079480 (ActionAdvertise handler) queues advertise data
4. FUN_0006b0a0 stores data in ring buffer (0x928B entries, max 20)
5. nn::lp2p::SendThread dequeues and transmits
6. Virtual dispatch: IAdvertiseParser->vtable[15](this, index, data, length)
7. Aes128GmacAdvertiseParser::BuildVendorIE at 0x99d80
8. memcpy(sp+0x13, data, length) with NO bounds check → OVERFLOW
```

## Related lp2p Class Hierarchy
- nn::lp2p::detail::net::Wlan (WiFi interface)
- nn::lp2p::detail::net::ActionFrameReceiver/Transmitter
- nn::lp2p::detail::net::DataFrameReceiver/Transmitter
- nn::lp2p::detail::G2gPlaintextProtocol / G2gAes128GcmProtocol
- nn::lp2p::detail::Message (shared_ptr)
- nn::lp2p::StateMachine, IpcServer, RecvThread, SendThread

## Calling Convention
- x0: object pointer (vptr at [x0+0], data ptr at [x0+8])
- w1: slot index
- x2: data pointer (attacker-controlled DHCP option data)
- x3: data length (attacker-controlled, UNBOUNDED)
- Called via virtual dispatch: vtable[15] at offset 0x78 from vptr

## Exploitation Implications
With 34 bytes of overflow past the 253-byte buffer:
- Bytes 253-260: overwrite x29 (frame pointer, 8 bytes)
- Bytes 261-268: overwrite x30 (return address, 8 bytes)
- Bytes 269-276: overwrite x28 (8 bytes)
- Bytes 277-286: overwrite x26/x25 (10 bytes)

For 2-byte partial x30 overwrite (bypasses ASLR):
- vendor_class ≈ 230-231 bytes → overwrites x30 low 2 bytes
- Redirect to gadget 0x6078 (best printable: LDP x19-x28, sp+=96)
- Printable ASCII constraint: all overflow bytes must be 0x20-0x7E

## x30 Partial Overwrite Analysis
With a 2-byte partial overwrite, x30 becomes:
  (original_x30 & 0xFFFFFFFFFFFF0000) | our_2_bytes

Since ASLR is 2MB-aligned, the low 21 bits of any address are deterministic.
The 2-byte overwrite controls bits 15-0. Bits 20-16 remain from original x30.

This means the target gadget must be in the SAME 64KB-aligned region (bits 20-16
must match) as the original return address. Finding the caller is critical to
determine which gadgets are reachable.

The caller dispatches through vtable[15] from somewhere in .text. The return
address (x30) would be the instruction after the BLR. The caller is likely in
the SendThread's data processing loop or a related lp2p dispatch function.

**Strategy**: Use crash data to determine x30. When vendor_class=222 crashes
the process, the low byte of x29 is overwritten with 'A' (0x41). If we can
capture the crash report on Horizon OS, we get the original x30 value and can
select the correct gadget.

**Alternative**: Binary search with different fill characters at the x29
position to cause different crash addresses, narrowing down x30's 64KB page.

## Secondary Bug: Length Truncation
`strb w26, [sp, #0xd]` stores `(length + 5) & 0xFF` as the IE length field.
For length ≥ 251: wraps around (256 → 0, 257 → 1, etc.)
This causes the sender to transmit an IE with an incorrect length field.
