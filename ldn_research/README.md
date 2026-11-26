# Nintendo Switch WiFi / HTTP Security Research

Authorized owner research on the "Send to Smartphone" attack surface of a
Nintendo Switch HAC-001 (serial XAW4 001878), firmware 22.5.0.

## Attack Surface

When the Switch enters "Send to Smartphone" mode (Album → Send to Smartphone),
it creates an LP2P WiFi AP and runs:
- **HTTP server** on 192.168.0.1:80 (cpp-httplib based, in the photoViewer applet)
- **DHCP server** on 192.168.0.1 (subnet /24, no gateway/DNS)
- **LDN protocol** via WiFi action frames (ldn sysmodule)

## Findings

### 1. Multipart Filename Overflow — photoViewer (ACTIVE, most promising)

A stack buffer overflow in the HTTP server's multipart parser. Sending a POST
with a `Content-Disposition: filename="..."` exceeding ~4000 bytes overflows a
~4096-byte stack buffer and corrupts saved FP/LR.

| Property | Value |
|----------|-------|
| Binary | photoViewer applet (Title ID 010000000000100d) |
| Trigger | Single unauthenticated HTTP POST |
| Buffer | ~4096 bytes (stack-allocated `char buf[0x1000]`) |
| LR control | **CONFIRMED** — 2-byte partial overwrite tested |
| Stack canaries | **NONE** (confirmed via SDK toolchain analysis) |
| Persistent DoS | **CONFIRMED** (3x reproduced) |
| Code execution | Not yet — ASLR is the remaining blocker |

**Detailed analysis:** [docs/multipart_overflow_status.md](docs/multipart_overflow_status.md)  
**CVE writeup:** [CVE-multipart-crash.md](CVE-multipart-crash.md)  
**Scripts:** [scripts/multipart/](scripts/multipart/)

### 2. CVE-2026-82079 — ldn WiFi Stack Overflow (confirmed, harder to exploit)

Stack-based buffer overflow in the ldn sysmodule's DHCP/network layers, triggered
via LP2P WiFi action frames. Requires monitor-mode WiFi injection.

**Detailed analysis:** [docs/cve_2026_82079_analysis.md](docs/cve_2026_82079_analysis.md)  
**Technical report:** [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md)  
**Scripts:** [scripts/wifi/](scripts/wifi/), [scripts/exploit/](scripts/exploit/)

### 3. LDN Heap OOB Write (separate from CVE-2026-82079)

Out-of-bounds heap copy in the ldn join handler (FUN_71000398b0). Relationship
to CVE-2026-82079 unresolved.

**Detailed findings:** [FINDINGS.md](FINDINGS.md)  
**Scripts:** [scripts/heap/](scripts/heap/)

### 4. HTTP Range DoS (DoS only, closed)

`Range: bytes=0-9223372036854775808` causes HTTP unavailability (error 2162-0002).
cpp-httplib integer handling issue. No code execution path.

### 5. DHCP Investigation (closed — code proven clean)

ldn DHCP code proven clean across 4 test sessions. The vendor_class >= 222 crash
is pre-DHCP, not in the ldn DHCP handler.

## Documentation

### Top-Level Reports

| Document | Description |
|----------|-------------|
| [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) | Authoritative findings reference |
| [VULNERABILITY_RESEARCH_REPORT.md](VULNERABILITY_RESEARCH_REPORT.md) | Full vulnerability research report |
| [FINDINGS.md](FINDINGS.md) | Detailed experimental findings with evidence tables |
| [RESEARCH_JOURNAL.md](RESEARCH_JOURNAL.md) | Chronological history including superseded hypotheses |
| [RUNBOOK.md](RUNBOOK.md) | How to run the experiments |
| [CVE-2026-82079_POC.md](CVE-2026-82079_POC.md) | CVE-2026-82079 writeup |
| [CVE-multipart-crash.md](CVE-multipart-crash.md) | Multipart crash writeup |

### Deep Analysis (docs/)

| Document | Topic |
|----------|-------|
| [research_status.md](docs/research_status.md) | Master status across all exploitation paths |
| [multipart_overflow_status.md](docs/multipart_overflow_status.md) | photoViewer overflow — full technical deep-dive |
| [cve_2026_82079_analysis.md](docs/cve_2026_82079_analysis.md) | CVE-2026-82079 static analysis |
| [VTABLE_ANALYSIS.md](docs/VTABLE_ANALYSIS.md) | LDN parser vtable reverse engineering |
| [caller_stack_layout.md](docs/caller_stack_layout.md) | ARM64 stack frame geometry |
| [partial_lr_pivot_assessment.md](docs/partial_lr_pivot_assessment.md) | LR partial overwrite + stack pivot assessment |
| [aslr_bypass_analysis.md](docs/aslr_bypass_analysis.md) | ASLR bypass research |
| [http_server_analysis.md](docs/http_server_analysis.md) | HTTP server profiling and bug catalog |
| [kernel_escalation_chain.md](docs/kernel_escalation_chain.md) | Kernel escalation theory |
| [firmware_acquisition.md](docs/firmware_acquisition.md) | How firmware was obtained and decrypted |
| [pcap_analysis.md](docs/pcap_analysis.md) | Packet capture analysis |
| [phase_deliverables.md](docs/phase_deliverables.md) | CVE validation deliverables checklist |
| [evidence_reconciliation.md](docs/evidence_reconciliation.md) | **Evidence audit — separates confirmed from inferred findings** |
| [vuln_function_0x99d80.md](docs/vuln_function_0x99d80.md) | SUPERSEDED — BuildVendorIE analysis (invalidated) |

## Scripts (scripts/)

Organized by attack surface:

| Directory | Description | Status |
|-----------|-------------|--------|
| `multipart/` | photoViewer filename overflow exploit dev | **Active** |
| `http/` | HTTP server fuzzing, range probes, path traversal | Completed |
| `dhcp/` | DHCP overflow testing, stack mapping | Closed (clean) |
| `wifi/` | WiFi frame injection, LDN protocol fuzzing | On hold |
| `heap/` | Heap corruption probing, boundary testing | On hold |
| `exploit/` | CVE-2026-82079 exploit chain building | On hold |
| `recon/` | QR extraction, MITM, pcap parsing, DNS fuzzing | Completed |

## Networking

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.setsockopt(socket.SOL_SOCKET, 25, b'wlp5s0\0')  # SO_BINDTODEVICE required
s.connect(('192.168.0.1', 80))
```

## Firmware Binaries (gitignored)

Extracted from device, stored locally only:

| Binary | Path | Size | Notes |
|--------|------|------|-------|
| photoViewer 20.0.0 | `firmware/photoViewer_20.0.0/main.flat.bin` | 9.7 MB | HTTP server target, open in Ghidra |
| ldn 22.5.0 | `firmware/ldn_22.5.0/main.flat.bin` | 961 KB | LDN sysmodule |
| capsrv 20.0.0 | `firmware/capsrv_20.0.0/main.flat.bin` | 660 KB | Album management (not HTTP) |
| capmtp 20.0.0 | `firmware/capmtp_20.0.0/main.flat.bin` | 460 KB | MTP protocol (not HTTP) |

## Evidence (gitignored)

Test output JSON, pcap captures, and raw binary evidence stored locally in
`evidence/`, organized by investigation:

- `action_frame_overflow/` — LDN heap OOB write evidence
- `dhcp_attack/` — DHCP investigation (proven clean)
- `exploit_dev/` — Multipart overflow exploit development
- `exploit_delivery/` — Exploit chain building
- `http_baseline/` — HTTP server baseline captures
- `http_fuzz/` — HTTP fuzzing results
- `lp2p_dhcp/` — LP2P DHCP probing

## Constraints

1. **No firmware updates** — intentionally on 22.5.0
2. **Software only** — no hardware glitching
3. **Evidence rigor** — HTTP availability is an indirect oracle, not crash proof
4. **Manual recovery** — user must manually restart Switch between crashes
