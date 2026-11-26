# tegra_fuzz

Security research tooling for the **Tegra X1 (T210)** on hardware I own — a
Nintendo Switch HAC-001 (serial XAW4 001878). All work is authorized
owner-conducted research on my own device.

## Disclaimer

This repository documents **authorized security research on hardware I
personally own**. It exists for educational and research purposes only.

- No exploits target devices belonging to other people
- No online services or multiplayer infrastructure are targeted
- All vulnerabilities found will be disclosed responsibly to Nintendo
- No production-ready exploit payloads are included in this repository
- Firmware binaries and evidence data are excluded from version control

This research is conducted under the principle that understanding the security
of hardware you own is a legitimate exercise of ownership rights. Nothing here
should be used to compromise devices you do not own.

## Target Hardware

| Property | Value |
| --- | --- |
| Console | Nintendo Switch (HAC-001) |
| Serial range | XAW4 001878 (patched V1) |
| SoC | Tegra X1 (T210) Erista |
| Firmware | 22.5.0 (intentionally not updated) |
| Goal | Persistent custom firmware via software-only exploitation |

---

## Active Research: WiFi / HTTP Exploitation

The main research effort is in [`ldn_research/`](ldn_research/). The Switch's
"Send to Smartphone" feature (Album → Send to Smartphone) exposes an HTTP
server, DHCP server, and LDN protocol handler over a local WiFi AP — all
reachable by any client that connects.

### Multipart Filename Overflow (photoViewer applet)

A stack buffer overflow in the HTTP server's multipart `Content-Disposition`
parser. This is the most promising path to code execution.

| Property | Value |
|----------|-------|
| Trigger | Single unauthenticated HTTP POST |
| Buffer | ~4096 bytes (stack-allocated) |
| Return address control | **CONFIRMED** |
| Stack canaries | **NONE** |
| Persistent DoS | **CONFIRMED** (3x reproduced) |
| Code execution | Not yet — ASLR (~18-bit entropy) is the remaining blocker |

**Writeup:** [CVE-multipart-crash.md](ldn_research/CVE-multipart-crash.md)
**Deep analysis:** [multipart_overflow_status.md](ldn_research/docs/multipart_overflow_status.md)
**Scripts:** [scripts/multipart/](ldn_research/scripts/multipart/)

### CVE-2026-82079 (ldn WiFi stack overflow)

Stack-based buffer overflow in the `ldn` sysmodule's network layer copy
function, triggered via LP2P WiFi action frames. Independently confirmed
through static analysis of the ldn binary. Harder to exploit than the
multipart overflow (requires monitor-mode WiFi injection).

**Writeup:** [CVE-2026-82079_POC.md](ldn_research/CVE-2026-82079_POC.md)
**Technical report:** [TECHNICAL_REPORT.md](ldn_research/TECHNICAL_REPORT.md)

### Full Research Status

See [RESEARCH_STATUS.md](RESEARCH_STATUS.md) for the complete chain status
across all research lanes (multipart overflow, CVE-2026-82079, heap OOB write,
HTTP DoS, RCM, TSEC, peripherals).

| Path | Status |
|------|--------|
| **Multipart overflow (photoViewer)** | **ACTIVE** — LR control confirmed, ASLR is the blocker |
| CVE-2026-82079 (ldn WiFi) | Confirmed, harder to exploit |
| LDN Heap OOB Write | Confirmed, separate finding |
| HTTP Range DoS | Confirmed, DoS only |
| RCM / USB Boot ROM | Exhausted — patched hardware |
| TSEC | Requires prior code exec |

---

## RCM Fuzzer (Phase 1 — completed)

The original RCM USB fuzzer that started this project. The well-known bug class
on this surface is Fusee Gelee / CVE-2018-6242 (DMA buffer overflow, public
since 2018). An exploit attempt against this unit was not demonstrated — the
console behaves consistently with hardware-patched Erista.

### Tools

```bash
# Fuzzer
sudo python -m tegra_fuzz --seed 1 -n 1000 --out findings

# Device identification (read-only)
sudo python -m tegra_fuzz.identify

# Payload sender (CVE-2018-6242)
sudo python -m tegra_fuzz.payload bins/hekate_ctcaer_6.5.5.bin

# BootROM control transfer probe
sudo python -m tegra_fuzz.probe [--out findings/probe_results.json]

# USB traffic capture
sudo python -m tegra_fuzz.usbmon --bus 3 --duration 30
```

### Architecture

| Module | Responsibility |
| --- | --- |
| `model.py` | `TestCase`, `Outcome`, `Result` — pure, JSON-serialisable |
| `rcm.py` | Protocol constants, message framing, hand-written seed corpus |
| `mutators.py` | Pure, seed-deterministic mutation strategies |
| `corpus.py` | Seed management + persistence of findings |
| `transport.py` | The **only** hardware module: pyusb `UsbTransport` + `FakeTransport` |
| `monitor.py` | Pure outcome classification from transfer + liveness probe |
| `engine.py` | The fuzz loop: schedule → execute → classify → log |
| `payload.py` | Fusee Gelee (CVE-2018-6242) payload sender |
| `probe.py` | Systematic bootROM control transfer enumeration |

---

## Project Structure

```
tegra_fuzz/
├── ldn_research/            WiFi / HTTP research (active)
│   ├── docs/                Deep analysis documents
│   ├── scripts/             Attack & test scripts (by category)
│   │   ├── multipart/       photoViewer overflow exploit dev
│   │   ├── http/            HTTP server fuzzing
│   │   ├── dhcp/            DHCP attack scripts
│   │   ├── wifi/            WiFi frame injection & LDN fuzzing
│   │   ├── heap/            Heap exploitation attempts
│   │   ├── exploit/         Exploit chain building
│   │   └── recon/           Network recon, MITM, pcap analysis
│   ├── firmware/            Extracted binaries (gitignored)
│   └── evidence/            JSON/pcap test output (gitignored)
├── tegra_fuzz/              RCM USB fuzzer package
├── tests/                   Unit tests (77 tests, no hardware required)
├── findings/                RCM-era evidence (gitignored)
└── bins/                    Payload binaries (gitignored)
```

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt    # pyusb, scapy; needs system libusb-1.0
pip install pytest                 # for the test suite
```

## Tests

```bash
python -m pytest        # 77 tests, no hardware required
```

## Constraints

1. **No firmware updates** — intentionally on 22.5.0
2. **Software only** — no hardware glitching or voltage fault injection
3. **Evidence rigor** — distinguish established from inferred

## Contributing

This is a personal research repository. It is not accepting pull requests or
outside contributions. If you have questions about the research, open an issue.

If you discover a vulnerability in Nintendo hardware or software, please
disclose it responsibly through Nintendo's coordinated disclosure process.
