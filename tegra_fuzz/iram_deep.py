"""Deep IRAM analysis — read every accessible window and correlate.

Pre-handshake only: does NOT claim interface or read device ID.
Can run many EP0 reads per session without consuming the RCM exchange.

Maps all IRAM accessible via EP0 over-reads and looks for:
- BCT fields (loaded at 0x40000000)
- Fuse-derived data
- Stack contents near 0x40008000
- IPATCH handler code at 0x40004C30
- Pointers to bootROM code (0x0010xxxx range)

Usage:
    sudo python -m tegra_fuzz.iram_deep [--consume]

    --consume: Also do the RCM exchange after EP0 analysis to compare
               IRAM state before vs after message processing.
"""
import struct, sys, json, os
import usb.core

VID, PID = 0x0955, 0x7321

FORBIDDEN = {(0x00, 0x05)}  # Never SET_ADDRESS

# Known IRAM addresses from prior research
KNOWN_ADDRS = {
    0x40000000: "BCT base",
    0x40004C30: "IPATCH SVC handler (T210)",
    0x40005000: "IRAM pointer (from leak)",
    0x40008000: "Stack pointer",
    0x40009000: "DMA buffer",
    0x40010000: "Bootloader load addr",
    0x40013FE0: "PK11 blob addr",
    0x4000FC94: "src_base (from leak)",
    0x4000FCE0: "near-stack (from leak)",
}

ROM_ADDRS = {
    0x001007B0: "SVC dispatch (T210 thunk DCD 0)",
    0x001007F8: "SVC dispatch (T210 thunk DCD 1)",
    0x0010291B: "bootROM function (from leak)",
    0x00102929: "bootROM function (from leak)",
    0x00102AD1: "bootROM function (from leak)",
    0x0010769A: "IPATCH Patch 3 target (CVE fix)",
    0x001079DB: "ShofEL2 return addr",
    0x00107B23: "USB handler (from leak)",
}


def try_read(dev, bmrt, breq, wval, widx, wlen, timeout=500):
    if (bmrt, breq) in FORBIDDEN:
        return None
    try:
        data = bytes(dev.ctrl_transfer(bmrt, breq, wval, widx, wlen, timeout))
        return data
    except usb.core.USBTimeoutError:
        return "TIMEOUT"
    except usb.core.USBError as e:
        errno = getattr(e, 'errno', None)
        if errno == 32:
            return "STALL"
        return f"ERR:{errno}"


def parse_words(data, offset_name=""):
    words = []
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, i)[0]
        annotation = ""
        if val in KNOWN_ADDRS:
            annotation = f" ← {KNOWN_ADDRS[val]}"
        elif val in ROM_ADDRS:
            annotation = f" ← {ROM_ADDRS[val]}"
        elif 0x00100000 <= val <= 0x00120000:
            annotation = " ← bootROM range"
        elif 0x40000000 <= val <= 0x40040000:
            annotation = " ← IRAM range"
        elif 0x60000000 <= val <= 0x80000000:
            annotation = " ← MMIO range"
        words.append({
            'offset': i,
            'value': f"0x{val:08X}",
            'raw': val,
            'annotation': annotation,
        })
    return words


def entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())


def main():
    consume = '--consume' in sys.argv

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device")
        return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    results = {}

    # === Phase 1: EP0 reads across all known working request types ===
    print("\n=== Phase 1: EP0 Window Mapping ===", flush=True)

    windows = [
        # (bmrt, breq, wval, widx, label)
        (0x80, 0x00, 0, 0x00, "dev_status"),
        (0x80, 0x08, 0, 0x00, "get_config"),
        (0x81, 0x00, 0, 0x00, "iface0_status"),
        (0x81, 0x00, 0, 0x01, "iface1_status"),
        (0x81, 0x0A, 0, 0x00, "get_iface0"),
        (0x81, 0x0A, 0, 0x01, "get_iface1"),
        (0x82, 0x00, 0, 0x00, "ep0_out_status"),
        (0x82, 0x00, 0, 0x01, "ep1_out_status"),
        (0x82, 0x00, 0, 0x02, "ep2_out_status"),
        (0x82, 0x00, 0, 0x80, "ep0_in_status"),
        (0x82, 0x00, 0, 0x81, "ep1_in_status"),
        (0x82, 0x00, 0, 0x82, "ep2_in_status"),
    ]

    for bmrt, breq, wval, widx, label in windows:
        data = try_read(dev, bmrt, breq, wval, widx, 255)
        if isinstance(data, bytes) and len(data) > 0:
            nonzero = sum(1 for b in data if b != 0)
            ent = entropy(data)
            print(f"  {label:20s} {len(data):3d}B  nonzero={nonzero:3d}  entropy={ent:.2f}  {data[:16].hex()}", flush=True)
            words = parse_words(data, label)
            ptrs = [w for w in words if w['annotation']]
            results[label] = {
                'bmrt': bmrt, 'breq': breq, 'wval': wval, 'widx': widx,
                'len': len(data), 'nonzero': nonzero, 'entropy': ent,
                'hex': data.hex(),
                'pointers': ptrs,
            }
        elif isinstance(data, str):
            if data not in ('STALL', 'ERR:32'):
                print(f"  {label:20s} {data}", flush=True)
            results[label] = {'status': data}

    # === Phase 2: Stability check — read same window twice ===
    print("\n=== Phase 2: Stability ===", flush=True)
    d1 = try_read(dev, 0x82, 0x00, 0, 0x81, 255)
    d2 = try_read(dev, 0x82, 0x00, 0, 0x81, 255)
    if isinstance(d1, bytes) and isinstance(d2, bytes):
        same = d1 == d2
        diff_count = sum(1 for a, b in zip(d1, d2) if a != b)
        print(f"  ep1_in read1 vs read2: same={same} diffs={diff_count}", flush=True)
        results['stability'] = {'same': same, 'diff_bytes': diff_count}

    # === Phase 3: SET_INTERFACE state changes ===
    print("\n=== Phase 3: SET_INTERFACE effects ===", flush=True)
    baseline = try_read(dev, 0x82, 0x00, 0, 0x81, 255)
    for alt in [1, 0xFF, 0x100, 0xFFFF]:
        try:
            dev.ctrl_transfer(0x01, 0x0B, alt, 0, None, 500)
            after = try_read(dev, 0x82, 0x00, 0, 0x81, 255)
            if isinstance(baseline, bytes) and isinstance(after, bytes):
                same = baseline == after
                diffs = sum(1 for a, b in zip(baseline, after) if a != b)
                print(f"  alt={alt:#06x}: same={same} diffs={diffs}", flush=True)
                if not same:
                    for i, (a, b) in enumerate(zip(baseline, after)):
                        if a != b:
                            print(f"    byte[{i}]: 0x{a:02X} → 0x{b:02X}", flush=True)
        except usb.core.USBError as e:
            print(f"  alt={alt:#06x}: {e}", flush=True)

    # === Phase 4: SET_FEATURE / CLEAR_FEATURE effects on different EPs ===
    print("\n=== Phase 4: Halt state effects ===", flush=True)
    for ep in [0x01, 0x81]:
        pre = try_read(dev, 0x82, 0x00, 0, ep, 255)
        try:
            dev.ctrl_transfer(0x02, 0x03, 0, ep, None, 500)  # SET_FEATURE HALT
        except usb.core.USBError:
            pass
        post = try_read(dev, 0x82, 0x00, 0, ep, 255)
        if isinstance(pre, bytes) and isinstance(post, bytes):
            diffs = sum(1 for a, b in zip(pre, post) if a != b)
            print(f"  EP 0x{ep:02X} halt: diffs={diffs}", flush=True)
            if diffs > 0:
                for i, (a, b) in enumerate(zip(pre, post)):
                    if a != b:
                        print(f"    byte[{i}]: 0x{a:02X} → 0x{b:02X}", flush=True)
        # Clear halt
        try:
            dev.ctrl_transfer(0x02, 0x01, 0, ep, None, 500)  # CLEAR_FEATURE HALT
        except usb.core.USBError:
            pass

    # === Phase 5: Exhaustive word analysis of best window ===
    print("\n=== Phase 5: Full word analysis (ep1_in) ===", flush=True)
    best = try_read(dev, 0x82, 0x00, 0, 0x81, 255)
    if isinstance(best, bytes):
        words = parse_words(best)
        rom_ptrs = []
        iram_ptrs = []
        for w in words:
            if 0x00100000 <= w['raw'] <= 0x00120000:
                rom_ptrs.append(w)
                print(f"  ROM  [{w['offset']:3d}] {w['value']}{w['annotation']}", flush=True)
            elif 0x40000000 <= w['raw'] <= 0x40040000:
                iram_ptrs.append(w)
                print(f"  IRAM [{w['offset']:3d}] {w['value']}{w['annotation']}", flush=True)
        results['rom_pointers'] = rom_ptrs
        results['iram_pointers'] = iram_ptrs

        # High-entropy region analysis
        print("\n  High-entropy regions:", flush=True)
        window = 16
        for start in range(0, len(best) - window, 4):
            chunk = best[start:start+window]
            e = entropy(chunk)
            if e > 3.5:
                print(f"    [{start:3d}-{start+window:3d}] entropy={e:.2f} {chunk.hex()}", flush=True)

    # === Phase 6: Consume RCM session (optional) ===
    if consume:
        print("\n=== Phase 6: RCM exchange ===", flush=True)
        import usb.util as uu
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        try:
            dev.set_configuration()
            uu.claim_interface(dev, 0)
        except usb.core.USBError:
            pass
        try:
            did = bytes(dev.read(0x81, 16, timeout=2000))
            print(f"  id={did.hex()}", flush=True)
        except Exception as e:
            print(f"  id={e}", flush=True)

        # Send minimal valid message (all zeros, length=0x30298)
        msg = bytearray(MSG_LEN)
        struct.pack_into('<I', msg, 0, MSG_LEN)
        n_chunks = (MSG_LEN + CHUNK - 1) // CHUNK
        total = 0
        for i in range(n_chunks):
            start = i * CHUNK
            end = min(start + CHUNK, MSG_LEN)
            chunk = msg[start:end]
            if len(chunk) < CHUNK:
                chunk = chunk + b'\x00' * (CHUNK - len(chunk))
            try:
                w = dev.write(0x01, chunk, timeout=2000)
                total += w
            except Exception:
                break
        print(f"  wrote {total}B", flush=True)

        try:
            r = bytes(dev.read(0x81, 4096, timeout=5000))
            val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
            print(f"  status=0x{val:08X}", flush=True)
        except Exception as e:
            print(f"  read={e}", flush=True)

        # Post-exchange EP0 check
        post_ep0 = try_read(dev, 0x82, 0x00, 0, 0x81, 255)
        if isinstance(post_ep0, str):
            print(f"  post-exchange EP0: {post_ep0}", flush=True)
        elif isinstance(post_ep0, bytes):
            print(f"  post-exchange EP0: {len(post_ep0)}B", flush=True)

    alive = usb.core.find(idVendor=VID, idProduct=PID) is not None
    print(f"\nalive={alive}", flush=True)

    outfile = "findings/iram_deep_analysis.json"
    os.makedirs("findings", exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Saved to {outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
