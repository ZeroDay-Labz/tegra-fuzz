"""Instrumented RCM send — trace bootROM state between every chunk.

Sends 0x30298-byte message one chunk at a time. After each chunk,
reads IRAM via EP0 to capture the bootROM's internal state transition.

Outputs a JSON trace showing how buffer pointers, remaining count,
function pointers, and other IRAM state evolve chunk by chunk.

Usage:
    sudo python -m tegra_fuzz.trace_rcm [fill_byte_hex] [--every N]

    fill_byte_hex: body fill byte (default 00)
    --every N: read IRAM every N chunks (default 1 = every chunk)
"""
import struct, sys, time, json, os
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000
N_CHUNKS = (MSG_LEN + CHUNK - 1) // CHUNK  # 49


def parse_iram(data):
    """Extract key fields from the EP0 over-read window."""
    if not isinstance(data, bytes) or len(data) < 128:
        return None
    fields = {}
    for offset in range(0, min(len(data) - 3, 128), 4):
        val = struct.unpack_from('<I', data, offset)[0]
        fields[f'w{offset}'] = val

    return {
        'src_base': f"0x{fields.get('w12', 0):08X}",
        'buf_20': f"0x{fields.get('w20', 0):08X}",
        'buf_28': f"0x{fields.get('w28', 0):08X}",
        'buf_32': f"0x{fields.get('w32', 0):08X}",
        'ptr_36': f"0x{fields.get('w36', 0):08X}",
        'rom_40': f"0x{fields.get('w40', 0):08X}",
        'flag_44': fields.get('w44', 0),
        'stack_48': f"0x{fields.get('w48', 0):08X}",
        'buf_52': f"0x{fields.get('w52', 0):08X}",
        'rom_56': f"0x{fields.get('w56', 0):08X}",
        'remaining': fields.get('w60', 0),
        'chunk_size': fields.get('w64', 0),
        'rom_72': f"0x{fields.get('w72', 0):08X}",
        'ptr_76': f"0x{fields.get('w76', 0):08X}",
        'ptr_84': f"0x{fields.get('w84', 0):08X}",
        'rom_120': f"0x{fields.get('w120', 0):08X}",
        'raw_hex': data[:128].hex(),
    }


def ep0_read(dev):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, 500))
    except Exception:
        return None


def main():
    fill = 0x00
    every = 1
    for i, a in enumerate(sys.argv[1:]):
        if a == '--every' and i + 2 < len(sys.argv):
            every = int(sys.argv[i + 2])
        elif a.startswith('--'):
            pass
        elif not a.startswith('-'):
            try:
                fill = int(a, 16)
            except ValueError:
                pass

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device"); return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # Pre-handshake IRAM baseline
    baseline = ep0_read(dev)
    baseline_parsed = parse_iram(baseline)
    print(f"baseline: remaining={baseline_parsed['remaining']:#x} buf_20={baseline_parsed['buf_20']}", flush=True)

    # Claim + device ID
    try:
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        pass

    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"id={did.hex()}", flush=True)
    except Exception as e:
        print(f"id fail: {e}"); return 1

    # Build message
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0, MSG_LEN)
    if fill:
        for i in range(4, MSG_LEN):
            msg[i] = fill

    trace = []
    trace.append({'event': 'baseline', 'state': baseline_parsed})

    # Post-claim IRAM
    post_claim = ep0_read(dev)
    if post_claim:
        pc = parse_iram(post_claim)
        trace.append({'event': 'post_claim', 'state': pc})
        print(f"post_claim: remaining={pc['remaining']:#x} buf_20={pc['buf_20']} rom_56={pc['rom_56']}", flush=True)

    # Send chunks with IRAM reads between them
    total = 0
    for i in range(N_CHUNKS):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = msg[start:end]
        if len(chunk) < CHUNK:
            chunk = chunk + b'\x00' * (CHUNK - len(chunk))

        t0 = time.perf_counter_ns()
        try:
            w = dev.write(0x01, chunk, timeout=2000)
            t1 = time.perf_counter_ns()
            total += w
            write_us = (t1 - t0) / 1000
        except usb.core.USBTimeoutError:
            print(f"chunk[{i}]=TIMEOUT (total={total})")
            trace.append({'event': f'chunk_{i}', 'error': 'timeout', 'total': total})
            break
        except usb.core.USBError as e:
            print(f"chunk[{i}]={e} (total={total})")
            trace.append({'event': f'chunk_{i}', 'error': str(e), 'total': total})
            break

        # Read IRAM after this chunk
        if (i % every == 0) or i == 0 or i == N_CHUNKS - 1:
            iram = ep0_read(dev)
            if iram:
                state = parse_iram(iram)
                entry = {
                    'event': f'chunk_{i}',
                    'written': total,
                    'write_us': write_us,
                    'state': state,
                }
                trace.append(entry)

                # Print changes
                rem = state['remaining']
                buf = state['buf_20']
                rom56 = state['rom_56']
                print(f"  [{i:2d}] wrote={total:6d}  remaining=0x{rem:06X}  buf={buf}  rom56={rom56}  {write_us:.0f}us", flush=True)
            else:
                print(f"  [{i:2d}] wrote={total:6d}  EP0=FAIL", flush=True)
                trace.append({'event': f'chunk_{i}', 'written': total, 'ep0': 'fail'})

    # Read response
    print(f"\ntotal_written={total}", flush=True)
    t0 = time.perf_counter_ns()
    try:
        r = bytes(dev.read(0x81, 4096, timeout=5000))
        t1 = time.perf_counter_ns()
        resp_us = (t1 - t0) / 1000
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"resp={len(r)}B status=0x{val:08X} wait={resp_us:.0f}us", flush=True)
        trace.append({'event': 'response', 'status': val, 'resp_us': resp_us})
    except usb.core.USBTimeoutError:
        print("resp=TIMEOUT", flush=True)
        trace.append({'event': 'response', 'status': 'timeout'})
    except usb.core.USBError as e:
        print(f"resp={e}", flush=True)
        trace.append({'event': 'response', 'status': str(e)})

    outfile = "findings/trace_rcm.json"
    os.makedirs("findings", exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(trace, f, indent=2, default=str)
    print(f"Saved {len(trace)} events to {outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
