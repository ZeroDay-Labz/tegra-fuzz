"""Test EP0 state manipulation between bulk chunks.

Sends chunks with EP0 SET_FEATURE/CLEAR_FEATURE HALT between them.
We know byte[44] changes from 1→4 when EP_IN is halted. This test
checks whether halting/clearing endpoints mid-transfer:
1. Changes the destination pointer or remaining count
2. Causes the bootROM to skip/repeat a chunk copy
3. Crashes or alters the state machine
4. Affects the final response status

Usage:
    sudo python -m tegra_fuzz.mid_halt <mode>

Modes:
    halt_in_5      — HALT EP_IN after chunk 5, clear before chunk 6
    halt_out_5     — HALT EP_OUT after chunk 5, clear before chunk 6
    halt_both_5    — HALT both EPs after chunk 5, clear before chunk 6
    halt_noclear   — HALT EP_IN after chunk 5, never clear, continue writes
    halt_every     — HALT+CLEAR EP_IN after every chunk
    halt_at_last   — HALT EP_IN after chunk 47 (before final chunk)
"""
import struct, sys, time, json, os
import usb.core, usb.util

VID, PID = 0x0955, 0x7321
MSG_LEN = 0x30298
CHUNK = 0x1000
N_CHUNKS = (MSG_LEN + CHUNK - 1) // CHUNK


def ep0_read(dev):
    try:
        return bytes(dev.ctrl_transfer(0x82, 0x00, 0, 0x81, 255, 500))
    except Exception:
        return None


def parse_key_fields(data):
    if not data or len(data) < 128:
        return None
    return {
        'ptr_36': struct.unpack_from('<I', data, 36)[0],
        'flag_44': struct.unpack_from('<I', data, 44)[0],
        'remaining': struct.unpack_from('<I', data, 60)[0],
        'total': struct.unpack_from('<I', data, 64)[0],
        'buf_20': struct.unpack_from('<I', data, 20)[0],
    }


def halt_ep(dev, ep):
    try:
        dev.ctrl_transfer(0x02, 0x03, 0, ep, None, 500)
        return True
    except:
        return False


def clear_halt(dev, ep):
    try:
        dev.ctrl_transfer(0x02, 0x01, 0, ep, None, 500)
        return True
    except:
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python -m tegra_fuzz.mid_halt <mode>")
        return 1

    mode = sys.argv[1]

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if not dev:
        print("no device"); return 1
    print(f"dev {dev.bus}:{dev.address}", flush=True)

    # Pre-handshake EP0 check
    pre = ep0_read(dev)
    if pre:
        f = parse_key_fields(pre)
        if f:
            print(f"pre: ptr=0x{f['ptr_36']:08X} flag44={f['flag_44']}", flush=True)

    # Claim
    try:
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        usb.util.claim_interface(dev, 0)
        print("claimed", flush=True)
    except usb.core.USBError as e:
        print(f"claim: {e}", flush=True)

    try:
        did = bytes(dev.read(0x81, 16, timeout=2000))
        print(f"id={did.hex()}", flush=True)
    except Exception as e:
        print(f"id fail: {e}"); return 1

    time.sleep(0.05)

    # Build message
    msg = bytearray(MSG_LEN)
    struct.pack_into('<I', msg, 0, MSG_LEN)

    trace = []
    total = 0

    for i in range(N_CHUNKS):
        start = i * CHUNK
        end = min(start + CHUNK, MSG_LEN)
        chunk = msg[start:end]
        if len(chunk) < CHUNK:
            chunk = chunk + b'\x00' * (CHUNK - len(chunk))

        try:
            w = dev.write(0x01, chunk, timeout=2000)
            total += w
        except usb.core.USBTimeoutError:
            print(f"chunk[{i}]=TIMEOUT total={total}")
            trace.append({'chunk': i, 'error': 'timeout'})
            break
        except usb.core.USBError as e:
            print(f"chunk[{i}]={e} total={total}")
            trace.append({'chunk': i, 'error': str(e)})
            break

        # Apply halt/clear based on mode
        did_halt = False
        did_clear = False

        if mode == 'halt_in_5' and i == 5:
            did_halt = halt_ep(dev, 0x81)
        elif mode == 'halt_in_5' and i == 6:
            # Was halted, now reading state before clear
            pass
        elif mode == 'halt_out_5' and i == 5:
            did_halt = halt_ep(dev, 0x01)
        elif mode == 'halt_both_5' and i == 5:
            halt_ep(dev, 0x81)
            did_halt = halt_ep(dev, 0x01)
        elif mode == 'halt_noclear' and i == 5:
            did_halt = halt_ep(dev, 0x81)
        elif mode == 'halt_every':
            did_halt = halt_ep(dev, 0x81)
        elif mode == 'halt_at_last' and i == 47:
            did_halt = halt_ep(dev, 0x81)

        # Read IRAM at key points
        should_read = (i <= 2 or i in [4, 5, 6, 7, 24, 46, 47, 48]
                       or did_halt)
        if should_read:
            state = parse_key_fields(ep0_read(dev))
            entry = {'chunk': i, 'total': total}
            if did_halt:
                entry['halted'] = True
            if state:
                entry.update(state)
                ptr = state['ptr_36']
                f44 = state['flag_44']
                rem = state['remaining']
                print(f"  [{i:2d}] ptr=0x{ptr:08X} flag44={f44} rem=0x{rem:X} total={total}"
                      + (" HALTED" if did_halt else ""), flush=True)
            trace.append(entry)

        # Clear halt after reading state
        if mode == 'halt_in_5' and i == 5:
            # Read halted state, then clear before next chunk
            did_clear = clear_halt(dev, 0x81)
            after_clear = parse_key_fields(ep0_read(dev))
            if after_clear:
                print(f"       after clear: flag44={after_clear['flag_44']}"
                      f" ptr=0x{after_clear['ptr_36']:08X}", flush=True)
                trace.append({'chunk': i, 'event': 'after_clear', **after_clear})
        elif mode == 'halt_out_5' and i == 5:
            did_clear = clear_halt(dev, 0x01)
        elif mode == 'halt_both_5' and i == 5:
            clear_halt(dev, 0x81)
            did_clear = clear_halt(dev, 0x01)
        elif mode == 'halt_every':
            did_clear = clear_halt(dev, 0x81)
        elif mode == 'halt_at_last' and i == 47:
            did_clear = clear_halt(dev, 0x81)

    print(f"\ntotal_written={total}", flush=True)

    # Read response
    t0 = time.perf_counter_ns()
    try:
        r = bytes(dev.read(0x81, 4096, timeout=5000))
        t1 = time.perf_counter_ns()
        val = struct.unpack_from('<I', r, 0)[0] if len(r) >= 4 else -1
        print(f"resp={len(r)}B status=0x{val:08X} wait={(t1-t0)/1000:.0f}us", flush=True)
        trace.append({'event': 'response', 'status': val})
    except usb.core.USBTimeoutError:
        print("resp=TIMEOUT", flush=True)
        trace.append({'event': 'response', 'status': 'timeout'})
    except usb.core.USBError as e:
        print(f"resp={e}", flush=True)
        trace.append({'event': 'response', 'status': str(e)})

    outfile = f"findings/mid_halt_{mode}.json"
    os.makedirs("findings", exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(trace, f, indent=2, default=str)
    print(f"Saved to {outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
