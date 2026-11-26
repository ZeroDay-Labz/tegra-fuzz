#!/usr/bin/env python3
"""
NM Configuration Diff — Compare NM connection profiles at vendor=221 vs 222.

Checks what NM actually does differently when the vendor class crosses
the crash boundary. No WiFi connection needed — just examines NM configs.
"""
import subprocess
import json
import sys
from pathlib import Path

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "crash_isolator"
SSID = "switch_F3DCDB0100S"
PSK = None  # pass via --psk or extract from QR code
HOSTNAME = "H" * 255

def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def create_conn(name, vendor_len):
    """Create NM connection profile with given vendor class size."""
    run(f"nmcli connection delete {name}", timeout=5)
    vendor = "V" * vendor_len
    rc, out, err = run(
        f"nmcli connection add type wifi con-name {name} ssid {SSID} "
        f"wifi-sec.key-mgmt wpa-psk wifi-sec.psk {PSK} "
        f"ipv4.method auto connection.autoconnect no "
        f"ipv4.dhcp-hostname {HOSTNAME}",
        timeout=10
    )
    if rc != 0:
        print(f"  ERROR creating {name}: {err}")
        return False

    rc, out, err = run(
        f"nmcli connection modify {name} ipv4.dhcp-vendor-class-identifier {vendor}",
        timeout=5
    )
    if rc != 0:
        print(f"  ERROR setting vendor class for {name}: {err}")
        return False

    return True

def dump_conn(name):
    """Dump full NM connection settings."""
    rc, out, err = run(f"nmcli -t connection show {name}", timeout=5)
    if rc != 0:
        return {}

    result = {}
    for line in out.split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip()] = val.strip()
    return result

def get_keyfile(name):
    """Read the NM keyfile for the connection."""
    # NM stores keyfiles in /etc/NetworkManager/system-connections/
    path = f"/etc/NetworkManager/system-connections/{name}.nmconnection"
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""

def main():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    print("Creating NM connections for diff comparison...")

    # Create both connections
    conns = {}
    for vendor_len in [221, 222]:
        name = f"isolator_v{vendor_len}"
        print(f"\n--- Creating {name} (vendor={vendor_len}) ---")
        if not create_conn(name, vendor_len):
            continue

        settings = dump_conn(name)
        keyfile = get_keyfile(name)

        conns[vendor_len] = {
            "name": name,
            "vendor_len": vendor_len,
            "settings": settings,
            "keyfile": keyfile,
            "keyfile_len": len(keyfile),
            "settings_count": len(settings),
        }

        print(f"  Settings count: {len(settings)}")
        print(f"  Keyfile length: {len(keyfile)}")

        # Print key DHCP settings
        for k in sorted(settings):
            if "dhcp" in k.lower() or "hostname" in k.lower() or "vendor" in k.lower():
                val = settings[k]
                if len(val) > 80:
                    val = val[:80] + f"... ({len(val)} total)"
                print(f"  {k}: {val}")

    # Diff
    if 221 in conns and 222 in conns:
        print("\n" + "=" * 60)
        print("DIFF: vendor=221 vs vendor=222")
        print("=" * 60)

        s221 = conns[221]["settings"]
        s222 = conns[222]["settings"]

        all_keys = sorted(set(s221.keys()) | set(s222.keys()))
        diffs = []
        for k in all_keys:
            v221 = s221.get(k, "<MISSING>")
            v222 = s222.get(k, "<MISSING>")
            if v221 != v222:
                # Truncate long values
                if len(v221) > 60:
                    v221 = v221[:60] + f"...({len(v221)})"
                if len(v222) > 60:
                    v222 = v222[:60] + f"...({len(v222)})"
                diffs.append({"key": k, "v221": v221, "v222": v222})
                print(f"  DIFF: {k}")
                print(f"    221: {v221}")
                print(f"    222: {v222}")

        if not diffs:
            print("  NO DIFFERENCES (except vendor class value)")

        # Check keyfile diff
        kf221 = conns[221]["keyfile"]
        kf222 = conns[222]["keyfile"]
        if kf221 and kf222:
            lines221 = set(kf221.split("\n"))
            lines222 = set(kf222.split("\n"))
            only_221 = lines221 - lines222
            only_222 = lines222 - lines221
            if only_221 or only_222:
                print("\n  Keyfile diffs:")
                for l in sorted(only_221):
                    if l.strip():
                        print(f"    221 only: {l[:100]}")
                for l in sorted(only_222):
                    if l.strip():
                        print(f"    222 only: {l[:100]}")

        # Save
        output = {
            "diffs": diffs,
            "keyfile_221_len": len(kf221),
            "keyfile_222_len": len(kf222),
        }
        path = EVIDENCE_DIR / "nm_diff.json"
        with open(path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nDiff saved to {path}")

    # Cleanup
    for vendor_len in [221, 222]:
        run(f"nmcli connection delete isolator_v{vendor_len}", timeout=5)

    print("\nConnections cleaned up.")

if __name__ == "__main__":
    main()
