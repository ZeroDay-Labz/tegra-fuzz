#!/usr/bin/env python3
"""
Captive Portal Attack — Serve a crafted captive portal to the Nintendo Switch.

Creates a WiFi AP, sets up DHCP/DNS, and serves a captive portal page that
the Switch's WebKit browser should open automatically when it fails its
connectivity check (conntest.nintendowifi.net).

The portal page probes the browser's User-Agent, available APIs, and
serves crafted HTML/JS to test for WebKit vulnerabilities.

Usage:
    sudo python3 -I captive_portal.py --iface wlp5s0

Requirements:
    - hostapd, dnsmasq installed
    - WiFi interface that supports AP mode
    - Run as root
"""

import subprocess
import tempfile
import signal
import sys
import os
import json
import time
import argparse
import http.server
import socketserver
import threading
from pathlib import Path
from datetime import datetime, timezone

EVIDENCE_DIR = Path(__file__).parent.parent / "evidence" / "captive_portal"
AP_IP = "192.168.44.1"
AP_SUBNET = "192.168.44.0/24"
DHCP_RANGE_START = "192.168.44.10"
DHCP_RANGE_END = "192.168.44.50"
AP_SSID = "NintendoWiFi"
AP_CHANNEL = 6
HTTP_PORT = 80
HTTPS_PORT = 443

NINTENDO_CONNTEST_HOSTS = [
    "conntest.nintendowifi.net",
    "ctest.cdn.nintendo.net",
    "sun.hac.lp1.d4c.nintendo.net",
]

procs = []
tmpfiles = []


def _update_config(ssid, channel):
    global AP_SSID, AP_CHANNEL
    AP_SSID = ssid
    AP_CHANNEL = channel
evidence = {
    "start_time": None,
    "connections": [],
    "http_requests": [],
    "user_agents": [],
    "dhcp_leases": [],
}


def evidence_dir():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_DIR


def cleanup(*args):
    print("\n[*] Cleaning up...")
    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    for f in tmpfiles:
        try:
            os.unlink(f)
        except Exception:
            pass

    # Restore interface
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", args[0] if args and isinstance(args[0], str) else "wlp5s0"],
                   capture_output=True)
    subprocess.run(["sudo", "rfkill", "unblock", "wifi"], capture_output=True)

    # Save evidence
    evidence["end_time"] = datetime.now(timezone.utc).isoformat()
    path = evidence_dir() / "captive_portal_evidence.json"
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"[*] Evidence saved to {path}")
    sys.exit(0)


def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


CONNTEST_RESPONSE = """<!DOCTYPE html>
<html><head><title>OK</title></head><body>This is not the page you expected.</body></html>"""

PROBE_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Login</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    background: #f5f5f5; color: #333;
    padding: 20px; min-height: 100vh;
}
.container { max-width: 400px; margin: 0 auto; }
h1 { font-size: 20px; margin-bottom: 10px; color: #e60012; }
.card {
    background: white; border-radius: 12px; padding: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 15px;
}
.btn {
    display: block; width: 100%; padding: 12px;
    background: #e60012; color: white; border: none;
    border-radius: 8px; font-size: 16px; cursor: pointer;
    text-align: center;
}
.info { font-size: 12px; color: #666; margin-top: 8px; }
#output {
    font-family: monospace; font-size: 11px;
    white-space: pre-wrap; word-break: break-all;
    background: #1a1a1a; color: #0f0; padding: 10px;
    border-radius: 8px; max-height: 300px; overflow-y: auto;
    margin-top: 10px;
}
</style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>Free WiFi</h1>
        <p>Welcome! Click below to connect to the internet.</p>
        <br>
        <button class="btn" onclick="probe()">Connect</button>
        <p class="info">By connecting, you agree to our terms of service.</p>
    </div>
    <div id="results" class="card" style="display:none">
        <h2 style="font-size:14px;margin-bottom:8px;">Connection Status</h2>
        <div id="output"></div>
    </div>
</div>

<script>
var out = "";
function log(msg) {
    out += msg + "\\n";
    var el = document.getElementById("output");
    if (el) { el.textContent = out; }
}

function probe() {
    document.getElementById("results").style.display = "block";

    // Basic browser fingerprint
    log("=== BROWSER PROBE ===");
    log("UA: " + navigator.userAgent);
    log("Platform: " + navigator.platform);
    log("Language: " + navigator.language);
    log("CookiesEnabled: " + navigator.cookieEnabled);
    log("Screen: " + screen.width + "x" + screen.height);
    log("DevPixRatio: " + window.devicePixelRatio);
    log("InnerSize: " + window.innerWidth + "x" + window.innerHeight);

    // WebKit version detection
    var wkMatch = navigator.userAgent.match(/AppleWebKit\\/([\\d.]+)/);
    if (wkMatch) log("WebKit: " + wkMatch[1]);

    var safariMatch = navigator.userAgent.match(/Version\\/([\\d.]+)/);
    if (safariMatch) log("Version: " + safariMatch[1]);

    // JavaScript engine features
    log("\\n=== JS ENGINE ===");
    log("ES6 Proxy: " + (typeof Proxy !== "undefined"));
    log("WeakRef: " + (typeof WeakRef !== "undefined"));
    log("BigInt: " + (typeof BigInt !== "undefined"));
    log("SharedArrayBuffer: " + (typeof SharedArrayBuffer !== "undefined"));
    log("Atomics: " + (typeof Atomics !== "undefined"));
    log("FinalizationRegistry: " + (typeof FinalizationRegistry !== "undefined"));
    log("globalThis: " + (typeof globalThis !== "undefined"));

    // Memory/buffer APIs
    log("\\n=== MEMORY APIS ===");
    log("ArrayBuffer: " + (typeof ArrayBuffer !== "undefined"));
    log("DataView: " + (typeof DataView !== "undefined"));
    log("WebAssembly: " + (typeof WebAssembly !== "undefined"));
    log("TextEncoder: " + (typeof TextEncoder !== "undefined"));
    log("TextDecoder: " + (typeof TextDecoder !== "undefined"));

    // Try to detect ArrayBuffer max size
    try {
        var maxTest = [1024*1024, 16*1024*1024, 64*1024*1024, 256*1024*1024, 512*1024*1024, 1024*1024*1024];
        var maxAlloc = 0;
        for (var i = 0; i < maxTest.length; i++) {
            try {
                var buf = new ArrayBuffer(maxTest[i]);
                if (buf.byteLength === maxTest[i]) maxAlloc = maxTest[i];
                buf = null;
            } catch(e) { break; }
        }
        log("MaxArrayBuffer: " + (maxAlloc / (1024*1024)) + "MB");
    } catch(e) { log("MaxArrayBuffer: error"); }

    // DOM APIs
    log("\\n=== DOM APIS ===");
    log("Fetch: " + (typeof fetch !== "undefined"));
    log("WebSocket: " + (typeof WebSocket !== "undefined"));
    log("Worker: " + (typeof Worker !== "undefined"));
    log("ServiceWorker: " + ("serviceWorker" in navigator));
    log("IndexedDB: " + (typeof indexedDB !== "undefined"));
    log("localStorage: " + (typeof localStorage !== "undefined"));
    log("Notification: " + (typeof Notification !== "undefined"));

    // Canvas fingerprinting
    try {
        var c = document.createElement("canvas");
        c.width = 200; c.height = 50;
        var ctx = c.getContext("2d");
        ctx.textBaseline = "top";
        ctx.font = "14px Arial";
        ctx.fillText("Switch?", 2, 2);
        var d = c.toDataURL();
        log("Canvas: " + d.substring(0, 60) + "...");
        log("CanvasLen: " + d.length);
    } catch(e) { log("Canvas: " + e); }

    // WebGL
    try {
        var gl = document.createElement("canvas").getContext("webgl");
        if (gl) {
            log("\\n=== WEBGL ===");
            log("Vendor: " + gl.getParameter(gl.VENDOR));
            log("Renderer: " + gl.getParameter(gl.RENDERER));
            log("Version: " + gl.getParameter(gl.VERSION));
            log("ShadingLang: " + gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
            var dbg = gl.getExtension("WEBGL_debug_renderer_info");
            if (dbg) {
                log("UnmaskedVendor: " + gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL));
                log("UnmaskedRenderer: " + gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
            }
            log("MaxTexSize: " + gl.getParameter(gl.MAX_TEXTURE_SIZE));
            log("MaxVertexAttribs: " + gl.getParameter(gl.MAX_VERTEX_ATTRIBS));
        } else {
            log("WebGL: not available");
        }
    } catch(e) { log("WebGL: " + e); }

    // Report back to our server
    log("\\n=== REPORTING ===");
    try {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/report", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onload = function() {
            log("Report sent: " + xhr.status);
        };
        xhr.onerror = function() {
            log("Report failed");
        };
        xhr.send(JSON.stringify({
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            screen: screen.width + "x" + screen.height,
            webkitVersion: wkMatch ? wkMatch[1] : "unknown",
            features: out,
            timestamp: new Date().toISOString()
        }));
    } catch(e) {
        log("XHR error: " + e);
    }

    // Test WebKit-specific attack surfaces
    log("\\n=== WEBKIT SURFACE ===");

    // CSS custom properties (for UAF probing)
    log("CSSCustomProps: " + (CSS && CSS.supports && CSS.supports("--a", "0")));

    // Check for specific WebKit bugs indicators
    try {
        // Test regex engine (CVE-type targets)
        var r = new RegExp("(?:a{10000}){10000}");
        log("RegexLarge: ok");
    } catch(e) { log("RegexLarge: " + e.message); }

    // Intl APIs (common WebKit attack surface)
    log("Intl: " + (typeof Intl !== "undefined"));
    if (typeof Intl !== "undefined") {
        log("Intl.Segmenter: " + (typeof Intl.Segmenter !== "undefined"));
        log("Intl.ListFormat: " + (typeof Intl.ListFormat !== "undefined"));
        log("Intl.RelativeTimeFormat: " + (typeof Intl.RelativeTimeFormat !== "undefined"));
    }

    // ResizeObserver (newer API)
    log("ResizeObserver: " + (typeof ResizeObserver !== "undefined"));
    log("IntersectionObserver: " + (typeof IntersectionObserver !== "undefined"));
    log("MutationObserver: " + (typeof MutationObserver !== "undefined"));

    log("\\n=== DONE ===");
}

// Auto-probe on load after short delay
setTimeout(function() {
    probe();
}, 500);
</script>
</body>
</html>"""


class CaptivePortalHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        msg = fmt % args
        ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": ts,
            "client": self.client_address[0],
            "method": "LOG",
            "message": msg,
        }
        evidence["http_requests"].append(entry)
        print(f"  [{ts}] {self.client_address[0]} {msg}")

    def do_GET(self):
        ts = datetime.now(timezone.utc).isoformat()
        host = self.headers.get("Host", "")
        ua = self.headers.get("User-Agent", "")

        entry = {
            "timestamp": ts,
            "client": self.client_address[0],
            "method": "GET",
            "path": self.path,
            "host": host,
            "user_agent": ua,
            "headers": dict(self.headers),
        }
        evidence["http_requests"].append(entry)

        if ua and ua not in evidence["user_agents"]:
            evidence["user_agents"].append(ua)
            print(f"\n  [!] NEW USER-AGENT: {ua}\n")

        print(f"  GET {host}{self.path} <- {self.client_address[0]} [{ua[:60]}]")

        # Nintendo connectivity test endpoints
        is_conntest = any(h in host for h in NINTENDO_CONNTEST_HOSTS)
        if is_conntest or self.path in ["/", "/index.html"]:
            if is_conntest:
                # Return non-expected response to trigger captive portal
                print(f"  [!] CONNTEST DETECTED from {self.client_address[0]} — sending portal redirect")
                self.send_response(302)
                self.send_header("Location", f"http://{AP_IP}/portal")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        if self.path == "/portal" or self.path == "/generate_204" or self.path == "/hotspot-detect.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            content = PROBE_PAGE.encode("utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # For any other request, serve the probe page
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        content = PROBE_PAGE.encode("utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        ts = datetime.now(timezone.utc).isoformat()
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        entry = {
            "timestamp": ts,
            "client": self.client_address[0],
            "method": "POST",
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "user_agent": self.headers.get("User-Agent", ""),
            "body": body[:10000],
        }
        evidence["http_requests"].append(entry)

        if self.path == "/report":
            print(f"\n{'='*60}")
            print(f"  [!!!] BROWSER REPORT FROM {self.client_address[0]}")
            print(f"{'='*60}")
            try:
                data = json.loads(body)
                for k, v in data.items():
                    if k != "features":
                        print(f"  {k}: {v}")
                if "features" in data:
                    print(f"\n  Full probe output:")
                    print(f"  {data['features'][:3000]}")

                # Save report separately
                report_path = evidence_dir() / f"browser_report_{ts.replace(':','')}.json"
                with open(report_path, "w") as f:
                    json.dump(data, f, indent=2)
                print(f"\n  [*] Report saved to {report_path}")
            except Exception as e:
                print(f"  [!] Failed to parse report: {e}")
                print(f"  Raw body: {body[:500]}")
            print(f"{'='*60}\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        resp = b'{"status":"ok"}'
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def setup_ap(iface):
    """Set up the WiFi AP using hostapd."""
    print(f"[*] Setting up AP on {iface}...")

    # Disconnect from any current WiFi
    run(f"nmcli device disconnect {iface}", timeout=10)
    time.sleep(1)

    # Stop NM from managing this interface
    run(f"nmcli device set {iface} managed no", timeout=5)
    time.sleep(1)

    # Set interface up with IP
    run(f"ip addr flush dev {iface}", timeout=5)
    run(f"ip addr add {AP_IP}/24 dev {iface}", timeout=5)
    run(f"ip link set {iface} up", timeout=5)
    time.sleep(1)

    # Create hostapd config
    hostapd_conf = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    tmpfiles.append(hostapd_conf.name)
    hostapd_conf.write(f"""interface={iface}
driver=nl80211
ssid={AP_SSID}
hw_mode=g
channel={AP_CHANNEL}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
""")
    hostapd_conf.close()

    # Create dnsmasq config
    dnsmasq_conf = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    tmpfiles.append(dnsmasq_conf.name)
    dnsmasq_conf.write(f"""interface={iface}
bind-interfaces
dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},255.255.255.0,12h
dhcp-option=6,{AP_IP}
dhcp-option=3,{AP_IP}

# Redirect ALL DNS to us — this triggers captive portal detection
address=/#/{AP_IP}

# Log DHCP
log-dhcp
log-queries
""")
    dnsmasq_conf.close()

    # Start hostapd
    print(f"[*] Starting hostapd (SSID: {AP_SSID})...")
    hostapd_proc = subprocess.Popen(
        ["hostapd", hostapd_conf.name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    procs.append(hostapd_proc)
    time.sleep(2)

    # Check if hostapd started
    if hostapd_proc.poll() is not None:
        out = hostapd_proc.stdout.read().decode()
        print(f"[!] hostapd FAILED to start:\n{out}")
        return False

    # Start dnsmasq
    print(f"[*] Starting dnsmasq (DHCP + DNS wildcard → {AP_IP})...")
    # Kill any existing dnsmasq on this interface first
    run("pkill -f 'dnsmasq.*captive'", timeout=3)
    time.sleep(1)

    dnsmasq_proc = subprocess.Popen(
        ["dnsmasq", "-C", dnsmasq_conf.name, "--no-daemon", "--log-facility=-"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    procs.append(dnsmasq_proc)
    time.sleep(1)

    if dnsmasq_proc.poll() is not None:
        out = dnsmasq_proc.stdout.read().decode()
        print(f"[!] dnsmasq FAILED to start:\n{out}")
        return False

    print(f"[+] AP '{AP_SSID}' is running on {iface} ({AP_IP})")
    return True


def start_http_server():
    """Start the captive portal HTTP server."""
    print(f"[*] Starting HTTP server on port {HTTP_PORT}...")

    server = socketserver.TCPServer(("0.0.0.0", HTTP_PORT), CaptivePortalHandler)
    server.allow_reuse_address = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"[+] HTTP server listening on 0.0.0.0:{HTTP_PORT}")
    return server


def main():
    parser = argparse.ArgumentParser(description="Captive Portal Attack for Nintendo Switch")
    parser.add_argument("--iface", default="wlp5s0", help="WiFi interface")
    parser.add_argument("--ssid", default=AP_SSID, help="AP SSID name")
    parser.add_argument("--channel", type=int, default=AP_CHANNEL, help="WiFi channel")
    args = parser.parse_args()

    # Update module-level config from args
    _update_config(args.ssid, args.channel)

    if os.getuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)

    evidence["start_time"] = datetime.now(timezone.utc).isoformat()
    evidence["config"] = {
        "iface": args.iface,
        "ssid": AP_SSID,
        "channel": AP_CHANNEL,
        "ap_ip": AP_IP,
    }

    signal.signal(signal.SIGINT, lambda s, f: cleanup(args.iface))
    signal.signal(signal.SIGTERM, lambda s, f: cleanup(args.iface))

    print("=" * 60)
    print("  CAPTIVE PORTAL ATTACK — Nintendo Switch Browser Probe")
    print("=" * 60)
    print(f"  Interface: {args.iface}")
    print(f"  SSID: {AP_SSID}")
    print(f"  AP IP: {AP_IP}")
    print(f"  Channel: {AP_CHANNEL}")
    print("=" * 60)

    # Step 1: Set up AP
    if not setup_ap(args.iface):
        print("[!] Failed to set up AP. Cleaning up.")
        cleanup(args.iface)
        return

    # Step 2: Start HTTP server
    http_srv = start_http_server()

    # Step 3: Wait for connections
    print()
    print("=" * 60)
    print("  AP IS READY — NOW DO THIS ON THE SWITCH:")
    print("=" * 60)
    print(f"  1. Go to System Settings → Internet → Internet Settings")
    print(f"  2. Look for network '{AP_SSID}' and connect to it")
    print(f"     (It's an open network, no password needed)")
    print(f"  3. The Switch should detect a captive portal")
    print(f"  4. When prompted, open the browser/login page")
    print(f"  5. The probe will run automatically")
    print()
    print("  Waiting for connections... (Ctrl+C to stop)")
    print("=" * 60)
    print()

    # Monitor loop
    try:
        while True:
            time.sleep(1)
            # Check if hostapd is still running
            if procs[0].poll() is not None:
                print("[!] hostapd died!")
                out = procs[0].stdout.read().decode()
                print(f"    Output: {out[:500]}")
                break
    except KeyboardInterrupt:
        pass

    cleanup(args.iface)


if __name__ == "__main__":
    main()
