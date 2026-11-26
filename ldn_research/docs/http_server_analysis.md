# Switch "Send to Smartphone" HTTP Server Analysis

## Corrected Findings (2026-11-22)

### FALSE POSITIVE: "Bug 3" (403 on data.json)
The 403 Forbidden returned to 10.0.0.25 on `/data.json` was **NOT from the Switch**.
Evidence: response included `Server: Xfinity Broadband Router Server` and
`Date: Sun, 04 Jan 1970 21:59:37 GMT` (epoch near zero).
The Switch HTTP server never sends Server or Date headers.
This was the home router intercepting cross-network traffic.

### Confirmed Bugs (2 remaining)
1. **Double Content-Type on OOB range** — 206 response with both `Content-Type: image/jpeg`
   AND `Content-Type: text/html`, Content-Length: 117 (404 body). Indicates the range handler
   doesn't early-return on file-not-found or OOB, letting two code paths each add a Content-Type.
2. **Range processing on 404 body** — requesting a Range on a nonexistent file returns 404 with
   `Content-Range: bytes 0-15/117`. The 117-byte entity is the internal 404 HTML body.
   The range handler runs on the error page buffer.

### Server Profile
- **No Server header** (confirmed by pcap)
- **No Date header** (confirmed by pcap)
- Always `Connection: close` (no keepalive)
- Supports: GET, HEAD, Range requests
- POST: untested live (need recon)
- OPTIONS: returns 404
- Content types: `text/html`, `text/plain` (for JSON!), `image/jpeg`, `text/css`, `text/html` (for JS!)
- DHCP server: 192.168.0.1, subnet /24, no gateway, no DNS
- mDNS: Switch advertises NO services

### URL Schema
```
/index.html          → text/html (341B)
/js/index.js         → text/html (3271B) [NOTE: served as text/html, not application/javascript]
/styles/index.css    → text/css
/data.json           → text/plain (NOT application/json)
/img/<filename>      → image/jpeg (or video/mp4)
```

### data.json Full Structure
```json
{
  "FileType": "photo|movie",
  "DownloadMes": "Download",
  "PhotoHelpMes": "To save a screenshot...",
  "MovieHelpMes": "To save a video...",
  "ConsoleName": "Switch",
  "FileNames": ["<screenshot-id>.jpg", ...]
}
```

### JavaScript Analysis (index.js)
- `escapeHtml()` used for display text (ConsoleName, messages) — XSS-safe for those
- **Filenames used UNSANITIZED in**: `img.src = "img/" + filename`, `a.href = "img/" + filename`,
  `a.download = filename`, `img.alt = filename`
- JSON.parse for data.json — safe
- XHR GET to relative `data.json` — no auth, no cookies, no tokens

### DHCP Details (from pcap)
- Switch sends DHCP ACK with: Subnet 255.255.255.0, Server ID 192.168.0.1, Broadcast 192.168.0.255
- No Router option (isolated network — no internet)
- No DNS option
- Lease time: not captured (need new pcap)

### Beacon Structure (288 bytes)
- 56B radiotap header
- Frame control 0x80 (beacon)
- SSID: `switch_F3DCDB0100S`
- Nintendo vendor IE: OUI 00:22:aa, type 0x10, data: 01 01
- Broadcom vendor IE: OUI 00:10:18
- WPA2-PSK/CCMP, RSN IE present
- Beacon interval: 100 TU (~102.4ms)

### Attack Surface Map
1. **HTTP URI path** — length limits, path traversal, encoding
2. **HTTP headers** — size limits, number of headers
3. **Range header** — integer overflow (double Content-Type bug suggests weak parsing)
4. **img/ path** — directory traversal via crafted filenames?
5. **POST body** — if accepted, body parsing
6. **WiFi management frames** — IEs, RSN, vendor-specific
7. **DHCP** — option injection, lease manipulation
8. **WPA2 handshake** — EAPOL frames
