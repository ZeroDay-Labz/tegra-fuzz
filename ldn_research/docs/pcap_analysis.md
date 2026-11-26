# Deep PCAP Analysis — Switch LDN HTTP Server

## 403 "Bug" Debunked

The previously-reported "phone gets 403 on data.json" is **NOT a Switch bug**.

**Root cause:** The user's PC was dual-homed (192.168.0.2 on Switch AP + 10.0.0.25 via Ethernet/home). All requests from 10.0.0.25 were routed through the **Xfinity Broadband Router Server**, not the Switch.

Evidence from TCP stream follow:
- 403 response: `Server: Xfinity Broadband Router Server`, `Date: Sun, 04 Jan 1970 21:59:37 GMT`
- 200 responses to 10.0.0.25: Same Xfinity server, Content-Length 8823 (router login page), CSP headers, X-Frame-Options — none of which the Switch sends
- Real Switch responses (192.168.0.2): No Server header, no Date header, no security headers

**Conclusion:** Switch HTTP server has **zero access control**. Any client on the WiFi can hit any endpoint.

## Real Switch HTTP Fingerprint

From streams 0-1 (192.168.0.2 ↔ 192.168.0.1):

```
HTTP/1.1 200 OK
Connection: close
Content-Length: <exact>
Content-Type: <correct type>
```

- NO Server header
- NO Date header
- NO Cache-Control / Pragma
- NO security headers (CSP, X-Frame-Options, etc.)
- Connection: close on EVERY response (no keep-alive)
- Content-Type mapping: .html→text/html, .json→text/plain, .jpg→image/jpeg, .js→text/javascript, .css→text/css

## Switch TCP Stack Profile

From SYN/ACK packets:
- MSS: 1460
- Window Scale: 6 (effective window = 65535 * 64 = 4,194,240)
- SACK: enabled
- TCP Timestamps: enabled (starting value ~3.9 billion — high, possibly uptime-derived)
- Initial Window: 65535

TCP timestamp analysis: `TSval=3971998949` at t=0.013s. At 1000Hz, this is ~46 days uptime. At 100Hz, ~460 days. Could be used for uptime fingerprinting.

## Network Topology

DHCP analysis reveals:
- **Switch AP network**: 192.168.0.0/24, gateway=192.168.0.1 (Switch), DHCP from Switch
- **Home network**: 10.0.0.0/24, gateway=10.0.0.1 (Xfinity router), separate DHCP
- **PC (darkstar)**: 192.168.0.2 (WiFi, MAC 22:7c:ce:e0:bd:56) + 10.0.0.25 (Ethernet, MAC f4:3b:d8:ec:ae:0a)
- **Other home devices**: Samsung (10.0.0.6), OnePlus-13, iPhone-2, Spaceshuttle (a0:59:50:66:c2:90)

## Baseline Capture Protocol Stats (2.5 days, 316K frames)

| Protocol | Frames | Notes |
|----------|--------|-------|
| ARP | 188,376 | Mostly Switch AP ARP (192.168.0.1 ↔ 192.168.0.2) |
| HTTP | 1,320 | Multiple "Send to Smartphone" sessions |
| mDNS | 54,809 | IPv4 + IPv6 combined |
| DNS | 19,226 | Home network DNS |
| UDP data | 34,441 | Port 2021 broadcasts from 10.0.0.3 (NOT Switch) |
| SMB/Browser | 422 | Windows network discovery from home devices |
| IGMP | 1,275 | Multicast group management |
| ICMPv6 | 7,118 | IPv6 neighbor discovery |

## Beacon Analysis (Monitor Capture)

180 beacons + 4 probe responses over capture window.
- Beacon interval: 100ms (standard)
- Frame size: 288 bytes

**Information Elements:**
| IE | Tag | Details |
|----|-----|---------|
| SSID | 0 | 18 bytes: `switch_F3DCDB0100S` |
| Supported Rates | 1 | 8 rates (1/2/5.5/11/6/9/12/18 Mbps) |
| DS Parameter | 3 | Channel 1 |
| TIM | 5 | Traffic Indication Map |
| Country | 7 | US, 6 bytes |
| Power Constraint | 32 | 1 byte |
| TPC Report | 35 | 2 bytes |
| ERP Info | 42 | 1 byte |
| Extended Rates | 50 | 4 rates (24/36/48/54 Mbps) |
| RSN | 48 | 20 bytes: WPA2-PSK/CCMP |
| HT Capabilities | 45 | 26 bytes |
| HT Operation | 61 | 22 bytes |
| Extended Capabilities | 127 | 8 bytes |
| **Nintendo vendor** | 221 | OUI 00:22:aa, type 0x10, data: 01 01 |
| **Broadcom vendor** | 221 | OUI 00:10:18, type 0x02, data: 00 00 1c 00 00 |
| WMM/WME | 221 | OUI 00:50:f2, type 0x02, U-APSD enabled |

**Nintendo IE decode (OUI 00:22:aa):**
- Type: 0x10 (16)
- Data: 0x01 0x01
- Likely meaning: LDN protocol version 1, session type 1 (album transfer)

**Broadcom IE decode (OUI 00:10:18):**
- Type: 0x02
- Data: 00 00 1c 00 00
- Standard Broadcom capability advertisement

## Security-Relevant Observations

1. **No HTTPS**: All traffic unencrypted HTTP. MitM trivial for anyone on the AP.
2. **No auth tokens**: No cookies, no session IDs, no bearer tokens in any request.
3. **Connection: close always**: Server opens no persistent connections — each request is a fresh TCP connection. This limits connection-state attacks but means every request is independent.
4. **Minimal HTTP implementation**: No OPTIONS, no CORS, no content negotiation. This is a bare-minimum embedded HTTP server.
5. **data.json as text/plain**: JSON served as text/plain, not application/json — further evidence of hardcoded content types.
6. **File naming leaks title IDs**: `2026082120041401-0E7DF678130F4F0FA2C88AE72B47AFDF.jpg` — the hex suffix is a Nintendo title ID, potentially usable for fingerprinting game library.
