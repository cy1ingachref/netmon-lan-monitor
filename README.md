# netmon — LAN Monitor + Blue/Red Defense Console

[![CI](https://github.com/cy1ingachref/netmon-lan-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/cy1ingachref/netmon-lan-monitor/actions/workflows/ci.yml)

A Windows-first local-network monitor that layers device identity, threat detection, and an authorized red-team lab on top of packet capture. It is a SOC-style console that uses Wireshark's own engine (tshark) for capture and dissection — not a Wireshark replacement.

## Overview

netmon operates in three escalating modes, each with a clear risk level:

| Mode | What it shows | How it works | Risk |
|------|---------------|--------------|------|
| **Discovery** (`scan`) | Device grid: IP, MAC, vendor, OS guess, router flagged `[ROUTER]` | ARP cache + ping sweep + router DHCP pull (passive) | Zero |
| **Traffic Analysis** (`sniff`) | Live DNS / SNI / HTTP from this host | tshark non-promiscuous on Wi-Fi (preserves L4) | Zero |
| **Red-Team Lab** (`sniff --arp-spoof`) | Full LAN traffic (other phones/laptops) | Gated ARP-spoof; restores ARP on exit | Ethical, but gated |

The honest layering is the project's core design principle: it proves a device is *present* passively, inspects its traffic with the host NIC, and only escalates to full-LAN visibility behind an explicit, reversible authorization gate.

## Scope (honest)

On a switched Wi-Fi LAN, host-only capture sees this machine plus broadcasts — not every other device's packets. "Seeing every device" = Discovery (who is present) + the opt-in, authorized redirect for their traffic. The tool says so plainly.

For full LAN visibility, use `--arp-spoof` (requires Administrator + typed authorization), a mirrored/SPAN port, or paste your router's DHCP table into `router_clients.txt`.

## How it uses Wireshark

`capture.py` detects `C:\Program Files\Wireshark\tshark.exe` and runs it as the primary capture backend:

- Writes a byte-valid `.pcap` AND streams dissected rows (DNS query+response, TLS SNI, HTTP host/method/UA, QUIC labelled) in parallel.
- Runs non-promiscuous (`-p`) on Wi-Fi, which preserves TCP/UDP content.
- Falls back to scapy if Wireshark isn't installed.

## What netmon adds over raw Wireshark

- Device discovery (ARP + ping + router DHCP) with vendor/OS/hostname.
- Live web UI (http://localhost:8080) with device grid + packet feed.
- Detection engine: indicator match (Tor/DoH/RAT ports, suspicious TLDs), baseline deviation (new device / MAC-spoof), beaconing.
- Authorized red-team lab (ARP-spoof / deauth-sim) gated behind a whitelist + typed confirmation; hard refusals against your IP/gateway.
- One-click `.pcap` export that opens in real Wireshark.

## Quick start

```bash
python -m netmon scan                  # discover all LAN devices
python -m netmon scan --fetch-router   # pull router DHCP table (read-only)
python -m netmon sniff [seconds]       # capture via tshark (host-only)
python -m netmon sniff --arp-spoof     # opt-in whole-LAN (admin+auth)
python -m netmon web                   # localhost cyberpunk UI
python -m netmon web --with-demo       # UI with live demo feed
python -m netmon view [capture.pcap]   # offline Wireshark-style pcap summary
python -m netmon compare               # accuracy comparison harness
```

Production install: `pip install -e .` then `netmon <cmd>` from anywhere. The zero-install path (`python -m netmon`) is identical.

## Tests

```bash
python -m unittest discover tests -v
```

Covers: tshark row parsing, ARP packet construction (safe — no injection), graceful backend failure handling, device identity merging, detection engine indicators.

## Requirements

- Windows 10/11, Python 3.11
- Wireshark (provides tshark + Npcap) — recommended, used automatically
- scapy (fallback capture if Wireshark absent)
- `--arp-spoof` needs Administrator + typed authorization

## License

MIT
