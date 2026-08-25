# netmon - cyberpunk LAN monitor + blue/red defense console

A Windows-first local-network monitor that layers **device identity,
threat detection, and an authorized red-team lab** on top of packet capture.
It is *not* a Wireshark replacement — it is a SOC console that uses
**Wireshark's own engine** (tshark) for the capture + dissection.

## Three-Mode Demo (the narrative spine)

netmon is presented as three escalating modes, each with a clear risk level.
This honest layering is the project's core design principle: it proves a
device is *present* passively, inspects its traffic with the host NIC, and only
escalates to full-LAN visibility behind an explicit, reversible authorization
gate.

| Mode | What it shows | How it works | Risk |
|------|---------------|--------------|------|
| **Discovery** (`scan`) | Device grid: IP, MAC, vendor, OS guess, router flagged `[ROUTER]` | ARP cache + ping sweep + router DHCP pull (passive) | Zero |
| **Traffic Analysis** (`sniff`) | Live DNS / SNI / HTTP from this host | tshark non-promiscuous on Wi-Fi (preserves L4) | Zero |
| **Red-Team Lab** (`sniff --arp-spoof`) | Full LAN traffic (other phones/laptops) | Gated ARP-spoof; restores ARP on exit | Ethical, but gated |

Honest scope (same as Wireshark): on a switched Wi-Fi LAN, host-only capture
sees this machine + broadcasts — not every other device's packets. "Seeing
every device" = Discovery (who is present) + the opt-in, authorized redirect
for their traffic. The tool says so plainly.

## Offline operation & router credentials

If auto-pull fails (wrong router model, creds, or no network), paste your
router's DHCP client list into `router_clients.txt` (tab-separated:
`Hostname<TAB>MAC<TAB>IP`). **The tool works fully offline** — the file is
the authoritative source either way. Credentials for `--fetch-router` are
user-supplied (`--router-user` / `--router-pass`); nothing is hardcoded.

## How it uses Wireshark

`capture.py` detects `C:\Program Files\Wireshark\tshark.exe` and, when present,
runs it as the PRIMARY capture backend:

- `tshark -i <iface> -a duration:N -w out.pcap -F pcap -T fields -e ...`
  writes a byte-valid `.pcap` AND streams dissected rows (DNS query+response,
  TLS SNI, HTTP host/method/UA, QUIC labelled) in parallel.
- Runs **non-promiscuous** (`-p`) on Wi-Fi, which *preserves* TCP/UDP content
  (Windows promiscuous on Wi-Fi drops the L4 payload — the old scapy path's
  exact failure, now avoided).
- Falls back to scapy if Wireshark isn't installed.

**Honest scope (same as Wireshark):** on a switched Wi-Fi network your PC only
receives frames addressed to its own MAC + broadcasts, so *live* capture shows
this machine's traffic + broadcasts — not every other device's packets. To see
every device you need: monitor mode (admin + capable adapter), a mirrored/SPAN
port, or the opt-in ARP-spoof MITM (`sniff --arp-spoof`, admin + typed auth).
For plain visibility of *every device*, paste your router's DHCP table into
`router_clients.txt` — that is the authoritative device list regardless of
capture mode.

## What netmon adds over raw Wireshark

- Device discovery (ARP + ping + router DHCP) with vendor/OS/hostname.
- Live cyberpunk web UI (http://localhost:8080) with device grid + packet feed.
- Detection engine: indicator match (Tor/DoH/RAT ports/suspicious TLDs),
  baseline deviation (new device / MAC-spoof), beaconing.
- Authorized red-team lab (ARP-spoof / deauth-sim) gated behind a whitelist +
  typed confirmation; hard refusals against your IP/gateway. No offensive
  capability runs without explicit authorization.
- One-click `.pcap` export that opens in real Wireshark.

## Commands

    python __main__.py scan                  # discover all LAN devices
    python __main__.py scan --simulate-devices   # seed [SIMULATED] demo devices (empty-LAN)
    python __main__.py scan --fetch-router       # pull router DHCP table (read-only)
    python __main__.py scan --fetch-router --router-url http://...  # probe a custom endpoint
    python __main__.py sniff [seconds]       # capture via tshark (host-only)
    python __main__.py sniff --with-demo 20  # generate traffic to visualize
    python __main__.py sniff --whole-lan     # promiscuous attempt
    python __main__.py sniff --arp-spoof    # opt-in whole-LAN (admin+auth)
    python __main__.py web                   # localhost cyberpunk UI
    python __main__.py web --with-demo      # UI with live demo feed
    python __main__.py view [capture.pcap]   # offline Wireshark-style pcap summary
    python __main__.py compare               # accuracy vs the repo you sent

> Production install: `pip install -e .` then `netmon <cmd>` from anywhere.
> The zero-install path (`python __main__.py`) is identical.

## Files

- `capture.py` / `dissect.py` — capture (tshark-primary) + content dissection
- `discover.py` — device discovery + identity + OUI vendor
- `detect.py` — detection engine
- `webview.py` — localhost UI server (Discovery + Traffic Analysis control panel)
- `pcap_view.py` — offline pcap layer-tree / summary (wired to `netmon view`)
- `arpspoof.py` — authorized red-team MITM (gated)
- `router_fetch.py` — read-only router DHCP adapters (TP-Link Archer + luci stub + manual paste)
- `capture.pcap` / `packets_log.txt` / `devices.json` / `alerts.log` — artifacts
- `router_clients.txt` — paste DHCP table here for full device visibility

## Requirements

- Windows 10/11. Python 3.11.
- **Wireshark** (provides tshark + Npcap) — recommended, used automatically.
- scapy (fallback capture if Wireshark absent).
- `--arp-spoof` needs Administrator + typed authorization.
