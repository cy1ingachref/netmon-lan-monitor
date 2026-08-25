# netmon — code review / upgrade brief

## What this project is
`netmon` is a Windows-first local-network monitor and SOC-style console. It layers
device discovery, a threat-detection engine, and an **authorized, opt-in red-team
lab** on top of packet capture. It is NOT a Wireshark replacement — it is a SOC
console that uses Wireshark's own engine (tshark) for capture + dissection, with a
scapy fallback.

- **Stack:** Python 3.11, Windows 10/11. Primary capture = `tshark.exe`
  (auto-detected at `C:\Program Files\Wireshark\tshark.exe`), fallback = `scapy`.
  Discovery pipeline is stdlib-only. **No external API keys, no paid services.**
- **Context / why it exists:** this is a school final-year project (PFE). The
  demonstrated goal is a tool that **detects and shows OTHER devices on the LAN,
  not just the localhost** — for a jury/defense demo. It also has a
  defense-vs-offense angle (detection engine + gated ARP-spoof lab).

## Commands (entry point: `python __main__.py`)
    scan                 # discover all LAN devices (ARP + ping + router DHCP)
    sniff [seconds]      # capture via tshark (host-only) + detect + report
    sniff --whole-lan    # promiscuous attempt (see Trouble #1)
    sniff --arp-spoof    # OPT-IN whole-LAN MITM (admin + typed auth, see arpspoof.py)
    web                  # localhost cyberpunk UI (http://localhost:8080)
    compare              # accuracy vs the reference repo

## Key files to look at
- `discover.py` — discovery (ARP cache, passive ARP, ping sweep, router DHCP list),
  OUI vendor resolution, OS-by-TTL, identity persistence (`devices.json`).
- `capture.py` / `dissect.py` — tshark-primary capture + content dissection
  (DNS, TLS SNI, HTTP host/method/UA, QUIC). Non-promiscuous on Wi-Fi by design.
- `detect.py` — detection engine (indicator match, baseline deviation / new device,
  MAC-spoof, beaconing).
- `webview.py` — localhost UI server.
- `arpspoof.py` — authorized red-team MITM (gated behind admin + typed
  `YES-I-AM-AUTHORIZED`; restores ARP on exit; unit-testable `build_spoof()`).
- `__main__.py` — CLI / subcommand wiring.
- `enrich.py`, `report.py`, `pcap_view.py`, `compare.py` — enrichment, report,
  pcap viewer, accuracy comparison helpers.

## What I'm having trouble with (please focus here)

### 1. The core problem: seeing OTHER devices on a switched Wi-Fi LAN
On a normal switched Wi-Fi/Ethernet LAN, a host-only capture only receives frames
addressed to its own MAC + broadcasts. So *live* capture shows this machine's
traffic + broadcasts — NOT every other device's packets. This is a physics limit
of switched networks, not a code bug.

What I have today:
- `sniff --whole-lan` (promiscuous): on Windows Wi-Fi, promiscuous mode **drops the
  L4 payload** (only link-layer headers survive) — so it's useless for content.
- `sniff --arp-spoof` (MITM): tells clients "I am the gateway", forwards, restores
  on exit. This DOES reveal other devices' traffic, but it's legally/ethically
  charged and needs Administrator + explicit authorization.

**Question:** for a clean, presentable jury demo (no legal/ethical gray area), what
is the most robust architecture to "see other devices"? Candidate directions:
  (a) a passive **router-fingerprint** mode (identify the router's IP/MAC/vendor
      via `route print -4` + `arp -a` — already partially done — and flag it
      distinctly),
  (b) **auto-pull the router's DHCP client list** from the router's web/HTTP API
      (the box is a TP-Link at 192.168.1.1) so every leased device appears with zero
      interference — currently this is a manual paste into `router_clients.txt`,
  (c) real **monitor mode** support (admin + capable adapter),
  (d) a clear "honest scope" framing that pairs passive discovery (who is there)
      with a clearly-gated MITM (their traffic) and documents the limit.
Which gives the best demo-to-risk ratio, and how should it be structured?

### 2. Possible bugs in the capture/dissect/detect pipeline
I had a bugged run where the capture produced no/garbage output (the traceback got
lost in a broken paste), so I can't pin the exact failure. **Please sanity-check the
pipeline for crashes or empty-capture edge cases**, specifically:
- tshark path detection and the `-T fields -e ...` dissector string (does it break
  on some tshark versions?),
- field parsing in `dissect.py` (malformed/truncated rows),
- report generation in `report.py` / `webview.py` when `records` is empty or None,
- the `whole_lan` + ARP-spoof coordination in `__main__.py::_run_whole_lan`.

### 3. Architecture & code quality for a PFE defense
Is the module separation clean? Any dead code, duplicated logic, or fragile imports
(note: `__main__.py` does `sys.path.insert(0, parent_of_package)` then
`from netmon import ...` — is that the right entry pattern)? How would you add a
small **test harness** (the `arpspoof.build_spoof()` returning bytes is already
unit-testable without injection — good)? I want this to look deliberate and
defensible, not cobbled together.

### 4. "Be the router without being the router"
Confirm whether passively reading the gateway IP (`route print -4`) + router MAC
(`arp -a`) is sufficient and safe for *identification*. And is there a safe,
non-MITM way to programmatically fetch the router's DHCP lease table (TP-Link
web API) so `router_clients.txt` is auto-populated?

## Honesty notes for the reviewer
- Please do NOT ask for API keys or paid services — the design is intentionally
  zero-cost and offline-capable.
- The current "sees other devices" story is split: passive discovery = *who is
  present*; full traffic visibility = gated MITM. That split is intentional and
  honest, but I want the demo to make it crystal clear rather than imply passive
  capture shows everyone's packets.
- Runtime artifacts (`.pcap`, `oui.json`, `devices.json`, logs) were excluded from
  this zip — re-run `scan` / `sniff` locally to regenerate them.
