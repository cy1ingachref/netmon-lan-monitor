# Jury Demo Script (tape this to your desk during the defense)

netmon is shown in THREE escalating modes. Lead with the zero-risk modes;
present the gated red-team lab as code-complete + authorization-gated. If the
demo laptop has no admin or no other LAN host, SKIP phase 3 and say:
"the capability exists but is gated; physics + authorization prevent a live demo here."

==================================================================
PHASE 1 — DISCOVERY (zero risk)
------------------------------------------------------------------
Command:  python -m netmon scan --fetch-router
Say:      "First I see every device on the LAN without sending a single
           malicious packet. The router's own DHCP table is the authoritative
           source — even phones that are asleep show up. The gateway is flagged
           [ROUTER], identified passively via the OS routing table + ARP cache."
Pass:     Device grid prints; router tagged; (if --fetch-router reaches your
           router) other phones/laptops appear from the DHCP lease table.

==================================================================
PHASE 2 — TRAFFIC ANALYSIS (zero risk)
------------------------------------------------------------------
Command:  python -m netmon sniff --with-demo 20
Say:      "Second, I analyze traffic from THIS host using Wireshark's own
           engine (tshark). On a switched Wi-Fi LAN, physics limits me to my
           own frames — same as Wireshark. I recover DNS, TLS SNI, and HTTP
           from the host NIC without promiscuous mode (which would strip L4
           on Windows Wi-Fi)."
Pass:     Live feed shows dns=/sni=/http= lines. netmon_report.html written.

==================================================================
PHASE 3 — RED-TEAM LAB (gated; only if authorized + admin)
------------------------------------------------------------------
Command:  python -m netmon sniff --arp-spoof 60   (run as Administrator)
Say:      "Third, IF I own the network and have explicit authorization, I can
           opt into a reversible ARP-spoof bridge. It forwards victims' traffic
           so they stay online, and restores ARP on exit. This is the only way
           to see other devices' traffic on a switched LAN — and it is gated by
           admin rights + a typed confirmation."
Gate:     Requires admin. You must type YES-I-AM-AUTHORIZED. Refuses otherwise.
Pass:     Phone stays online (YouTube loads); web UI shows phone's IP with
           dns=/sni=; Ctrl-C restores ARP cleanly.

==================================================================
WEB UI (optional, any phase)
------------------------------------------------------------------
Command:  python -m netmon web
Open:     http://localhost:8080  (cyberpunk dashboard; gateway banner on top)
Control:  Click "Scan Network" / "Start Capture" / "Stop Capture" / "Export CSV"
          in the browser — the web UI now drives Discovery + Traffic Analysis.
          ARP-spoof stays CLI-only (see Phase 3); the UI shows that explicitly.

==================================================================
DEFENSE SOUND-BITES
------------------------------------------------------------------
* "netmon proves a device is PRESENT passively, inspects its traffic with the
   host NIC, and only escalates to full-LAN visibility behind an explicit,
   reversible authorization gate."
* "It never claims passive capture sees everyone's packets — that's a network
   fact, not a bug."
* "The router DHCP pull is read-only GET, ethically equivalent to logging into
   the router's admin page. Not MITM, not interception."
* Accuracy: compare.py shows netmon 100% content/alert extraction vs the
   baseline repo's 0%.

==================================================================
KNOWN LIMITATIONS (state them before they ask)
------------------------------------------------------------------
* Switched Wi-Fi only shows this host + broadcasts in host-only mode.
* Full-LAN requires the gated ARP-spoof (admin + authorized LAN).
* "localhost" means THIS machine only (127.0.0.1). You cannot passively see
  other devices' traffic through localhost — that's impossible on a switched
  LAN (same limit as Wireshark). "See everything" = Phase 3 ARP-spoof, not
  localhost. Do not let the jury confuse the two.
* Router DHCP auto-pull needs your router model/creds; if it fails, paste the
  DHCP table into router_clients.txt — the tool works fully offline.
