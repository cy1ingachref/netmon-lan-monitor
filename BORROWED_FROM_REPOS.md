# netmon — what I borrowed from the surveyed GitHub repos

This document records the *useful* ideas pulled from the topic-page survey
(you said: "if you think you can get useful things from those you can take it").
Nothing was copy-pasted; patterns were re-implemented to fit netmon's clean
Python package. The honest source tier is also noted so the PFE write-up is
credible.

## Tier 1 — established tools (benchmark targets, NOT copied)
These are the real league; netmon is a student/portfolio v1 next to them.
- **Zeek (7.9k★, C++)** — NSM framework. Borrowed *architecture idea*:
  separate protocol analyzers from policy/rule logic. netmon's `dissect.py`
  (parsers) vs `detect.py` (rules) mirrors this. Zeek's depth is far beyond.
- **NetXMS (393★, C++)** — full NMS (SNMP, topology). Idea: persistent
  device inventory + baselining. netmon's `devices.json` + `baseline.json`
  is a tiny version of this.
- **cyberprobe (174★, C++)** — capture + respond to attacks. Idea: alerts
  should be actionable. netmon's `alerts.log` + web alerts rail follows this.
- **bettercap** — whole-LAN via ARP-spoof. netmon keeps an *opt-in,
  authorization-gated* ARP-spoof path (not enabled by default) for true
  whole-LAN capture.

## Tier 2 — student repos (directly useful patterns adopted)
- **s-r-e-e-r-a-j/NetScope (20★, Python)** — discovery + live monitor.
  Adopted:
    * Manufacturer/vendor filter  (`netmon scan -m Apple`)
    * Scan-result export to file   (`netmon scan -o devices.csv`)
    * IP-range targeting + live interval (live monitor scaffolding)
- **Trewsaazz/ActiveConnectionScanner (6★, Python)** — blue-team IP
  reputation via AbuseIPDB. Adopted + improved:
    * `netmon/enrich.py`: offline-first local blocklist (zero config) PLUS
      opt-in AbuseIPDB API (`ABUSEIPDB_KEY` env / `enrich_config.json`).
    * Wired into `detect.run_detections(enrich=True)` and `sniff --enrich`
      so malicious IPs raise high-severity reputation alerts.
    * Legal difference: this only enriches IPs seen on YOUR LAN; it never
      scans external targets (unlike the repo's Windows-netstat approach,
      which is fine but we kept it LAN-scoped).

## Tier 3 — reviewed, rejected as not useful / not legal
- Vuln-Scanner-Exploit-Combo, sheepwall, advanced-ip-scanner-boost:
  contain botnet/brute/camera-scan or legal-gray behavior. Studied only for
  architecture; never adopted. (Consistent with the pentest hard-lines:
  no live/illegal targets, authorized-only.)

## What this means for the PFE
netmon now combines, in one clean package:
  discovery (ARP+ping+router-DHCP, vendor filter, CSV export)
  + content-aware capture (DNS/SNI/HTTP)
  + detection (indicators + baseline + behavioral + IP reputation)
  + visualization (cyberpunk localhost web UI)
  + honest accuracy comparison (vs the repo you originally sent)

That combination is broader than ~90% of the surveyed student repos and is a
credible security-portfolio piece. It is NOT a Zeek/NetXMS replacement — and
the write-up should say so plainly.
