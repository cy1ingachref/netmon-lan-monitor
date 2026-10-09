"""detect.py - Detection engine (indicators + baseline + behavioral).

Three offline layers, all operating on dissect records so they are testable
without a live NIC:

  1. INDICATORS - match SNI/DNS/port against a built-in block/caution list
     (Tor, DoH/DoT resolvers, RAT/scan ports, suspicious TLDs). Extensible.
  2. BASELINE    - learn the normal device set + port profile over N scans;
     alert on deviation (new MAC on known IP, vendor-class change).
  3. BEHAVIORAL  - beaconing / repeated single-destination contact.

This is the detection layer the original repo you sent COMPLETELY LACKS
(it only printed IP/port/proto + a 40-char ASCII preview). The comparison
harness quantifies that gap.
"""
from __future__ import annotations

import json
import os
import time
from netmon import discover  # module-level so learn_baseline AND check_baseline both see it

_HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(_HERE, "baseline.json")
ALERTS_FILE = os.path.join(_HERE, "alerts.log")

SUSPICIOUS_SNI_DNS = [
    ("torproject.org", "high", "Tor anonymizer traffic"),
    (".onion", "high", "Tor hidden service"),
    ("dns.google", "low", "DoH/DoT public resolver (Google)"),
    ("1.1.1.1", "low", "DoH/DoT public resolver (Cloudflare)"),
    ("cloudflare-dns", "low", "DoH/DoT public resolver (Cloudflare)"),
    ("pastebin.com", "medium", "paste site - possible exfil/C2 staging"),
    ("raw.githubusercontent.com", "low", "GitHub raw - possible payload fetch"),
    ("ngrok.io", "medium", "tunneling/proxy - possible C2"),
    ("trycloudflare.com", "medium", "tunneling/proxy (cloudflared) - possible C2"),
    ("bit.ly", "low", "URL shortener - possible phishing/C2"),
]

SUSPICIOUS_PORTS = {
    4444: ("high", "Metasploit/default RAT port"),
    31337: ("high", "Back Orifice / elite port"),
    6667: ("medium", "IRC - possible C2 beacon"),
    23: ("high", "Telnet - cleartext, risky"),
    512: ("medium", "rlogin"), 513: ("medium", "rlogin/rsh"),
    514: ("medium", "rsh/syslog"), 3306: ("low", "MySQL exposed"),
    6379: ("medium", "Redis exposed - common RCE"), 11211: ("high", "Memcached exposed"),
    9200: ("medium", "Elasticsearch exposed"), 5900: ("medium", "VNC"),
}

SUSPICIOUS_TLDS = (".xyz", ".top", ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".pw", ".su")


def _sev_rank(sev):
    return {"high": 3, "medium": 2, "low": 1}.get(sev, 1)


def check_indicators(rec: dict) -> list:
    alerts = []
    subj = (rec.get("sni") or "") + " " + (rec.get("dns") or "")
    low = subj.lower()
    for frag, sev, why in SUSPICIOUS_SNI_DNS:
        if frag in low:
            alerts.append({"type": "indicator", "severity": sev, "reason": why,
                           "subject": subj.strip(), "src": rec.get("src"),
                           "dst": rec.get("dst"), "ts": rec.get("ts")})
            break
    host = (rec.get("sni") or rec.get("dns") or "").lower()
    if host:
        for tld in SUSPICIOUS_TLDS:
            # Match the actual trailing TLD only (not a substring inside a
            # subdomain, e.g. sub.xyz.google.com must NOT alert on .xyz).
            parts = host.split(".")
            if parts and parts[-1] == tld.lstrip("."):
                alerts.append({"type": "indicator", "severity": "low",
                               "reason": f"uncommon TLD {tld}", "subject": host,
                               "src": rec.get("src"), "dst": rec.get("dst"),
                               "ts": rec.get("ts")})
                break
    for port in (rec.get("dport"), rec.get("sport")):
        if port and port in SUSPICIOUS_PORTS:
            sev, why = SUSPICIOUS_PORTS[port]
            alerts.append({"type": "indicator", "severity": sev, "reason": why,
                           "subject": f"port {port}", "src": rec.get("src"),
                           "dst": rec.get("dst"), "ts": rec.get("ts")})
    return alerts


def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"devices": {}, "scans": 0}


def save_baseline(b):
    try:
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(b, f, indent=2)
    except Exception:
        pass


def learn_baseline(devices: dict, cidr: str):
    from netmon import discover
    b = load_baseline()
    b["scans"] += 1
    for ip, mac in devices.items():
        key = discover.device_key(mac, ip)
        if key not in b["devices"]:
            b["devices"][key] = {"ip": ip, "mac": discover.mac_of(mac).upper(),
                                 "vc": discover.mac_of(mac)[:8].upper(),
                                 "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")}
        else:
            b["devices"][key]["ip"] = ip
    save_baseline(b)
    return b


def check_baseline(devices: dict, cidr: str) -> list:
    b = load_baseline()
    alerts = []
    if b["scans"] < 1:
        return alerts
    known = set(b["devices"].keys())
    for ip, mac in devices.items():
        key = discover.device_key(mac, ip)
        if key not in known:
            alerts.append({"type": "baseline", "severity": "medium",
                           "reason": "new device never seen in baseline",
                           "subject": f"{ip} ({mac})", "src": ip, "dst": "",
                           "ts": time.strftime("%H:%M:%S")})
            continue
        base_vc = b["devices"][key].get("vc", "")
        cur_vc = (discover.mac_of(mac) or "?")[:8].upper()
        # Exclude placeholder OUIs: if a device was first seen with an empty
        # MAC (router DHCP with no MAC column), the baseline stored vc="?" and
        # a later ARP-resolved real MAC would otherwise trip a false "MAC spoof".
        if (base_vc and base_vc not in ("?", "") and
                cur_vc and cur_vc not in ("?", "") and
                base_vc != cur_vc):
            alerts.append({"type": "baseline", "severity": "high",
                           "reason": "vendor class changed on known device (MAC spoof?)",
                           "subject": f"{ip} ({mac})", "src": ip, "dst": "",
                           "ts": time.strftime("%H:%M:%S")})
    return alerts


def analyze_traffic(records: list, threshold: int = 60) -> list:
    alerts = []
    per_pair = {}
    for r in records:
        if not r.get("src") or not r.get("dst"):
            continue
        pair = (r["src"], r["dst"])
        per_pair[pair] = per_pair.get(pair, 0) + 1
    for (src, dst), n in per_pair.items():
        if n >= threshold:
            alerts.append({"type": "behavioral", "severity": "medium",
                           "reason": f"repeated contact {n}x to single destination (beacon/C2?)",
                           "subject": f"{src} -> {dst}", "src": src, "dst": dst,
                           "ts": time.strftime("%H:%M:%S")})
    return alerts


def run_detections(records: list, devices: dict = None, cidr: str = "",
                   enrich: bool = False) -> list:
    # Defensive: never iterate over None (cli.py already guards, but the
    # function should be safe when called directly / from tests).
    if not records:
        records = []
    all_a = []
    for rec in records:
        all_a.extend(check_indicators(rec))
    all_a.extend(analyze_traffic(records))
    if devices is not None:
        all_a.extend(check_baseline(devices, cidr))
    if enrich:
        try:
            from netmon import enrich as enrich_mod
            ips = set()
            for r in records:
                if r.get("dst"):
                    ips.add(r["dst"])
                if r.get("src"):
                    ips.add(r["src"])
            for v in enrich_mod.enrich_ips(ips):
                if v["malicious"]:
                    all_a.append({"type": "reputation", "severity": "high",
                                  "reason": f"malicious IP ({v['score']}): {v['reason']}",
                                  "subject": v["ip"], "src": v["ip"], "dst": "",
                                  "ts": v["checked_at"]})
        except Exception:
            pass
    seen = set()
    uniq = []
    for a in all_a:
        k = (a["type"], a.get("subject", ""), a.get("reason", ""))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(a)
    uniq.sort(key=lambda a: -_sev_rank(a["severity"]))
    if uniq:
        try:
            with open(ALERTS_FILE, "a", encoding="utf-8") as f:
                for a in uniq:
                    f.write(f"[{a.get('ts','')}] {a['severity'].upper()} "
                            f"{a['type']}: {a['reason']} | {a.get('subject','')}\n")
        except Exception:
            pass
    return uniq
