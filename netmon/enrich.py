"""enrich.py - Blue-team IP reputation enrichment (offline-first, opt-in API).

Idea borrowed from ActiveConnectionScanner: enrich every seen IP against a
threat-intel source so the monitor can flag malicious connections, not just
match static indicators. Differences from that repo:
  * OFFLINE-FIRST: a built-in local blocklist works with zero config.
  * OPT-IN AbuseIPDB: only used if ABUSEIPDB_KEY env var / config is set.
  * No secrets required to get value; the API is a strict enhancement.

This is blue-team reputation scoring, fully legal for authorized monitoring of
your own LAN. It never performs scans against external targets.
"""
from __future__ import annotations

import json
import os
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REP_FILE = os.path.join(_HERE, "reputation.json")
_CONFIG = os.path.join(_HERE, "enrich_config.json")

# Curated high-confidence malicious/abuse infrastructure (offline fallback).
# Updated as of build; extend as needed. These are well-known bad ranges/names.
LOCAL_BLOCKLIST = {
    # Common C2 / malware callback hosts (publicly documented takedown lists)
    "185.220.101.": "known Tor exit / abuse range",
    "45.155.205.": "reported malware C2 range",
    "194.165.16.": "reported scanner/botnet range",
    "91.219.236.": "reported botnet range",
    # You can paste your own observed-bad IPs here or into reputation.json
}


def load_config() -> dict:
    try:
        with open(_CONFIG, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_blocklist(entries: dict):
    try:
        cur = {}
        if os.path.exists(REP_FILE):
            with open(REP_FILE, "r", encoding="utf-8") as f:
                cur = json.load(f)
        cur.update(entries)
        with open(REP_FILE, "w", encoding="utf-8") as f:
            json.dump(cur, f, indent=2)
    except Exception:
        pass


def _local_rep(ip: str) -> tuple[int, str]:
    """Return (score 0-100, reason) from the offline blocklist."""
    for prefix, why in LOCAL_BLOCKLIST.items():
        if ip.startswith(prefix):
            return 90, why
    try:
        with open(REP_FILE, "r", encoding="utf-8") as f:
            user = json.load(f)
        if ip in user:
            v = user[ip]
            if isinstance(v, dict):
                return int(v.get("score", 80)), v.get("reason", "user blocklist")
            return 80, "user blocklist"
    except Exception:
        pass
    return 0, ""


def _abuseipdb(ip: str, key: str) -> tuple[int, str]:
    """Query AbuseIPDB (opt-in). Returns (score 0-100, reason)."""
    try:
        import urllib.request
        import urllib.parse
        url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + urllib.parse.quote(ip) + "&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.load(r)
        sc = int(data.get("data", {}).get("abuseScore", 0))
        return sc, f"AbuseIPDB abuseScore={sc}"
    except Exception as e:
        return 0, f"AbuseIPDB query failed: {e}"


def enrich_ip(ip: str) -> dict:
    """Return a reputation verdict for an IP. Always works offline."""
    score, reason = _local_rep(ip)
    src = "local"
    cfg = load_config()
    key = cfg.get("abuseipdb_key") or os.environ.get("ABUSEIPDB_KEY")
    # Only escalate to API if local is clean (save quota) or config forces it.
    if key and score == 0:
        sc, why = _abuseipdb(ip, key)
        if sc > 0:
            score, reason, src = sc, why, "abuseipdb"
    return {
        "ip": ip,
        "score": score,
        "reason": reason,
        "source": src,
        "malicious": score >= 50,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def enrich_ips(ips: set) -> list:
    return [enrich_ip(ip) for ip in ips if ip]
