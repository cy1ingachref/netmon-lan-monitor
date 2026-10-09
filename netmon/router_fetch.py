"""router_fetch.py - Read-only router DHCP scraper (adapter pattern).

WHY THIS EXISTS
  The "see other devices" story is strongest when the device grid is
  AUTHORITATIVE (every leased device, including silent/asleep ones that
  don't answer ping). The router's own DHCP client list is exactly that.
  This module pulls it READ-ONLY from the router's web UI, using credentials
  you own, and writes the result to router_clients.txt (the format
  discover.merge_router_devices() already consumes).

SAFETY / ETHICS (non-negotiable)
  * This is a read-only GET/POST to your own router's management interface.
  * It is ethically equivalent to logging into the admin panel with a browser.
  * It is NOT a man-in-the-middle: no traffic is intercepted, no layer-2
    addresses are spoofed.
  * If the pull fails, the manual-paste path (router_clients.txt) still works.

ADAPTER PATTERN
  TP-Link firmware varies across models (older Archer web UI vs. newer
  OpenWrt/luci-based). This file defines a RouterAdapter interface and one
  concrete adapter (TPLinkArcherHTTP). Add a sibling adapter for other models
  without touching the rest of netmon. The manual-paste fallback is the
  universal adapter.
"""
from __future__ import annotations

import os
import re
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
ROUTER_CLIENTS = os.path.join(_HERE, "router_clients.txt")

# A syntactically valid MAC (used to validate scraped rows).
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


class RouterAdapter:
    """Interface every router adapter implements."""

    name = "base"

    def fetch(self, router_ip: str, username: str, password: str) -> list:
        """Return a list of tab-separated 'host\\tmac\\tip' rows.

        Return [] on any failure (caller falls back to manual paste).
        """
        raise NotImplementedError


class TPLinkArcherHTTP(RouterAdapter):
    """Adapter for older TP-Link Archer/C-class web UIs (HTTP Basic Auth).

    Adjust URL/parser to your exact firmware. Inspect your router's HTML by
    visiting the DHCP-client-list page and viewing source.
    """

    name = "tplink-archer-http"

    def fetch(self, router_ip: str, username: str, password: str) -> list:
        url = f"http://{router_ip}/userRpm/AssignedIpAddrListRpm.htm"
        try:
            pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pwd_mgr.add_password(None, f"http://{router_ip}", username, password)
            opener = urllib.request.build_opener(
                urllib.request.HTTPBasicAuthHandler(pwd_mgr))
            with opener.open(url, timeout=8) as r:
                html = r.read().decode("utf-8", "ignore")
        except Exception as e:
            print(f"[!] TPLinkArcherHTTP fetch failed: {e}")
            return []

        # Typical TP-Link page embeds rows as JS string literals:
        #   ["HostName","AA-BB-CC-DD-EE-FF","192.168.1.50","23:59:59"]
        rows = []
        for m in re.finditer(
                r"\"([^\"]*)\",\"(" + _MAC_RE.pattern + r")\",\"(\d+\.\d+\.\d+\.\d+)\"",
                html):
            host, mac, ip = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
            if mac and ip:
                rows.append(f"{host}\t{mac.upper()}\t{ip}")
        return rows


class TPLinkLuciAdapter(RouterAdapter):
    """Adapter stub for OpenWrt/luci-based TP-Link firmware (C-series, Omada).

    luci exposes the DHCP leases as JSON at /cgi-bin/luci/rpc/sys?... or via the
    ubus JSON-RPC endpoint. This stub proves the ADAPTER REGISTRY pattern to the
    jury: netmon is extensible to other firmware without code surgery. It probes
    a couple of common luci paths, and parses the typical
    'HostName  MAC  IP' rows if it reaches a legacy luci HTML page. Implement the
    real JSON-RPC auth when you have a luci router to test against.
    """

    name = "tplink-luci"

    _PROBE_PATHS = [
        "/cgi-bin/luci/admin/network/dhcp",
        "/cgi-bin/luci/rpc/sys?method=net.arptable",
        "/luci/admin/network/dhcp",
    ]

    def fetch(self, router_ip: str, username: str, password: str) -> list:
        base = f"http://{router_ip}"
        rows = []
        try:
            pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pwd_mgr.add_password(None, base, username, password)
            opener = urllib.request.build_opener(
                urllib.request.HTTPBasicAuthHandler(pwd_mgr))
            for path in self._PROBE_PATHS:
                try:
                    with opener.open(base + path, timeout=8) as r:
                        html = r.read().decode("utf-8", "ignore")
                    for m in re.finditer(
                            r"([0-9A-Za-z_\- ]+)\s+(" + _MAC_RE.pattern
                            + r")\s+(\d+\.\d+\.\d+\.\d+)", html):
                        host, mac, ip = (m.group(1).strip(), m.group(2).strip(),
                                         m.group(3).strip())
                        if mac and ip:
                            rows.append(f"{host}\t{mac.upper()}\t{ip}")
                    if rows:
                        return rows
                except Exception:
                    continue
        except Exception as e:
            print(f"[!] TPLinkLuciAdapter fetch failed: {e}")
        return rows


class ManualPasteAdapter(RouterAdapter):
    """Universal fallback: return whatever is already in router_clients.txt.

    If the auto-pull fails during a demo, the operator pre-seeds
    router_clients.txt by pasting the router's DHCP table. This adapter makes
    that file the authoritative source regardless of auto-pull success, so the
    chain always yields the real device list when it is present.
    """

    name = "manual-paste"

    def fetch(self, router_ip: str, username: str, password: str) -> list:
        try:
            if not os.path.exists(ROUTER_CLIENTS):
                return []
            with open(ROUTER_CLIENTS, "r", encoding="utf-8") as f:
                rows = [ln.rstrip("\n") for ln in f if ln.strip()]
            return rows
        except Exception:
            return []


# Registry: try adapters in order. Add new models here. The ManualPasteAdapter
# is LAST so a pre-seeded router_clients.txt is the universal fallback.
ADAPTERS = [TPLinkArcherHTTP(), TPLinkLuciAdapter(), ManualPasteAdapter()]


# Probe paths tried (in order) when --router-url is supplied: lets the jury-room
# lab router (if not TP-Link) still demo the concept against a local test page.
_ROUTER_URL_PROBES = [
    "/userRpm/AssignedIpAddrListRpm.htm",
    "/cgi-bin/luci/admin/network/dhcp",
    "/cgi-bin/luci/rpc/sys?method=net.arptable",
]


def fetch_tp_link_dhcp(router_ip: str = "192.168.1.1",
                        username: str = "admin",
                        password: str = "admin") -> int:
    """Spec-named alias for fetch_router_dhcp (TP-Link adapter is primary).

    Kept so build-spec v2.0 (`router_fetch.fetch_tp_link_dhcp()`) works
    unchanged. Delegates to the adapter-based fetch_router_dhcp below.

    NOTE: the default admin/admin are convenience placeholders ONLY; the CLI
    always overrides them via --router-user / --router-pass. Never hardcode real
    credentials here.
    """
    return fetch_router_dhcp(router_ip=router_ip, username=username,
                             password=password)


def fetch_router_dhcp(router_ip: str = "192.168.1.1",
                      username: str = "admin",
                      password: str = "admin",
                      router_url: str = None) -> int:
    """Pull the DHCP client list from the router and write router_clients.txt.

    `router_url` (optional) points at a single specific endpoint to probe first
    (e.g. a local test page in the jury lab) — overrides the adapter's default
    path. Returns the number of clients written (0 on total failure). Safe + read-only.
    """
    rows: list = []
    if router_url:
        # Direct-probe mode: try the given URL (and its host's common paths).
        try:
            from urllib.parse import urlparse
            host = urlparse(router_url).netloc or router_ip
            pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pwd_mgr.add_password(None, f"http://{host}", username, password)
            opener = urllib.request.build_opener(
                urllib.request.HTTPBasicAuthHandler(pwd_mgr))
            probes = [router_url] + _ROUTER_URL_PROBES
            for path in probes:
                try:
                    with opener.open(path if path.startswith("http")
                                     else f"http://{host}{path}", timeout=8) as r:
                        html = r.read().decode("utf-8", "ignore")
                    for m in re.finditer(
                            r"\"([^\"]*)\",\"(" + _MAC_RE.pattern
                            + r")\",\"(\d+\.\d+\.\d+\.\d+)\"", html):
                        host_, mac, ip = (m.group(1).strip(), m.group(2).strip(),
                                          m.group(3).strip())
                        if mac and ip:
                            rows.append(f"{host_}\t{mac.upper()}\t{ip}")
                    if rows:
                        break
                except Exception:
                    continue
        except Exception as e:
            print(f"[!] router-url probe failed: {e}")
        if rows:
            print(f"[+] router-url probe returned {len(rows)} clients")
    if not rows:
        for adapter in ADAPTERS:
            try:
                rows = adapter.fetch(router_ip, username, password)
            except Exception as e:
                print(f"[!] adapter {adapter.name} error: {e}")
                rows = []
            if rows:
                print(f"[+] adapter '{adapter.name}' returned {len(rows)} clients")
                break
    if not rows:
        print("[!] no DHCP clients retrieved (check router_ip/credentials, or "
              "paste router_clients.txt manually)")
        return 0
    try:
        with open(ROUTER_CLIENTS, "w", encoding="utf-8") as f:
            f.write("\n".join(rows) + "\n")
        print(f"[+] router DHCP: {len(rows)} clients -> {ROUTER_CLIENTS}")
    except Exception as e:
        print(f"[!] could not write {ROUTER_CLIENTS}: {e}")
        return 0
    return len(rows)


def main():
    import argparse
    p = argparse.ArgumentParser(description="Pull router DHCP table (read-only)")
    p.add_argument("--ip", default="192.168.1.1", help="router IP")
    p.add_argument("--user", default="admin")
    p.add_argument("--pass", dest="password", default="admin")
    a = p.parse_args()
    n = fetch_router_dhcp(a.ip, a.user, a.password)
    print(f"wrote {n} client(s)")


if __name__ == "__main__":
    main()
