"""capture.py - Live packet capture -> dissected records + real .pcap.

Design:
  * scapy is PRIMARY. We keep raw scapy packets AND build dissected records.
  * Writes a genuine .pcap (wrpcap) openable in real Wireshark.
  * `--whole-lan` uses promisc=True. HONEST NOTE (Wireshark/bettercap reality):
    on a Windows Wi-Fi adapter promiscuous mode captures raw 802.11 and DROPS
    TCP/UDP content. True whole-LAN needs an Ethernet into a mirrored/span port
    or an adapter in monitor mode. We report the actual mode, never claim more
    than we observe.
  * For authorized whole-LAN on a normal LAN, the proven approach (bettercap)
    is ARP-spoof the gateway so other devices' traffic routes through you. That
    is implemented as an OPT-IN, authorization-gated module (see arp_spoof.py)
    and is NEVER on by default.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
PACKETS_LOG = os.path.join(_HERE, "packets_log.txt")
PCAP_FILE = os.path.join(_HERE, "capture.pcap")
DEVICES_DB = os.path.join(_HERE, "devices.json")
DEVICES_LOG = os.path.join(_HERE, "devices_log.txt")
ALERTS_LOG = os.path.join(_HERE, "alerts.log")
BASELINE = os.path.join(_HERE, "baseline.json")
REPORT = os.path.join(_HERE, "netmon_report.html")
WHOLE_LAN_MARKER = os.path.join(_HERE, "whole_lan.active")


def set_whole_lan_active(on: bool):
    """Cross-process signal so the web UI can show a WHOLE-LAN banner
    while an opt-in ARP-spoof capture is running."""
    try:
        if on:
            with open(WHOLE_LAN_MARKER, "w", encoding="utf-8") as f:
                f.write("arp-spoof active\n")
        else:
            if os.path.exists(WHOLE_LAN_MARKER):
                os.remove(WHOLE_LAN_MARKER)
    except Exception:
        pass


def is_whole_lan_active() -> bool:
    return os.path.exists(WHOLE_LAN_MARKER)


def clear_artifacts():
    """Delete stale capture/scan artifacts so a new run starts clean
    (old packets/devices/alerts no longer pollute the live view)."""
    for p in (PACKETS_LOG, PCAP_FILE, DEVICES_DB, DEVICES_LOG,
              ALERTS_LOG, BASELINE, REPORT, WHOLE_LAN_MARKER):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass


from . import dissect


# ---------------------------------------------------------------------------
# tshark backend  (Wireshark's own capture + dissection engine)
# ---------------------------------------------------------------------------
# Wireshark captures through Npcap exactly like scapy does, so on a switched
# Wi-Fi network it sees the SAME other-device traffic as our scapy path. The
# reason to prefer tshark as PRIMARY is its dissectors are far richer than what
# we hand-roll in scapy: real DNS query+response, TLS SNI (the cleartext site
# behind HTTPS), full HTTP host/method/UA, and QUIC/HTTP3 labelled. It also
# guarantees a byte-valid .pcap (so the "open in Wireshark" button always
# works). We run it NON-promiscuous (-p) which on Wi-Fi preserves TCP/UDP
# content (Windows promiscuous on Wi-Fi drops the L4 payload).
# ---------------------------------------------------------------------------

def tshark_path() -> str | None:
    """Locate the tshark.exe that ships with Wireshark."""
    cands = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return shutil.which("tshark")


def _native_path(p: str) -> str:
    """Convert an MSYS/Cygwin /c/Users/... path to a native C:\\Users\\... path
    so the Windows tshark.exe can open the file."""
    if p.startswith("/") and ":" not in p.split("/")[0]:
        # /c/Users/cy1in/...  -> C:\Users\cy1in\...
        parts = p.split("/")
        drive = parts[1]
        if len(drive) == 1:
            return drive.upper() + ":\\" + "\\".join(parts[2:])
    return p


def _tshark_ifaces():
    """Return {idx_or_name: description} from `tshark -D` (the names tshark
    actually accepts for `-i`). Empty dict if tshark is absent."""
    try:
        out = subprocess.run([tshark_path(), "-D"], capture_output=True,
                             text=True, timeout=15).stdout
    except Exception:
        return {}
    res = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\.\s+(.*)", line)
        if m:
            res[m.group(1)] = m.group(2)
    return res


def _resolve_iface(explicit=None, my_ip=""):
    """Pick the ACTUAL capture interface string the active backend accepts.

    The earlier bug: scapy's `conf.ifaces` name (e.g. 'Wi-Fi') was passed to
    tshark, but tshark's `-i` expects ITS OWN `-D` name (often a longer string
    like 'Wireless LAN Wi-Fi' or an NPF GUID). When they mismatch, tshark binds
    nothing and the capture reports 0 packets forever.

    Fix: build the candidate set from the backend's real interface list and
    prefer the one carrying our LAN IP, then a Wi-Fi/WLAN keyword match, then
    the first real interface. Returns a string both backends can use.
    """
    if explicit:
        return explicit
    ts_if = _tshark_ifaces()  # {idx: desc}
    # Build a searchable list: (candidate_string, description_lower)
    cands = []
    for idx, desc in ts_if.items():
        cands.append((idx, desc.lower()))
        cands.append((desc, desc.lower()))  # tshark also accepts the name
    # 1) interface whose description contains our LAN IP wins (most reliable)
    if my_ip:
        want = my_ip.replace(".", "")
        for c, dl in cands:
            if want in dl.replace("-", "").replace(" ", ""):
                return c
    # 2) a Wi-Fi / WLAN / Wireless description
    for c, dl in cands:
        if "wi-fi" in dl or "wlan" in dl or "wireless" in dl:
            return c
    # 3) first real NPF/Wi-Fi interface (skip loopback/adapter descriptors)
    for c, dl in cands:
        if "loopback" in dl or dl.startswith("lo"):
            continue
        return c
    # 4) fall back to scapy's view if tshark gave nothing
    try:
        from scapy.all import conf
        for i in conf.ifaces.values():
            nm = (getattr(i, "name", "") or "").lower()
            if "wi-fi" in nm or "wlan" in nm or "wireless" in nm:
                return i.name
    except Exception:
        pass
    return "1"


def _pick_tshark_iface(explicit=None, my_ip=""):
    """Map a capture interface for tshark."""
    return _resolve_iface(explicit, my_ip)


def _pick_wlan_iface(explicit=None):
    """Pick the capture interface (validated against tshark's real list)."""
    return _resolve_iface(explicit)


# Fields tshark extracts in parallel with writing the pcap. These ARE the
# Wireshark dissector outputs - same fields Wireshark shows in its columns.
TSHARK_FIELDS = [
    "frame.number", "eth.src", "eth.dst", "frame.time_relative", "ip.src", "ip.dst",
    "ip.ttl", "_ws.col.Protocol", "ip.proto",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.resp.name",
    "tls.handshake.extensions_server_name",
    "http.host", "http.request.method", "http.user_agent",
    "tcp.flags",
]
# Tab separator: it NEVER appears inside valid dissector output, so a protocol
# that yields multiple values cannot shift our column layout.
TSHARK_FIELD_SEP = "\t"


def _parse_tshark_row(line: str, my_ip: str) -> dict | None:
    cols = line.rstrip("\n").split(TSHARK_FIELD_SEP)
    # tshark may emit fewer columns than TSHARK_FIELDS when trailing fields are
    # empty; pad so downstream indexing is always safe.
    if len(cols) < len(TSHARK_FIELDS):
        cols += [""] * (len(TSHARK_FIELDS) - len(cols))
    def g(i):
        v = cols[i].strip() if i < len(cols) else ""
        return v
    eth_src = g(1); eth_dst = g(2)
    src = g(4); dst = g(5)
    trel = g(3)
    try:
        ts = f"{float(trel):.3f}" if trel else ""
    except Exception:
        ts = ""
    ttl = int(g(6)) if g(6).isdigit() else 0
    proto_col = g(7)
    proto_num = int(g(8)) if g(8).isdigit() else 0
    sport = int(g(9)) if g(9).isdigit() else 0
    dport = int(g(10)) if g(10).isdigit() else 0
    uport = int(g(11)) if g(11).isdigit() else 0
    udport = int(g(12)) if g(12).isdigit() else 0
    dns_q = g(13); dns_r = g(14)
    sni = g(15)
    http_host = g(16); http_method = g(17); http_ua = g(18)
    flags = g(19)

    if not src or not dst or src == "0.0.0.0" or dst == "0.0.0.0":
        return None  # non-IPv4 frame (e.g. ARP/LLC) - scapy path handles those

    # Build a dissect-style record (same schema as dissect.dissect_record)
    rec = {"ts": ts, "src": src, "dst": dst, "eth_src": eth_src, "eth_dst": eth_dst,
           "proto": "",
           "sport": 0, "dport": 0, "ttl": ttl,
           "dns": "", "sni": "", "http": "", "app": "", "browser": "",
           "_flags": flags}
    # Normalize sport/dport across tcp/udp
    if proto_num == 6:
        rec["sport"], rec["dport"] = sport, dport
    elif proto_num == 17:
        rec["sport"], rec["dport"] = uport, udport
    pname = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, proto_col or str(proto_num))
    rec["proto"] = pname
    # Enrich via the existing dissect heuristics (app/browser labelling)
    dissect._enrich_record(rec, (dns_q or dns_r or ""), sni or "",
                           (http_host or ""), (http_method or ""), (http_ua or ""))
    rec["direction"] = _direction(src, dst, my_ip)
    return rec


def tshark_capture(seconds=20, my_ip="", iface=None, pcap_path=None,
                   with_demo=False, whole_lan=False, continuous=False,
                   stop_event=None, register_devices=True):
    """Capture using Wireshark's tshark engine. Writes a valid .pcap AND
    streams dissected records. Returns (records, raw_pcap_bytes, mode).

    CONTINUOUS MODE: when `continuous=True` (or `seconds<=0`), capture runs
    until `stop_event` is set or the process ends — never stops on its own.
    Devices are recognized live from each packet (MAC-primary, de-duplicated)
    so the device grid stays accurate for the whole session.
    """
    if continuous or seconds is None or seconds <= 0:
        continuous = True
        seconds = 0
    exe = tshark_path()
    if not exe:
        print("[!] tshark not found; falling back to scapy")
        return None, None, "none"
    pcap_path = pcap_path or PCAP_FILE
    native_pcap = _native_path(pcap_path)
    iface = _pick_tshark_iface(iface, my_ip)
    mode = "whole-lan" if whole_lan else "host-only"
    # In continuous mode there is NO duration cap; tshark runs until stopped.
    # In timed mode we cap with -a duration:N. In whole-lan mode we also use the
    # stop_event to terminate (ARP-spoof lab is always user-interruptible).
    cmd = [exe, "-i", str(iface)]
    if (not continuous) and seconds and seconds > 0:
        cmd += ["-a", f"duration:{seconds}"]
    cmd += ["-w", native_pcap, "-F", "pcap",
            "-T", "fields", "-E", "separator=" + TSHARK_FIELD_SEP,
            "-E", "aggregator=,"]       # comma for multi-value fields
    if not whole_lan:
        cmd.append("-p")                  # non-promiscuous; omitted entirely when whole-lan
    cmd += [f"-e{f}" for f in TSHARK_FIELDS]
    dur = "continuous" if continuous else f"{seconds}s"
    print(f"[*] capture {dur} via Wireshark/tshark (iface={iface}, mode={mode})")
    print(f"[*] pcap -> {pcap_path}")
    records = []
    proc = None  # initialized so the finally cleanup never references an
                 # undefined name if Popen itself raises
    stop_ev = threading.Event() if stop_event is None else stop_event
    demo_stop = None
    if with_demo:
        demo_stop = threading.Event()
        _run_demo(3600 if continuous else seconds, demo_stop)
    log_f = None
    try:
        log_f = open(PACKETS_LOG, "w", encoding="utf-8")
    except Exception:
        pass
    seen_pairs = []  # (ip, mac) for live device registration
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                encoding="utf-8", errors="replace")
        for line in proc.stdout:
            if stop_ev.is_set():
                break
            rec = _parse_tshark_row(line, my_ip)
            if not rec:
                continue
            records.append(rec)
            if rec.get("eth_src") and rec.get("src"):
                seen_pairs.append((rec["src"], rec["eth_src"]))
            if dissect.record_interesting(rec):
                line_txt = _fmt(rec)
                print("  " + line_txt, flush=True)
                if log_f:
                    try:
                        log_f.write(line_txt + "\n"); log_f.flush()
                    except Exception:
                        pass
            else:
                if log_f:
                    try:
                        log_f.write(_fmt(rec) + "\n"); log_f.flush()
                    except Exception:
                        pass
            # Live device recognition: flush at most ~1/sec to avoid disk thrash.
            if seen_pairs and len(seen_pairs) >= 50:
                try:
                    from netmon import discover as _disc
                    _disc.bulk_upsert_devices(seen_pairs, cidr="", throttle_s=1.0)
                    seen_pairs.clear()
                except Exception:
                    pass
        if not continuous:
            try:
                proc.wait(timeout=seconds + 30)
            except Exception:
                pass
    except Exception as e:
        print(f"[!] tshark capture failed: {e}")
        mode = "none"
    finally:
        # Always reap the tshark subprocess so it can't become a zombie.
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        if stop_ev is not None and stop_event is None:
            stop_ev.set()
        if demo_stop is not None:
            demo_stop.set()
        if log_f:
            try:
                log_f.close()
            except Exception:
                pass
        # Final device flush so the grid is fully accurate at stop time.
        if seen_pairs:
            try:
                from netmon import discover as _disc
                _disc.bulk_upsert_devices(seen_pairs, cidr="", throttle_s=0)
                seen_pairs.clear()
            except Exception:
                pass
    # Read back the pcap bytes we wrote (valid, openable in Wireshark)
    raw = b""
    try:
        with open(native_pcap, "rb") as f:
            raw = f.read()
        print(f"[+] wrote {len(raw)} bytes / {len(records)} dissected rows -> {pcap_path}")
    except Exception as e:
        print(f"[!] pcap read-back failed: {e}")
    content_n = sum(1 for r in records if dissect.record_interesting(r))
    print(f"\n=== {len(records)} packets ({mode}) | {content_n} with DNS/SNI/HTTP ===")
    return records, raw, mode


def _direction(src, dst, my_ip):
    if src == my_ip:
        return "SENT"
    if dst == my_ip:
        return "RECV"
    return "fwd"


def _fmt(rec) -> str:
    parts = [f"[{rec['ts']}] {rec.get('direction','?'):4} "
             f"{rec['src']:16}->{rec['dst']:16} {rec['proto']:4}"]
    if rec.get("sni"):
        parts.append(f"SNI={rec['sni']}")
    if rec.get("dns"):
        parts.append(f"DNS={rec['dns']}")
    if rec.get("http"):
        parts.append(f"HTTP={rec['http']}")
    app = rec.get("app") or rec.get("browser")
    if app:
        parts.append(f"[{app}]")
    return " ".join(parts)


def live_rows_from_log(limit=600):
    """Parse the incrementally-written packets_log.txt into Wireshark-style
    rows. This is what makes the UI update INSTANTLY as packets arrive
    (the pcap is only finalized when the capture ends)."""
    if not os.path.exists(PACKETS_LOG):
        return []
    rows = []
    n = 0
    try:
        with open(PACKETS_LOG, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                n += 1
                # format: [ts] DIR  src -> dst PROTO  [extra...]
                try:
                    ts = line[1:line.index("]")]
                except Exception:
                    ts = ""
                body = line[line.index("]") + 1:].strip() if "]" in line else line
                parts = body.split()
                direction = parts[0] if parts else ""
                arrow = body.find("->")
                if arrow != -1:
                    left = body[:arrow].split()
                    right = body[arrow + 2:].split(None, 2)
                    # left: [DIR, src]  right: [dst, proto, info...]
                    src = left[-1] if len(left) > 1 else (left[0] if left else "")
                    dst = right[0] if right else ""
                    proto = right[1] if len(right) > 1 else ""
                    info = right[2] if len(right) > 2 else ""
                else:
                    src = dst = proto = info = ""
                rows.append({"no": n, "time": ts, "src": src, "dst": dst,
                             "proto": proto, "info": info,
                             "direction": direction})
    except Exception:
        return rows[-limit:]
    return rows[-limit:]


def _pick_wlan_iface(explicit=None):
    """Pick the capture interface. Preference: explicit > WLAN/Wi-Fi by name
    > interface whose IP is on the LAN > scapy default. Avoids binding to a
    virtual 169.254 adapter when a real Wi-Fi NIC exists."""
    try:
        from scapy.all import conf
    except Exception:
        return explicit
    if explicit:
        return explicit
    # 1) name contains Wi-Fi / WLAN
    for i in conf.ifaces.values():
        nm = (getattr(i, "name", "") or "").lower()
        if "wi-fi" in nm or "wlan" in nm or "wireless" in nm:
            return i.name
    # 2) interface with a private (192.168/10./172.16-31) IP, skip 169.254
    for i in conf.ifaces.values():
        ip = getattr(i, "ip", "") or ""
        if ip.startswith(("192.168.", "10.", "172.1", "172.2", "172.3")):
            return i.name
    # 3) fallback to scapy default
    return str(conf.iface)


def scapy_sniff(seconds=20, my_ip="", whole_lan=False, pcap_path=None,
                with_demo=False, enrich=False, iface=None, continuous=False,
                stop_event=None, register_devices=True):
    try:
        from scapy.all import sniff, IP, TCP, UDP, conf, wrpcap
    except Exception as e:
        print(f"[!] scapy unavailable: {e}")
        return [], [], "none"

    # optional demo traffic generator (fresh DNS/SNI)
    demo_th = demo_stop = None
    if with_demo:
        import threading
        demo_stop = threading.Event()

    mode = "whole-lan" if whole_lan else "host-only"
    if whole_lan:
        set_whole_lan_active(True)
    iface = _pick_wlan_iface(iface)
    dur = "continuous" if continuous else f"{seconds}s"
    print(f"[*] capture {dur} via scapy (iface={iface}, mode={mode})")
    print(f"[*] pcap -> {pcap_path or PCAP_FILE}")
    stats = {"pkts": 0, "apps": {}}
    records, pkts, log_f, seen_pairs = [], [], None, []
    stop_ev = threading.Event() if stop_event is None else stop_event
    try:
        log_f = open(PACKETS_LOG, "w", encoding="utf-8")
    except Exception:
        pass

    def cb(pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        src, dst, proto = ip.src, ip.dst, ip.proto
        sport = dport = 0
        eth_src = eth_dst = ""
        try:
            from scapy.all import Ether
            if Ether in pkt:
                eth_src = pkt[Ether].src
                eth_dst = pkt[Ether].dst
        except Exception:
            pass
        try:
            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
        except Exception:
            pass
        raw = dissect.raw_l4(pkt, proto)
        ttl = 0
        try:
            ttl = pkt[IP].ttl
        except Exception:
            pass
        rec = dissect.dissect_record(src, dst, proto, sport, dport, raw, ttl=ttl)
        rec["direction"] = _direction(src, dst, my_ip)
        rec["eth_src"] = eth_src
        rec["eth_dst"] = eth_dst
        records.append(rec)
        pkts.append(pkt)
        stats["pkts"] += 1
        if eth_src and src:
            seen_pairs.append((src, eth_src))
        if dissect.record_interesting(rec):
            line = _fmt(rec)
            print("  " + line, flush=True)
            if log_f:
                try:
                    log_f.write(line + "\n"); log_f.flush()
                except Exception:
                    pass
            tag = rec.get("app") or rec.get("browser")
            if tag:
                stats["apps"][tag] = stats["apps"].get(tag, 0) + 1
        elif log_f:
            try:
                log_f.write(_fmt(rec) + "\n"); log_f.flush()
            except Exception:
                pass
        if seen_pairs and len(seen_pairs) >= 50:
            try:
                from netmon import discover as _disc
                _disc.bulk_upsert_devices(seen_pairs, cidr="", throttle_s=1.0)
                seen_pairs.clear()
            except Exception:
                pass

    try:
        if continuous:
            sniff(prn=cb, store=True, iface=iface, promisc=whole_lan, count=0,
                  stop_filter=lambda p: stop_ev.is_set())
        else:
            sniff(timeout=seconds, prn=cb, store=True, iface=iface,
                  promisc=whole_lan, count=0)
    except Exception as e:
        print(f"[!] capture failed: {e}")
        mode = "none"
    finally:
        set_whole_lan_active(False)
        if stop_ev is not None and stop_event is None:
            stop_ev.set()
        if demo_stop is not None:
            demo_stop.set()
        if log_f:
            try:
                log_f.close()
            except Exception:
                pass
        if seen_pairs:
            try:
                from netmon import discover as _disc
                _disc.bulk_upsert_devices(seen_pairs, cidr="", throttle_s=0)
                seen_pairs.clear()
            except Exception:
                pass
    out = pcap_path or PCAP_FILE
    try:
        if pkts:
            wrpcap(out, pkts)
            print(f"[+] wrote {len(pkts)} packets to {out}")
    except Exception as e:
        print(f"[!] pcap write failed: {e}")
    content_n = sum(1 for r in records if dissect.record_interesting(r))
    if enrich and records:
        try:
            from netmon import detect
            alerts = detect.run_detections(records, enrich=True)
            if alerts:
                print(f"[+] reputation/enrichment alerts: {len(alerts)}")
                for a in alerts[:8]:
                    print(f"    [{a['severity']}] {a['reason']} | {a.get('subject','')}")
        except Exception:
            pass
    print(f"\n=== {len(records)} packets ({mode}) | {content_n} with DNS/SNI/HTTP ===")
    return records, pkts, mode


def _run_demo(seconds, stop_event):
    import threading, urllib.request, time as _t, random, string

    def rand_host():
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".example.com"

    sites = ["https://www.google.com", "https://github.com",
             "https://www.cloudflare.com", "https://news.ycombinator.com"]

    def worker():
        end = _t.time() + max(1, seconds - 1)
        i = 0
        while _t.time() < end and not stop_event.is_set():
            i += 1
            for t in [f"https://{rand_host()}"] + [sites[i % len(sites)]]:
                if stop_event.is_set():
                    return
                try:
                    urllib.request.urlopen(t, timeout=3)
                except Exception:
                    pass
            _t.sleep(0.4)

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    return th
