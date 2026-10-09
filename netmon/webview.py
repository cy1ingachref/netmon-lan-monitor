"""webview.py - Cyberpunk localhost UI for netmon (dark / neon / clean).

Stdlib http.server only. Visual style: near-black background, neon cyan +
magenta accents, monospace, subtle scanline glow. Layout is SIMPLE: a top bar
(host + live counters), a device grid (every LAN device, not just localhost),
a live packet feed (Wireshark-style rows), and an alerts rail.

Reads the SAME artifacts the CLI writes: capture.pcap, devices.json,
alerts.log. So: run a capture, the UI visualizes it.

Run:  python -m netmon web [--port 8080]
"""
from __future__ import annotations

import os
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
PCAP = os.path.join(_HERE, "capture.pcap")
DEVICES_DB = os.path.join(_HERE, "devices.json")
ALERTS_LOG = os.path.join(_HERE, "alerts.log")

from netmon import discover


def _read_devices():
    try:
        with open(DEVICES_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _read_alerts():
    out = []
    try:
        with open(ALERTS_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(line)
    except Exception:
        pass
    return out


def packets_json(limit=600):
    try:
        from netmon import capture as capture_mod
        return capture_mod.live_rows_from_log(limit)
    except Exception as e:
        return [{"error": str(e)}]


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# --- background job controller (stdlib only; keeps the UI non-blocking) ---
# ARP-spoof is DELIBERATELY excluded: the red-team lab stays CLI-only
# (sniff --arp-spoof) so the typed authorization is physically visible and the
# web surface remains a zero-risk control panel for Discovery + Traffic Analysis.
_current_job = {"thread": None, "stop": None, "type": None, "status": "idle"}
_job_lock = threading.Lock()
# When the server is launched with `netmon web --whole-lan`, the localhost UI is
# authorized to capture the WHOLE LAN (gated: admin + typed confirmation at the
# console BEFORE the server starts). The UI Control panel then uses whole_lan=True
# for its continuous capture. The ARP-spoof MITM itself is still started by
# cmd_web (not the web surface), so the typed authorization stays physically
# visible in the console.
_WHOLE_LAN_MODE = False
# Cache detect_self() (shells out to ipconfig/route print) for 5s so a browser
# refresh doesn't re-run subprocesses on every page load.
_self_cache = {"ts": 0.0, "val": (None, None, None, None, None)}
_SELF_CACHE_TTL = 5.0


def _cached_self():
    now = time.time()
    if now - _self_cache["ts"] < _SELF_CACHE_TTL and _self_cache["val"][0]:
        return _self_cache["val"]
    try:
        val = discover.detect_self()
    except Exception:
        val = (None, None, None, None, None)
    _self_cache["ts"] = now
    _self_cache["val"] = val
    return val


def _scan_job():
    try:
        from netmon import capture as _cap, detect as _det
        ip, mask, iface, gw, cidr = discover.detect_self()
        found = discover.discover(cidr or "")
        found = discover.merge_router_devices(found, cidr or "")
        discover.tag_gateway(found, gw)
        discover.log_new_devices(found, cidr or "")
        _det.learn_baseline(found, cidr or "")
        _current_job["status"] = f"done: {len(found)} devices"
    except Exception as e:
        _current_job["status"] = f"error: {e}"
    finally:
        with _job_lock:
            _current_job["type"] = None


def _capture_job(seconds, my_ip, iface, with_demo, continuous=False, whole_lan=False):
    from netmon import capture as _cap, detect as _det, discover as _disc
    stop_ev = threading.Event()
    with _job_lock:
        _current_job["stop"] = stop_ev
        _current_job["status"] = ("capturing (whole-LAN, continuous)" if whole_lan
                                  else "capturing (continuous)" if continuous
                                  else "capturing...")
        _current_job["continuous"] = continuous
        _current_job["whole_lan"] = whole_lan
    records = []
    try:
        _cap.clear_artifacts()
        if _cap.tshark_path():
            records, _, _ = _cap.tshark_capture(
                seconds=seconds, my_ip=my_ip or "", iface=iface,
                pcap_path=_cap.PCAP_FILE, with_demo=with_demo, whole_lan=whole_lan,
                continuous=continuous, stop_event=stop_ev)
        else:
            records, _, _ = _cap.scapy_sniff(
                seconds=seconds, my_ip=my_ip or "", whole_lan=whole_lan,
                pcap_path=_cap.PCAP_FILE, with_demo=with_demo, enrich=False,
                iface=iface, continuous=continuous, stop_event=stop_ev)
        records = records or []
        # Run the detection engine on what we just captured so the "Detection
        # alerts" rail in the browser populates live (not just stale CLI alerts).
        if records:
            try:
                devices = _disc.load_known_devices()
                _det.run_detections(records, devices=devices, cidr="")
                _current_job["status"] = f"done: {len(records)} packets analyzed"
            except Exception as e:
                _current_job["status"] = f"captured; detection skipped: {e}"
        else:
            _current_job["status"] = "done: 0 packets analyzed"
    except Exception as e:
        _current_job["status"] = f"error: {e}"
    finally:
        with _job_lock:
            _current_job["type"] = None
            _current_job["stop"] = None


def render(iface="Wi-Fi"):
    devices = _read_devices()
    alerts = _read_alerts()
    packets = packets_json(200)
    host_ip = "?"
    try:
        host_ip = _cached_self()[0] or "?"
    except Exception:
        pass
    n_pkts = len(packets)
    whole_lan = False
    try:
        from netmon import capture as _cap
        whole_lan = _cap.is_whole_lan_active()
    except Exception:
        pass
    gw_banner = ""
    try:
        gw_banner = discover.gateway_banner()
        # gateway_banner() -> "GATEWAY: 192.168.1.1 @ <mac> [Vendor]"; the IP is
        # the 2nd whitespace token (avoid the redundant "GATEWAY:" prefix).
        gw = (gw_banner.split()[1] if gw_banner and len(gw_banner.split()) > 1
              else "") or "?"
    except Exception:
        gw = "?"

    dev_cards = "".join(
        f"""<div class="card">
  <div class="ip">{esc(d.get('ip','?'))}</div>
  <div class="name">{esc(d.get('name','?'))}</div>
  <div class="mac">{esc(d.get('mac','?'))}</div>
  <div class="meta">{esc(d.get('vendor','?'))}</div>
  <div class="os">{esc(d.get('os','?'))}</div>
</div>""" for d in devices.values()
    ) or "<div class='card dim'>no devices yet &mdash; run: netmon scan</div>"

    alert_rows = "".join(
        f"<div class='alert'>{esc(a)}</div>" for a in alerts[-30:]
    ) or "<div class='alert dim'>no alerts</div>"

    pkt_rows = "".join(
        f"<tr><td>{esc(p['no'])}</td><td>{esc(p['time'])}</td>"
        f"<td>{esc(p['src'])}</td><td>{esc(p['dst'])}</td>"
        f"<td>{esc(p['proto'])}</td><td>{esc(p['info'])}</td></tr>"
        for p in packets
    ) or "<tr><td colspan='6' class='dim'>no packets &mdash; run: netmon sniff --with-demo 20</td></tr>"

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>netmon // localhost</title>
<style>
 :root{{--bg:#07090d;--panel:#0d1117;--cyan:#00f0ff;--mag:#ff2bd6;--amber:#ffb000;--txt:#c8d6e5;--dim:#5a6b7b}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:var(--bg);color:var(--txt);
   font-family:'Courier New',monospace;font-size:13px}}
 .glow{{text-shadow:0 0 6px var(--cyan)}}
 header{{padding:14px 20px;background:linear-gradient(90deg,#0a0e14,#0d1117);
   border-bottom:1px solid #14202b;display:flex;align-items:center;gap:18px}}
 header h1{{margin:0;font-size:18px;color:var(--cyan);letter-spacing:3px}}
  header .tag{{color:var(--mag);font-size:11px;border:1px solid var(--mag);
    padding:2px 8px;border-radius:3px}}
  header .live{{color:#07090d;background:var(--cyan);font-weight:bold;
    font-size:11px;padding:2px 8px;border-radius:3px;animation:pulse 1.4s infinite}}
  header .wl{{color:#07090d;background:#39ff14;font-weight:bold;
    font-size:11px;padding:2px 8px;border-radius:3px;animation:pulse 1.4s infinite}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
  header .ctr{{margin-left:auto;color:var(--dim);font-size:12px}}
  header .ctr b{{color:var(--cyan)}}
 .modebar{{margin:10px 18px 0;padding:8px 12px;border-radius:5px;font-size:12px}}
 .modebar code{{background:#0a0f15;padding:1px 5px;border-radius:3px;color:var(--cyan)}}
 .modebar.host{{background:#2a1c00;border:1px solid #5a3d00;color:#ffb94d}}
 .modebar.wl{{background:#062a06;border:1px solid #1f7a1f;color:#39ff14}}
 .panel{{background:var(--panel);border:1px solid #16202b;border-radius:6px;padding:14px}}
 h2{{margin:0 0 12px;font-size:13px;color:var(--mag);letter-spacing:2px;
   text-transform:uppercase;border-left:3px solid var(--mag);padding-left:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}}
 .gateway-banner{{background:#08131a;border:1px solid var(--cyan);border-radius:5px;
   color:var(--cyan);font-family:'Courier New',monospace;font-size:13px;
   padding:8px 10px;margin:0 0 12px;text-shadow:0 0 6px var(--cyan)}}
 .topo{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 14px;
   font-family:'Courier New',monospace;font-size:12px}}
 .topo-node{{border:1px solid var(--cyan);border-radius:4px;padding:6px 9px;color:var(--cyan)}}
 .topo-node.router{{border-color:#ff4d6d;color:#ff4d6d}}
 .topo-node.dev{{border-style:dashed;color:#9aa7b2}}
 .topo-link{{color:#5a6b78}}
 .ipfilter{{width:100%;margin-bottom:10px;background:#0a0f15;border:1px solid #15212e;
   color:var(--cyan);font-family:'Courier New',monospace;font-size:12px;
   padding:7px 9px;border-radius:4px}}
 .ipfilter:focus{{outline:none;border-color:var(--cyan);box-shadow:0 0 6px var(--cyan)}}
 .card{{background:#0a0f15;border:1px solid #15212e;border-radius:5px;padding:10px}}
 .card .ip{{color:var(--cyan);font-size:14px;font-weight:bold}}
 .card .mac{{color:var(--dim);font-size:11px;margin-top:2px}}
 .card .meta{{margin-top:6px;color:var(--txt)}}
 .card .os{{color:var(--dim);font-size:11px}}
 .card .name{{color:var(--cyan);font-size:13px;font-weight:bold;margin-top:4px}}
 .card .mac{{color:var(--dim);font-size:10px;margin-top:2px}}
 .card .meta{{margin-top:6px;color:var(--mag)}}
 .card .os{{color:var(--dim);font-size:11px}}
 .card.dim,.dim{{color:var(--dim)}}
 table{{width:100%;border-collapse:collapse;font-size:12px}}
 th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid #121b24}}
 th{{color:var(--cyan);font-size:11px;text-transform:uppercase}}
 tbody tr:nth-child(odd){{background:#0a0f15}}
 .feed{{max-height:420px;overflow:auto}}
 .alerts .alert{{border-left:2px solid var(--mag);padding:4px 8px;margin-bottom:6px;
   background:#100a12;color:#ffb3ec;font-size:11px}}
 .alerts .alert.dim{{border-color:#333;color:var(--dim);background:none}}
 .rail{{display:flex;flex-direction:column;gap:18px}}
 .ctl-note{{margin-top:8px;color:var(--dim);font-size:11px;line-height:1.5}}
 .ctl-note code{{background:#0a0f15;padding:1px 5px;border-radius:3px;color:var(--cyan)}}
</style>
<script>
 function ipMatch(ip, pat){{
   pat=(pat||'').trim(); if(!pat) return true;
   if(pat.indexOf('/')>=0){{ // CIDR
     try{{ var p=pat.split('/'); var pre=+p[1];
       function base(ipStr,m){{var pa=ipStr.split('.');var n=(+pa[0]<<24)+(+pa[1]<<16)+(+pa[2]<<8)+(+pa[3]);return (n>>(32-m))<<(32-m);}}
       return base(ip,pre)===base(p[0],pre);
     }}catch(e){{return ip.indexOf(pat.split('/')[0])>=0;}}
   }}
   if(pat.indexOf('*')>=0){{ // wildcard
     var a=pat.split('.'), b=ip.split('.');
     if(a.length!==4||b.length!==4) return false;
     for(var i=0;i<4;i++){{ if(a[i]!=='*'&&a[i]!==b[i]) return false; }}
     return true;
   }}
   if(pat.charAt(pat.length-1)==='.') return ip.indexOf(pat)===0;
   return ip===pat;
 }}
 function devCard(d){{
   return '<div class="card"><div class="ip">'+esc(d.ip||'?')+'</div>'+
     '<div class="name">'+esc(d.name||'?')+'</div>'+
     '<div class="mac">'+esc(d.mac||'?')+'</div>'+
     '<div class="meta">'+esc(d.vendor||'?')+'</div>'+
     '<div class="os">'+esc(d.os||'?')+'</div></div>';
 }}
 function esc(s){{return (''+s).replace(/[&<>]/g,function(c){{return '&#'+c.charCodeAt(0)+';';}});}}
 function loadDevices(){{
   fetch('/api/devices').then(r=>r.json()).then(d=>{{
     var all=Object.values(d); var f=document.getElementById('ipf').value;
     var shown=all.filter(x=>ipMatch(x.ip||'', f));
     document.getElementById('dg').innerHTML = shown.length? shown.map(devCard).join('') :
       '<div class="card dim">no devices match filter</div>';
     document.getElementById('dc').textContent=shown.length;
   }}).catch(e=>{{}});
 }}
 // --- packet tail-follow lock ---
 var follow=true;  // auto-scroll to newest unless user scrolls up
 function checkFollow(){{ var t=document.getElementById('pk'); if(!t) return;
   var p=t.closest('.feed'); if(!p) return;  // .feed scroll container (not <table>)
   follow = (p.scrollTop + p.clientHeight >= p.scrollHeight - 30);
 }}
 // The <script> lives in <head>, so the DOM isn't ready yet. Attach listeners
 // only after DOMContentLoaded to avoid null-reference on #pk / #ipf / #pkf.
 document.addEventListener('DOMContentLoaded', function(){{
   var pk = document.getElementById('pk');
   if (pk) {{ var pf = pk.closest('.feed'); if (pf) pf.addEventListener('scroll', checkFollow); }}
   var ipf = document.getElementById('ipf');
   if (ipf) ipf.addEventListener('input', loadDevices);
   var pkf = document.getElementById('pkf');
   if (pkf) pkf.addEventListener('input', loadPackets);
 }});
 function loadPackets(){{
   fetch('/api/packets').then(r=>r.json()).then(d=>{{
     var f=document.getElementById('pkf').value;
     var shown = d.filter(x=> ipMatch(x.src||'', f) || ipMatch(x.dst||'', f) || (x.info||'').toLowerCase().indexOf((f||'').toLowerCase())>=0);
     document.getElementById('pk').innerHTML = shown.length? shown.map(p=>
       '<tr><td>'+p.no+'</td><td>'+p.time+'</td><td>'+p.src+'</td>'+
       '<td>'+p.dst+'</td><td>'+p.proto+'</td><td>'+p.info+'</td></tr>').join('') :
       '<tr><td colspan="6" class="dim">no packets match filter</td></tr>';
     document.getElementById('pc').textContent=shown.length;
     if(follow){{ var tb=document.getElementById('pk'); var p=tb.closest('.feed'); if(p) p.scrollTop=p.scrollHeight; }}
   }}).catch(e=>{{}});
 }}
 function up(){{
   fetch('/api/alerts').then(r=>r.json()).then(d=>{{
     document.getElementById('ac').textContent=d.length;}});
   loadDevices(); loadPackets();
 }}
 setInterval(up,1000);
 function post(url, body){{
   fetch(url, {{method:'POST', headers:{{'Content-Type':'application/json'}},
               body: JSON.stringify(body||{{}})}})
     .then(r=>r.json()).then(j=>{{
       document.getElementById('job-status').textContent = (j.ok?'OK: ':'ERR: ') + JSON.stringify(j);
     }}).catch(e=>{{ document.getElementById('job-status').textContent = 'ERR: '+e; }});
 }}
 var _WL = {str(_WHOLE_LAN_MODE).lower()};
 // poll job status every 2s
 setInterval(function(){{
   fetch('/api/status').then(r=>r.json()).then(s=>{{
     var jt = (s.continuous)? ' (continuous)':'';
     document.getElementById('job-status').textContent = (s.job||'idle') + ' | ' + s.status + jt;
   }}).catch(e=>{{}});
 }}, 2000);
</script></head>
<body>
<header>
  <h1 class="glow">NETMON</h1>
  <span class="tag">CYBERPUNK LAN MONITOR</span>
  <span class="live">&#9679; LIVE</span>
  {('' if not whole_lan else '<span class="wl">&#9889; WHOLE-LAN ACTIVE</span>')}
  <span class="ctr">iface <b>{esc(iface)}</b> &nbsp;|&nbsp; host <b>{esc(host_ip)}</b> &nbsp;|&nbsp; packets <b id="pc">{n_pkts}</b> &nbsp;|&nbsp; alerts <b id="ac">{len(alerts)}</b> &nbsp;|&nbsp; auto 1s</span>
</header>
<div class="modebar {('wl' if whole_lan else 'host')}">
  {('<b>&#9889; WHOLE-LAN:</b> capturing EVERY device’s packets (ARP-spoof active) &mdash; this is the Wireshark-style full-LAN view.')
    if whole_lan else
    ('<b>&#9888; HOST-ONLY:</b> showing only this PC + broadcasts. To see <b>every device like Wireshark</b>, type <code>netmon</code> (as Administrator) &mdash; it launches the web UI whole-LAN monitor (opt-in ARP-spoof, restores ARP on exit). Or run <code>netmon_host</code> for host-only.')}
</div>
<div class="topo">
  <span class="topo-node router">&#9889; ROUTER {gw or '?'} @ {gw_banner.split('@')[-1].strip() if gw_banner else 'unknown'}</span>
  <span class="topo-link">&harr;</span>
  <span class="topo-node pc">YOUR PC {host_ip or '?'}</span>
  <span class="topo-link">&harr;</span>
  <span class="topo-node dev">OTHER DEVICES: visible via router DHCP, not passive capture</span>
</div>
<main>
  <div>
    <div class="panel" style="margin-bottom:18px">
      <h2>Control</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button onclick="post('/api/scan')" style="background:#0a0f15;border:1px solid var(--cyan);color:var(--cyan);padding:6px 12px;border-radius:4px;cursor:pointer">Scan Network</button>
        <button onclick="post('/api/start_capture', {{seconds:20, demo:true}})" style="background:#0a0f15;border:1px solid var(--cyan);color:var(--cyan);padding:6px 12px;border-radius:4px;cursor:pointer">Start Capture (20s + demo)</button>
        <button onclick="post('/api/start_capture', {{continuous:true, demo:true, whole_lan:_WL}})" style="background:#0a0f15;border:1px solid var(--cyan);color:var(--cyan);padding:6px 12px;border-radius:4px;cursor:pointer">Continuous Capture (until Stop)</button>
        <button onclick="post('/api/stop_capture')" style="background:#0a0f15;border:1px solid #ff4d6d;color:#ff4d6d;padding:6px 12px;border-radius:4px;cursor:pointer">Stop Capture</button>
        <button onclick="post('/api/export_csv')" style="background:#0a0f15;border:1px solid var(--mag);color:var(--mag);padding:6px 12px;border-radius:4px;cursor:pointer">Export CSV</button>
        <button onclick="post('/api/seed_demo')" style="background:#0a0f15;border:1px solid var(--amber);color:var(--amber);padding:6px 12px;border-radius:4px;cursor:pointer">Seed [SIMULATED] devices</button>
      </div>
      <div id="job-status" style="margin-top:8px;color:var(--dim);font-size:11px">idle</div>
      <div class="ctl-note">Whole-LAN monitor: type <code>netmon</code> (as Administrator) &mdash; it serves this UI with EVERY device's packets via opt-in ARP-spoof (type <code>YES-I-AM-AUTHORIZED</code>; ARP restored on exit). Host-only mode needs no admin: <code>netmon_host</code>.</div>
    </div>
    <div class="panel" style="margin-bottom:18px">
      <h2>Devices on the network (<span id="dc">{len(devices)}</span>)</h2>
      {('<div class="gateway-banner">⚡ ' + esc(gw_banner) + '</div>') if gw_banner else ''}
      <input id="ipf" class="ipfilter" placeholder="filter by IP: 192.168.1. / 192.168.1.0/24 / 192.168.*.5" />
      <div class="grid" id="dg">{dev_cards}</div>
    </div>
    <div class="panel">
      <h2>Live packet capture</h2>
      <input id="pkf" class="ipfilter" placeholder="filter packets by IP (src/dst): 192.168.1.17 / 192.168.*.5 / 142.250." />
      <div class="feed"><table>
        <thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Info</th></tr></thead>
        <tbody id="pk">{pkt_rows}</tbody>
      </table></div>
    </div>
  </div>
  <div class="rail">
    <div class="panel alerts">
      <h2>Detection alerts</h2>
      {alert_rows}
    </div>
    <div class="panel">
      <h2>Links</h2>
      <div style="line-height:1.8">
        <a style="color:var(--cyan)" href="/pcap">download .pcap</a><br>
        <a style="color:var(--cyan)" href="/compare">accuracy comparison</a>
      </div>
    </div>
  </div>
</main>
</body></html>"""


class _H(BaseHTTPRequestHandler):
    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/dashboard"):
            try:
                from netmon import capture as _cap
                iface = _cap._pick_wlan_iface(None)
            except Exception:
                iface = "Wi-Fi"
            self._send(render(iface).encode("utf-8"))
        elif path == "/api/packets":
            self._send(json.dumps(packets_json(500)).encode("utf-8"), "application/json")
        elif path == "/api/alerts":
            self._send(json.dumps(_read_alerts()).encode("utf-8"), "application/json")
        elif path == "/api/devices":
            self._send(json.dumps(_read_devices()).encode("utf-8"), "application/json")
        elif path == "/pcap":
            if os.path.exists(PCAP):
                with open(PCAP, "rb") as f:
                    self._send(f.read(), "application/vnd.tcpdump.pcap")
            else:
                self._send(b"no pcap yet", code=404)
        elif path == "/compare":
            from netmon import compare
            import io, sys
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                compare.print_report(compare.run_comparison())
            finally:
                sys.stdout = old
            self._send(buf.getvalue().encode("utf-8"), "text/plain; charset=utf-8")
        elif path == "/api/status":
            self._send(json.dumps({
                "job": _current_job["type"],
                "status": _current_job["status"],
                "continuous": bool(_current_job.get("continuous", False)),
            }).encode("utf-8"), "application/json")
        else:
            self._send(b"not found", code=404)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def do_POST(self):
        path = self.path.split("?")[0]
        # Guard: only ONE background job at a time. Read + set under the lock so
        # the status poll can't observe a half-initialized job (type set, thread
        # still None) on a concurrent thread.
        if path in ("/api/scan", "/api/start_capture"):
            with _job_lock:
                if _current_job["type"] is not None:
                    self._send(json.dumps({"ok": False, "error": "job running"}).encode("utf-8"),
                               "application/json", 409)
                    return
                if path == "/api/scan":
                    _current_job["type"] = "scan"
                    _current_job["status"] = "scanning..."
                    t = threading.Thread(target=_scan_job, daemon=True)
                    _current_job["thread"] = t
                    t.start()
                    self._send(json.dumps({"ok": True}).encode("utf-8"), "application/json")
                elif path == "/api/start_capture":
                    body = self._read_json()
                    secs = int(body.get("seconds", 30))
                    demo = bool(body.get("demo", False))
                    cont = bool(body.get("continuous", False))
                    # whole_lan is ONLY honored when the server was launched in
                    # authorized --whole-lan mode (admin + typed confirmation).
                    wl = bool(body.get("whole_lan", False)) and _WHOLE_LAN_MODE
                    if cont or wl:
                        secs = 0  # continuous = no duration cap
                    try:
                        ip, _, iface, _, _ = discover.detect_self()
                    except Exception:
                        ip, iface = "", None
                    _current_job["type"] = "capture"
                    t = threading.Thread(target=_capture_job,
                                         args=(secs, ip, iface, demo, cont, wl),
                                         daemon=True)
                    _current_job["thread"] = t
                    t.start()
                    self._send(json.dumps({"ok": True, "seconds": secs,
                                           "continuous": cont, "whole_lan": wl}).encode("utf-8"),
                               "application/json")
            return
        elif path == "/api/stop_capture":
            with _job_lock:
                if _current_job["stop"]:
                    _current_job["stop"].set()
            self._send(json.dumps({"ok": True}).encode("utf-8"), "application/json")
        elif path == "/api/export_csv":
            try:
                out = discover.export_devices_csv()
                self._send(json.dumps({"ok": True, "path": out}).encode("utf-8"),
                           "application/json")
            except Exception as e:
                self._send(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"),
                           "application/json", 500)
        elif path == "/api/seed_demo":
            # P1: empty-LAN jury-room fallback. Seeds labelled [SIMULATED]
            # devices so the grid is never empty. Honest label in the UI.
            try:
                seeded = discover.seed_simulated_devices("", count=4)
                self._send(json.dumps({"ok": True, "count": len(seeded)}).encode("utf-8"),
                           "application/json")
            except Exception as e:
                self._send(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"),
                           "application/json", 500)
        else:
            self._send(b"not found", code=404)

    def log_message(self, *a):
        pass


def run_web(port=8080):
    srv = ThreadingHTTPServer(("127.0.0.1", port), _H)
    print(f"[*] netmon web UI: http://127.0.0.1:{port}/")
    print(f"[*] (run 'netmon sniff --with-demo 20' to feed it)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped")
    finally:
        srv.server_close()
