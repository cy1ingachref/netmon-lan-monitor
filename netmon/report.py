"""report.py - HTML report exporter (device table + alerts)."""
from __future__ import annotations

import html
import os
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_FILE = os.path.join(_HERE, "netmon_report.html")


def _e(s):
    return html.escape(str(s)) if s is not None else ""


def write_report(devices, records, alerts, capture_mode="host-only", path=None) -> str:
    path = path or REPORT_FILE
    gen = time.strftime("%Y-%m-%d %H:%M:%S")
    dev_rows = "".join(
        f"<tr><td>{_e(d.get('ip',''))}</td><td>{_e(d.get('mac',''))}</td>"
        f"<td>{_e(d.get('vendor',''))}</td><td>{_e(d.get('os',''))}</td></tr>"
        for d in devices.values()) or "<tr><td colspan=4>no devices</td></tr>"
    alert_rows = "".join(
        f"<tr><td>{_e(a.get('severity',''))}</td><td>{_e(a.get('reason',''))}</td>"
        f"<td>{_e(a.get('subject',''))}</td></tr>" for a in alerts
    ) or "<tr><td colspan=3>no alerts</td></tr>"
    out = f"""<!doctype html><html><head><meta charset="utf-8">
<title>netmon report</title><style>body{{font-family:Consolas,monospace;margin:24px;color:#222}}
h1{{font-size:18px}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:4px 6px;text-align:left}} th{{background:#2c3e50;color:#fff}}</style>
</head><body><h1>netmon report - {gen}</h1>
<p>capture mode: {_e(capture_mode)} | devices: {len(devices)} | alerts: {len(alerts)}</p>
<h2>Devices</h2><table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>OS</th></tr>{dev_rows}</table>
<h2>Alerts</h2><table><tr><th>Severity</th><th>Reason</th><th>Subject</th></tr>{alert_rows}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
    return path
