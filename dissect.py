"""dissect.py - Pure packet-content dissection (no capture side effects).

Grounded in Wireshark's dissection model:
  * DNS  : query/response names (validated header so QUIC/UDP noise is rejected).
  * TLS  : SNI from the ClientHello (the cleartext site behind HTTPS) - the
           same field Wireshark labels "Server Name Indication".
  * HTTP : Host / method / user-agent when not over TLS.

All functions operate on RAW BYTES so the pipeline is testable WITHOUT a live
NIC or scapy. scapy is only a packet source in capture.py.
"""
from __future__ import annotations

import struct

BROWSER_UA = [
    ("Edg/", "Edge"), ("Chrome/", "Chrome"), ("Firefox/", "Firefox"),
    ("Safari/", "Safari"), ("OPR/", "Opera"), ("Brave/", "Brave"),
    ("PostmanRuntime", "Postman"), ("curl/", "curl"), ("python-requests", "python-requests"),
    ("okhttp", "OkHttp(Android)"), ("Java/", "Java"), ("Go-http", "Go-client"),
]

SNI_HINTS = [
    ("whatsapp.net", "WhatsApp"), ("facebook.com", "Facebook/Meta"),
    ("instagram.com", "Instagram"), ("messenger.com", "Messenger"),
    ("googlevideo.com", "YouTube"), ("youtube.com", "YouTube"),
    ("ytimg.com", "YouTube"), ("google.com", "Google"), ("gstatic.com", "Google"),
    ("gvt1.com", "Google"), ("apple.com", "Apple"), ("icloud.com", "Apple"),
    ("microsoft.com", "Microsoft"), ("windowsupdate.com", "Windows Update"),
    ("office.com", "Microsoft 365"), ("outlook.com", "Outlook"),
    ("teams.microsoft.com", "MS Teams"), ("amazon.com", "Amazon"),
    ("cloudfront.net", "AWS/CloudFront"), ("spotify.com", "Spotify"),
    ("netflix.com", "Netflix"), ("discord.com", "Discord"),
    ("telegram.org", "Telegram"), ("steam.com", "Steam"),
    ("epicgames.com", "Epic Games"), ("riotgames.com", "Riot Games"),
    ("xboxlive.com", "Xbox Live"), ("playstation.net", "PlayStation"),
    ("cloudflare.com", "Cloudflare"), ("github.com", "GitHub"),
    ("openai.com", "OpenAI"), ("anthropic.com", "Anthropic"),
    ("nousresearch.com", "Nous/Hermes"),
]


def app_from_ua(ua: str) -> str:
    if not ua:
        return ""
    for sub, name in BROWSER_UA:
        if sub in ua:
            return name
    return ""


def app_from_name(name: str) -> str:
    if not name:
        return ""
    for sub, svc in SNI_HINTS:
        if sub in name:
            return svc
    return ""


def dns_qname(raw: bytes) -> str:
    """Extract the first DNS query name. Validates opcode + QDCOUNT (RFC 1035)
    so random/QUIC UDP is NOT mistaken for DNS. Handles label compression."""
    try:
        if len(raw) < 12:
            return ""
        flags = int.from_bytes(raw[2:4], "big")
        opcode = (flags >> 11) & 0x0F
        if opcode not in (0, 1, 2):
            return ""
        qdcount = int.from_bytes(raw[4:6], "big")
        if qdcount < 1:
            return ""
        off = 12
        labels = []
        jumps = 0
        while True:
            if off >= len(raw):
                return ""
            length = raw[off]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                if off + 1 >= len(raw):
                    return ""
                ptr = ((length & 0x3F) << 8) | raw[off + 1]
                off = ptr
                jumps += 1
                if jumps > 10:
                    return ""
                continue
            if (length & 0xC0) != 0:
                return ""
            off += 1
            if off + length > len(raw):
                return ""
            labels.append(raw[off:off + length].decode("utf-8", "ignore"))
            off += length
        name = ".".join(labels)
        if not name or not all(32 <= ord(c) < 127 for c in name):
            return ""
        return name
    except Exception:
        return ""


def tls_sni(payload: bytes) -> str:
    """Extract SNI from a TLS ClientHello (version-agnostic, Wireshark-style)."""
    try:
        if payload and len(payload) >= 5 and payload[0] == 0x16:
            ch_pos = None
            for cand in (5, 6, 1):
                if cand + 4 <= len(payload) and payload[cand] == 0x01:
                    hlen = int.from_bytes(payload[cand + 1:cand + 4], "big")
                    if 0 < hlen <= len(payload):
                        ch_pos = cand
                        break
            if ch_pos is None:
                for i in range(1, min(len(payload), 40)):
                    if payload[i] == 0x01 and i + 4 < len(payload):
                        ch_pos = i
                        break
            if ch_pos is not None:
                pos = ch_pos + 4
                pos += 2 + 32
                if pos < len(payload):
                    sid_len = payload[pos]
                    pos += 1 + sid_len
                    if pos + 2 <= len(payload):
                        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
                        pos += 2 + cs_len
                        if pos < len(payload):
                            comp_len = payload[pos]
                            pos += 1 + comp_len
                            if pos + 2 <= len(payload):
                                ext_total = int.from_bytes(payload[pos:pos + 2], "big")
                                pos += 2
                                end = pos + ext_total
                                while pos + 4 <= min(end, len(payload)):
                                    etype = int.from_bytes(payload[pos:pos + 2], "big")
                                    elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
                                    pos += 4
                                    if etype == 0x00:
                                        if pos + 2 > len(payload):
                                            break
                                        list_len = int.from_bytes(payload[pos:pos + 2], "big")
                                        pos += 2
                                        sni_end = pos + list_len
                                        if pos + 1 > len(payload):
                                            break
                                        sntype = payload[pos]
                                        pos += 1
                                        if pos + 2 > len(payload):
                                            break
                                        snlen = int.from_bytes(payload[pos:pos + 2], "big")
                                        pos += 2
                                        if sntype == 0 and pos + snlen <= len(payload):
                                            return payload[pos:pos + snlen].decode("utf-8", "ignore")
                                        break
                                    pos += elen
    except Exception:
        pass
    # fallback: scan for SNI extension
    try:
        i = payload.find(b"\x00\x00")
        while i != -1 and i + 5 < len(payload):
            ext_len = int.from_bytes(payload[i + 2:i + 4], "big")
            j = i + 4
            if j + 3 < len(payload):
                if payload[j + 2] == 0x00 and 3 <= ext_len <= len(payload) - j:
                    host_len = int.from_bytes(payload[j + 3:j + 5], "big")
                    hstart = j + 5
                    if hstart + host_len <= len(payload):
                        cand = payload[hstart:hstart + host_len]
                        if all(32 <= c < 127 for c in cand) and b"." in cand:
                            return cand.decode("utf-8", "ignore")
            i = payload.find(b"\x00\x00", i + 1)
    except Exception:
        pass
    return ""


def _enrich_record(rec: dict, dns_q: str, sni: str, http_host: str,
                   http_method: str, http_ua: str) -> dict:
    """Apply app/browser/HTTP labelling to a record dict in place. Shared by
    the scapy path (dissect_record) and the tshark path (capture.py)."""
    if dns_q:
        rec["dns"] = dns_q
        rec["app"] = app_from_name(dns_q.lower())
    if sni:
        rec["sni"] = sni
        rec["app"] = app_from_name(sni.lower())
    if http_host or http_method:
        meth = (http_method or "").strip()
        rec["http"] = (meth + " " + http_host).strip()[:60]
        rec["app"] = rec["app"] or app_from_name((http_host or "").lower())
        if http_ua:
            rec["browser"] = app_from_ua(http_ua)
    return rec


def dissect_record(src, dst, proto, sport, dport, raw, ts=None, ttl=0) -> dict:
    import time
    if ts is None:
        ts = time.strftime("%H:%M:%S")
    pname = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
    info = {"ts": ts, "src": src, "dst": dst, "proto": pname,
            "sport": sport, "dport": dport, "ttl": ttl,
            "dns": "", "sni": "", "http": "", "app": "", "browser": ""}
    if proto == 17 and len(raw) > 12:
        q = dns_qname(raw)
        if q:
            info["dns"] = q
            info["app"] = app_from_name(q.lower())
    elif proto == 6 and raw:
        if raw[:1] == b"\x16":
            sni = tls_sni(raw)
            if sni:
                info["sni"] = sni
                info["app"] = app_from_name(sni.lower())
        elif raw[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE"):
            dec = raw[:600].decode("utf-8", "ignore")
            first = dec.split("\r\n")[0]
            info["http"] = first[:60]
            for line in dec.split("\r\n"):
                ll = line.lower()
                if ll.startswith("host:"):
                    info["app"] = info["app"] or app_from_name(line.split(":", 1)[1].strip().lower())
                if ll.startswith("user-agent:"):
                    info["browser"] = app_from_ua(line.split(":", 1)[1].strip())
    return info


def record_interesting(rec: dict) -> bool:
    return bool(rec.get("sni") or rec.get("dns") or rec.get("http"))


def raw_l4(pkt, proto):
    """Extract the raw L4 payload (TCP data / UDP payload) from a scapy packet.

    Pure bytes helper moved here from capture.py / pcap_view.py so the logic
    lives in ONE place (dissection is a pure concern). Returns b'' on failure.
    """
    try:
        from scapy.all import IP
        ipb = bytes(pkt[IP])
        ihl = (ipb[0] & 0x0F) * 4
        l4 = ipb[ihl:]
        if proto == 6:
            return l4[(l4[12] >> 4) * 4:]
        if proto == 17:
            return l4[8:]
    except Exception:
        return b""
    return b""
