"""pcap_view.py - Pure packet-list + layer-tree logic (Wireshark-style).

Used by the web UI and the (optional) terminal viewer. Pure functions so they
are testable headlessly. The interactive TUI is intentionally NOT included in
this fresh build - the web UI is the primary viewer.
"""
from __future__ import annotations

from netmon import dissect


def build_layer_tree(pkt) -> list:
    tree = []
    try:
        from scapy.all import Ether
        if Ether in pkt:
            e = pkt[Ether]
            tree.append(("Ethernet II", [
                f"eth.dst = {e.dst}", f"eth.src = {e.src}",
                f"eth.type = {hex(e.type)}"]))
    except Exception:
        pass
    try:
        from scapy.all import IP
        if IP in pkt:
            ip = pkt[IP]
            tree.append(("Internet Protocol V4", [
                f"ip.src = {ip.src}", f"ip.dst = {ip.dst}",
                f"ip.proto = {ip.proto}", f"ip.ttl = {ip.ttl}"]))
    except Exception:
        pass
    try:
        from scapy.all import TCP
        if TCP in pkt:
            t = pkt[TCP]
            fl = []
            if t.flags & 0x02: fl.append("SYN")
            if t.flags & 0x10: fl.append("ACK")
            if t.flags & 0x01: fl.append("FIN")
            if t.flags & 0x08: fl.append("PSH")
            if t.flags & 0x04: fl.append("RST")
            tree.append((f"TCP ({t.sport} -> {t.dport})", [
                f"tcp.srcport = {t.sport}", f"tcp.dstport = {t.dport}",
                f"tcp.flags = {','.join(fl) if fl else str(t.flags)}"]))
    except Exception:
        pass
    try:
        from scapy.all import UDP
        if UDP in pkt:
            u = pkt[UDP]
            tree.append((f"UDP ({u.sport} -> {u.dport})", [
                f"udp.srcport = {u.sport}", f"udp.dstport = {u.dport}"]))
    except Exception:
        pass
    raw = b""
    try:
        from scapy.all import IP
        if IP not in pkt:
            raise ValueError("non-IP")
        ip = pkt[IP]  # assign here so ip.proto is defined in this scope
        raw = dissect.raw_l4(pkt, ip.proto)
    except Exception:
        raw = b""
    if raw:
        if ip.proto == 17 and len(raw) > 12:
            q = dissect.dns_qname(raw)
            if q:
                tree.append(("Domain Name System", [f"dns.query = {q}"]))
        if ip.proto == 6 and raw[:1] == b"\x16":
            s = dissect.tls_sni(raw)
            if s:
                tree.append(("TLS Client Hello", [f"tls.sni = {s}"]))
        elif ip.proto == 6 and raw[:1] == b"\x17":
            tree.append(("TLS Application Data", ["(encrypted)"]))
    return tree


def list_summary(pkts) -> list:
    rows = []
    for i, pkt in enumerate(pkts, 1):
        try:
            from scapy.all import IP
            if IP not in pkt:
                rows.append((i, "-", "-", "-", "?", "non-IP"))
                continue
            ip = pkt[IP]
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, str(ip.proto))
            info = ""
            sport = dport = ""
            try:
                from scapy.all import TCP, UDP
                if TCP in pkt: sport, dport = pkt[TCP].sport, pkt[TCP].dport
                elif UDP in pkt: sport, dport = pkt[UDP].sport, pkt[UDP].dport
            except Exception:
                pass
            raw = b""
            try:
                from scapy.all import IP
                raw = dissect.raw_l4(pkt, ip.proto)
            except Exception:
                raw = b""
            if raw:
                if ip.proto == 17 and len(raw) > 12:
                    q = dissect.dns_qname(raw)
                    if q: info = f"DNS query: {q}"
                if ip.proto == 6 and raw[:1] == b"\x16":
                    s = dissect.tls_sni(raw)
                    if s: info = f"Client Hello: {s}"
                elif ip.proto == 6 and raw[:1] == b"\x17":
                    info = "TLS encrypted (app data)"
                elif ip.proto == 17 and dport in (443, 8443):
                    info = "QUIC (HTTP/3, encrypted)"
            if not info and sport != "":
                info = f"{proto} {sport} -> {dport}"
            try:
                tval = "%.6f" % float(getattr(pkt, "time", 0) or 0)
            except Exception:
                tval = "-"
            rows.append((i, tval, ip.src, ip.dst, proto, info))
        except Exception:
            rows.append((i, "-", "-", "-", "?", "parse-error"))
    return rows
