"""cli.py - netmon command-line interface (subcommands + logic).

Split out from __main__.py so the package has a clean, testable entry point.
__main__.py is now a 2-line shim: ``from netmon.cli import main; main()``.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from netmon import discover, capture, detect, report as reportmod, webview, compare


def _pcap():
    return capture.PCAP_FILE


def _dev_for_report(devices):
    return {ip: {"ip": ip, "mac": discover.mac_of(mac).upper(),
                 "vendor": discover.vendor_of(mac), "os": "?"}
            for ip, mac in devices.items()}


def cmd_scan(args):
    capture.clear_artifacts()  # start clean: delete old packets/devices/alerts
    ip, mask, iface, gw, cidr = discover.detect_self()
    print(f"[*] self: {ip}  iface={iface}  gw={gw}  cidr={cidr}")
    # Opt-in: auto-populate router_clients.txt from the router's DHCP table.
    if args.fetch_router:
        try:
            from netmon import router_fetch
            n = router_fetch.fetch_tp_link_dhcp(router_ip=gw or "192.168.1.1",
                                                username=args.router_user,
                                                password=args.router_pass,
                                                router_url=args.router_url)
            print(f"[+] router DHCP pull: {n} client(s) -> router_clients.txt")
        except Exception as e:
            print(f"[!] router DHCP pull failed (falling back to manual paste): {e}")
    found = discover.discover(cidr or "")
    found = discover.merge_router_devices(found, cidr or "")
    # P1 (jury-room empty-LAN fallback): seed labelled [SIMULATED] devices so
    # the UI is never empty when the room has no other hosts / router pull fails.
    if args.simulate_devices:
        seeded = discover.seed_simulated_devices(cidr or "", count=4)
        print(f"[+] simulated {len(seeded)} [SIMULATED] demo device(s) for the empty-LAN case")
        found.update(seeded)
    found = discover.tag_gateway(found, gw)  # mark router IP (passive, zero-interference)
    new_n, total = discover.log_new_devices(found, cidr or "")
    # NetScope-style manufacturer filter (wired to discover.filter_by_vendor)
    if args.vendor:
        filtered = discover.filter_by_vendor(found, args.vendor)
        print(f"[+] filtering by vendor '{args.vendor}': {len(filtered)} match(es)")
        found = filtered
    # IP-similarity filter (CIDR / prefix / wildcard / exact)
    if args.ip_filter:
        filtered = discover.filter_by_ip_similarity(found, args.ip_filter)
        print(f"[+] IP filter '{args.ip_filter}': {len(filtered)} match(es)")
        found = filtered
    print(f"[+] discovered {len(found)} devices ({new_n} new, {total} known)")
    for ip_ in sorted(found):
        role = "  [ROUTER]" if isinstance(found[ip_], dict) and found[ip_].get("role") == "gateway" else ""
        mac = discover.mac_of(found[ip_])
        print(f"    {ip_:<16} {str(mac):<20} {discover.vendor_of(mac)}{role}")
    if args.export:
        path = discover.export_devices_csv(args.export)
        print(f"[+] exported -> {path}")
    detect.learn_baseline(found, cidr or "")
    return found, cidr


def cmd_sniff(args):
    capture.clear_artifacts()  # start clean: delete old packets/devices/alerts
    ip, mask, iface, gw, cidr = discover.detect_self()
    # HONEST SCOPE: frames this limit as engineering literacy, not a bug.
    print("[*] HONEST SCOPE: switched LAN = this host + broadcasts only "
          "(same as Wireshark); other devices' traffic needs the gated "
          "ARP-spoof lab (Phase 3).")
    devices = discover.discover(cidr or "")
    devices = discover.merge_router_devices(devices, cidr or "")
    if args.arp_spoof:
        _run_whole_lan(ip, gw, devices, args, cidr)
        return
    # PRIMARY: Wireshark/tshark engine (richer dissection + valid pcap).
    # FALLBACK: scapy if tshark is absent.
    records, raw, mode = None, None, "none"
    # Continuous: run until the user interrupts (Ctrl-C / Stop). seconds=0 means
    # continuous; otherwise the timed window still applies. ARP-spoof whole-LAN
    # is ALWAYS continuous underneath (it's a long-running MITM) but here it is
    # gated by admin + typed authorization in _run_whole_lan.
    continuous = bool(getattr(args, "continuous", False)) or args.seconds <= 0
    stop_event = getattr(args, "stop_event", None)
    if capture.tshark_path():
        records, raw, mode = capture.tshark_capture(
            seconds=args.seconds, my_ip=ip or "", iface=args.iface,
            pcap_path=_pcap(), with_demo=args.with_demo,
            whole_lan=args.whole_lan, continuous=continuous,
            stop_event=stop_event)
    if records is None:
        _sc = capture.scapy_sniff(
            seconds=args.seconds, my_ip=ip or "", whole_lan=args.whole_lan,
            pcap_path=_pcap(), with_demo=args.with_demo, enrich=args.enrich,
            iface=args.iface, continuous=continuous, stop_event=stop_event)
        records, pkts, mode = _sc if _sc is not None else ([], [], "none")
    # Guard: if BOTH backends failed, records is None -> never pass None to the
    # detection/OS-fingerprinting pipeline (would crash on `for rec in records`).
    records = records or []
    # OS fingerprinting from observed TTLs -> device DB
    try:
        os_map = discover.os_map_from_records(records)
        discover.log_new_devices(devices, cidr or "", os_map)
    except Exception:
        pass
    alerts = detect.run_detections(records, devices=devices, cidr=cidr or "",
                                   enrich=args.enrich)
    path = reportmod.write_report(_dev_for_report(devices), records, alerts,
                                   capture_mode=mode)
    print(f"[+] report -> {path} | alerts: {len(alerts)}")
    print(f"[+] open web UI: netmon web   (http://localhost:8080)")
    return records, devices, alerts, mode


def _run_whole_lan(ip, gw, devices, args, cidr):
    """Opt-in ARP-spoof whole-LAN capture (bettercap pattern). Gated."""
    from netmon import arpspoof
    if not gw or gw.startswith("fe80"):
        print("[!] no IPv4 gateway resolved (got '%s'); cannot ARP-spoof." % gw)
        print("    Fix: ensure an IPv4 default gateway, or use 'sniff --whole-lan' (host promisc).")
        return
    if not arpspoof.is_admin():
        print("[!] ARP-spoof REQUIRES administrator/root. Re-run this command elevated.")
        return
    if not arpspoof.confirm_authorization(cidr or "your LAN"):
        print("[!] authorization not confirmed. Aborting (no spoof performed).")
        return
    gw_mac = discover.mac_of(devices.get(gw)) or "?"
    attacker_mac = discover.mac_of(devices.get(ip)) or _self_mac(ip)
    # Guard: a missing MAC would crash scapy inside run_arpspoof.
    if "?" in (gw_mac, attacker_mac):
        print("[!] cannot resolve required MAC addresses (gw=%s, self=%s); aborting."
              % (gw_mac, attacker_mac))
        return
    # clients must be {ip: mac_string}; mac_of normalizes the dict form that
    # tag_gateway() stores so run_arpspoof receives plain MAC strings. Cache the
    # MAC once instead of calling mac_of twice per entry.
    clients = {}
    for k, v in devices.items():
        if k in (ip, gw):
            continue
        m = discover.mac_of(v)
        if m and m != "?":
            clients[k] = m
    if not clients:
        print("[!] no other LAN clients discovered to monitor.")
        return
    print(f"[*] ARP-spoofing {len(clients)} client(s) <-> gateway {gw} ({gw_mac})")
    import threading
    stop = threading.Event()
    th = threading.Thread(target=arpspoof.run_arpspoof,
                          args=(gw, gw_mac, clients, attacker_mac,
                                args.seconds, stop, args.iface), daemon=True)
    th.start()
    # The victim's frames are unicast to OUR MAC (it thinks we're the gateway),
    # so we do NOT need promiscuous mode. On Windows Wi-Fi, promiscuous mode is
    # exactly what strips the L4 payload and gives empty/garbage dissection.
    # We capture non-promiscuous (whole_lan=False) and only toggle the marker
    # file so the web UI still shows the WHOLE-LAN ACTIVE banner.
    capture.set_whole_lan_active(True)
    records = []  # initialized so the post-capture detection step never sees None/undefined
    try:
        if capture.tshark_path():
            records, raw, mode = capture.tshark_capture(
                seconds=args.seconds, my_ip=ip or "", iface=args.iface,
                pcap_path=_pcap(), with_demo=False, whole_lan=False)
        else:
            records, pkts, mode = capture.scapy_sniff(
                seconds=args.seconds, my_ip=ip or "", whole_lan=False,
                pcap_path=_pcap(), with_demo=False, enrich=args.enrich,
                iface=args.iface)
    finally:
        stop.set()
        th.join(timeout=5)
        capture.set_whole_lan_active(False)
    alerts = detect.run_detections(records, devices=devices, cidr="",
                                   enrich=args.enrich)
    path = reportmod.write_report(_dev_for_report(devices), records, alerts,
                                   capture_mode="whole-lan(arp-spoof)")
    print(f"[+] report -> {path} | whole-LAN alerts: {len(alerts)}")


def _self_mac(ip):
    try:
        return discover.arp_table().get(ip, "?")
    except Exception:
        return "?"


def cmd_web(args):
    import threading
    from netmon import arpspoof
    # If a whole-LAN (ARP-spoof) capture is already running in another
    # process, just visualize its live artifacts instead of starting our own.
    whole_lan_running = False
    try:
        whole_lan_running = capture.is_whole_lan_active()
    except Exception:
        pass

    if args.whole_lan:
        # ---- GATED whole-LAN mode: this is the "see every device by default" path.
        # It REQUIRES administrator (Windows blocks ARP-spoof otherwise) and a
        # typed authorization, performed at the CONSOLE before the server starts —
        # the web surface itself never exposes the ARP-spoof.
        if not arpspoof.is_admin():
            print("[!] WHOLE-LAN monitor requires Administrator.")
            print("    Re-launch this command from an elevated (Run as Administrator) prompt.")
            print("    Non-admin fallback: `netmon web` -> host-only localhost UI (your PC + broadcasts).")
            return
        ip, mask, iface, gw, cidr = discover.detect_self()
        if not gw or gw.startswith("fe80"):
            print(f"[!] no IPv4 gateway resolved ('{gw}'); cannot ARP-spoof.")
            return
        if not arpspoof.confirm_authorization(cidr or "LAN"):
            print("[!] authorization not confirmed — refusing to start whole-LAN monitor.")
            return
        # authorized: discover clients, resolve MACs, start the ARP-spoof MITM as
        # a background thread (restores ARP on exit). Then serve the localhost UI.
        devices = discover.discover(cidr or "")
        devices = discover.merge_router_devices(devices, cidr or "")
        discover.tag_gateway(devices, gw)
        gw_mac = discover.mac_of(devices.get(gw)) or "?"
        attacker_mac = discover.mac_of(devices.get(ip)) or _self_mac(ip)
        if "?" in (gw_mac, attacker_mac):
            print(f"[!] cannot resolve required MACs (gw={gw_mac}, self={attacker_mac}); aborting.")
            return
        # clients must be {ip: mac_string}; skip gateway + self (already handled).
        clients = {}
        for k, v in devices.items():
            if k in (ip, gw):
                continue
            m = discover.mac_of(v)
            if m and m != "?":
                clients[k] = m
        if not clients:
            print("[!] no other LAN clients discovered to monitor.")
            return
        stop_ev = threading.Event()
        threading.Thread(
            target=arpspoof.run_arpspoof,
            args=(gw, gw_mac, clients, attacker_mac),
            kwargs={"duration": 0, "stop_event": stop_ev, "iface": iface},
            daemon=True).start()
        capture.set_whole_lan_active(True)
        webview._WHOLE_LAN_MODE = True
        # Auto-start a CONTINUOUS whole-LAN capture so the user just opens
        # localhost and sees every device's packets live (no extra clicks).
        def _auto_feed():
            fip, _, fiface, _, fcidr = discover.detect_self()
            discover.log_new_devices(devices, fcidr or "")
            detect.learn_baseline(devices, fcidr or "")
            t = threading.Thread(target=webview._capture_job,
                                 args=(0, fip, fiface, False, True, True),
                                 daemon=True)
            webview._current_job["thread"] = t
            t.start()
        threading.Thread(target=_auto_feed, daemon=True).start()
        print(f"[*] WHOLE-LAN monitor authorized on {cidr or 'LAN'} "
              f"(gateway {gw}); serving localhost UI on :{args.port}")
        print(f"[*] open http://localhost:{args.port} — captures ALL devices continuously.")
        try:
            webview.run_web(port=args.port)
        finally:
            stop_ev.set()
            capture.set_whole_lan_active(False)

    if whole_lan_running:
        print("[*] detected active WHOLE-LAN capture -> visualizing its live feed (no new capture started)")
    elif args.with_demo:
        def _feed():
            feed_ip, _, _, feed_gw, feed_cidr = discover.detect_self()
            capture.clear_artifacts()
            # initial discovery (device list rarely changes mid-demo)
            found = discover.discover(feed_cidr or "")
            found = discover.merge_router_devices(found, feed_cidr or "")
            discover.log_new_devices(found, feed_cidr or "")
            detect.learn_baseline(found, feed_cidr or "")
            last_discover = time.time()
            while True:
                if capture.tshark_path():
                    capture.tshark_capture(
                        seconds=(args.seconds or 30), my_ip=feed_ip or "",
                        iface=args.iface, pcap_path=_pcap(),
                        with_demo=True, whole_lan=False)
                else:
                    capture.scapy_sniff(seconds=30, my_ip=feed_ip or "",
                                        whole_lan=False, pcap_path=_pcap(),
                                        with_demo=True, enrich=args.enrich,
                                        iface=args.iface)
                # decouple discovery from capture: re-sweep only every ~2 min
                if time.time() - last_discover > 120:
                    found = discover.discover(feed_cidr or "")
                    found = discover.merge_router_devices(found, feed_cidr or "")
                    discover.log_new_devices(found, feed_cidr or "", None)
                    last_discover = time.time()
                time.sleep(5)  # don't re-sweep/refetch-router immediately
        threading.Thread(target=_feed, daemon=True).start()
        print(f"[*] demo capture feeding UI ({(args.seconds or 30)}s)...")
    webview.run_web(port=args.port)


def cmd_compare(args):
    compare.print_report(compare.run_comparison())


def cmd_view(args):
    """Offline pcap viewer (wires pcap_view.py so it is not dead code)."""
    from netmon import pcap_view
    path = args.pcap or capture.PCAP_FILE
    if not os.path.exists(path):
        print(f"[!] no pcap at {path} (run 'netmon sniff --with-demo 10' first)")
        return
    try:
        from scapy.all import rdpcap, IP
    except Exception as e:
        print(f"[!] scapy unavailable: {e}")
        return
    pkts = rdpcap(path)
    print(f"[+] {path}: {len(pkts)} packet(s)\n")
    for i, tval, src, dst, proto, info in pcap_view.list_summary(pkts):
        print(f"#{i:<4} {tval:<14} {src:<16} -> {dst:<16} {proto:<5} {info}")
    # Also show a layer tree for the first IP packet (Wireshark-style drill-down).
    for pkt in pkts:
        if IP in pkt:
            tree = pcap_view.build_layer_tree(pkt)
            if tree:
                print("\n[+] layer tree of first IP packet:")
                for name, attrs in tree:
                    print("  " + name)
                    for a in attrs:
                        print("    " + a)
            break


def build_parser():
    p = argparse.ArgumentParser(prog="netmon", description="cyberpunk LAN monitor")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="discover all LAN devices")
    s.add_argument("-m", "--vendor", help="NetScope-style vendor filter (e.g. Apple)")
    s.add_argument("-i", "--ip-filter", help="IP similarity filter: CIDR (192.168.1.0/24), prefix (192.168.1.), wildcard (192.168.*.5), exact")
    s.add_argument("-o", "--export", help="export known devices to CSV path")
    s.add_argument("--fetch-router", action="store_true",
                   help="auto-populate router_clients.txt from the router's DHCP table (TP-Link adapter)")
    s.add_argument("--router-user", default="admin",
                   help="router admin username for --fetch-router (user-supplied, default admin)")
    s.add_argument("--router-pass", default="admin",
                   help="router admin password for --fetch-router (user-supplied, default admin)")
    s.add_argument("--router-url", default=None,
                   help="optional override URL to probe for --fetch-router (e.g. a local test page)")
    s.add_argument("--simulate-devices", action="store_true",
                   help="seed 4 [SIMULATED] demo devices into the DB (jury-room empty-LAN fallback)")
    s.set_defaults(func=cmd_scan)
    sn = sub.add_parser("sniff", help="live capture + detect + report")
    sn.add_argument("seconds", nargs="?", type=int, default=20,
                     help="capture window in seconds (0 or --continuous = run until stopped)")
    sn.add_argument("--continuous", action="store_true",
                    help="capture forever until interrupted (Ctrl-C / Stop) — no time limit")
    sn.add_argument("--whole-lan", action="store_true", help="promiscuous/whole-LAN via ARP-spoof")
    sn.add_argument("--arp-spoof", action="store_true",
                    help="OPT-IN whole-LAN via ARP-spoof (requires admin + typed authorization)")
    sn.add_argument("--with-demo", action="store_true", help="generate fresh traffic")
    sn.add_argument("--enrich", action="store_true",
                    help="blue-team IP reputation enrichment (offline+opt-in AbuseIPDB)")
    sn.add_argument("--iface", help="capture interface (e.g. 'Wi-Fi'); auto-picks WLAN if omitted")
    sn.set_defaults(func=cmd_sniff)
    w = sub.add_parser("web", help="localhost cyberpunk UI")
    w.add_argument("--port", type=int, default=8080)
    w.add_argument("--with-demo", action="store_true")
    w.add_argument("--enrich", action="store_true")
    w.add_argument("--whole-lan", action="store_true",
                   help="WHOLE-LAN continuous monitor: authorized ARP-spoof so the "
                        "localhost UI sees EVERY device's packets (requires admin + "
                        "typed YES-I-AM-AUTHORIZED; restores ARP on exit)")
    w.add_argument("seconds", nargs="?", type=int, default=0)
    w.add_argument("--iface", help="capture interface (e.g. 'Wi-Fi'); auto-picks WLAN if omitted")
    w.set_defaults(func=cmd_web)
    c = sub.add_parser("compare", help="accuracy vs the repo you sent")
    c.set_defaults(func=cmd_compare)
    v = sub.add_parser("view", help="print a Wireshark-style summary of a .pcap (offline)")
    v.add_argument("pcap", nargs="?", default=None, help="path to capture.pcap (default: netmon/capture.pcap)")
    v.set_defaults(func=cmd_view)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    if not getattr(a, "func", None):
        build_parser().print_help()
        return
    a.func(a)


if __name__ == "__main__":
    main()
