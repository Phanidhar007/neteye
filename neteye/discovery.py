"""Host discovery and ARP scanning."""

from __future__ import annotations

import ipaddress

from .scapy_loader import get_scapy


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def arp_sweep(ip_range: str, timeout: float = 2.0, verbose: bool = False) -> list[dict]:
    """Send ARP requests across an IP range and collect MAC replies."""
    s = get_scapy()
    conf = s["conf"]
    old = conf.verb
    conf.verb = 0
    results = []
    try:
        ans, _ = s["srp"](
            s["Ether"](dst="ff:ff:ff:ff:ff:ff") / s["ARP"](pdst=ip_range),
            timeout=timeout, verbose=0,
        )
        for sent, recv in ans:
            results.append({
                "ip": recv.psrc,
                "mac": recv.hwsrc,
                "vendor": _oui_lookup(recv.hwsrc),
            })
    except Exception as e:
        if verbose:
            print(f"[!] ARP sweep failed: {e}")
    finally:
        conf.verb = old
    return results


def ping_sweep(ip_range: str, timeout: float = 2.0) -> list[str]:
    """ICMP echo discovery (fallback when ARP is not possible)."""
    s = get_scapy()
    alive = []
    try:
        for ip in ipaddress.ip_network(ip_range, strict=False).hosts():
            pkt = s["IP"](dst=str(ip)) / s["ICMP"]()
            reply = s["sr1"](pkt, timeout=timeout, verbose=0)
            if reply is not None:
                alive.append(str(ip))
    except Exception:
        pass
    return alive


_VENDORS = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5d": "Hyper-V",
    "02:42": "Docker",
    "00:1a:4b": "QEMU",
    "00:1b:21": "QEMU",
    "3c:97:0e": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
}


def _oui_lookup(mac: str) -> str:
    mac = mac.upper().replace(":", "").replace("-", "")[:6]
    for prefix, vendor in _VENDORS.items():
        if mac.startswith(prefix.upper().replace(":", "")):
            return vendor
    return "unknown"
