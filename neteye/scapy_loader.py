"""Lazy Scapy accessor so imports don't fail when Scapy is absent."""

from __future__ import annotations


def get_scapy():
    try:
        from scapy.all import (ARP, ICMP, IP, TCP, Ether, conf, sendp, sr1, srp)
        return {"ARP": ARP, "ICMP": ICMP, "IP": IP, "TCP": TCP, "Ether": Ether,
                "conf": conf, "sendp": sendp, "sr1": sr1, "srp": srp}
    except ImportError as e:
        raise RuntimeError(
            "Scapy is not installed. Install with: pip install scapy\n"
            "On Linux run as root; on Windows install Npcap (https://npcap.com)."
        ) from e


def get_arpreq():
    try:
        from scapy.layers.l2 import arping
        return arping
    except ImportError:
        return None
