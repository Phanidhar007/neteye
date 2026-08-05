"""SYN port scanning with Scapy + fallback TCP connect scan."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .scapy_loader import get_scapy

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 5900,
    6379, 6443, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9300, 10000, 11211, 27017, 50000,
]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    2376: "docker-tls", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9000: "php-fpm", 9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    10000: "webmin", 11211: "memcached", 27017: "mongodb", 50000: "http-alt",
}


def syn_scan(host: str, ports: list[int] | None = None, timeout: float = 1.5,
             workers: int = 100) -> list[dict]:
    """Half-open SYN scan using Scapy. Requires root/Npcap."""
    s = get_scapy()
    ports = ports or COMMON_PORTS
    open_ports: list[int] = []

    def _probe(port: int) -> int | None:
        pkt = s["IP"](dst=host) / s["TCP"](dport=port, flags="S")
        reply = s["sr1"](pkt, timeout=timeout, verbose=0)
        if reply is not None and reply.haslayer(s["TCP"]) and reply[s["TCP"]].flags & 0x12:
            return port
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_probe, ports):
            if result:
                open_ports.append(result)
    return [_result(p) for p in sorted(open_ports)]


def connect_scan(host: str, ports: list[int] | None = None, timeout: float = 2.0,
                 workers: int = 200) -> list[dict]:
    """Fallback full TCP connect scan (works without raw sockets)."""
    ports = ports or COMMON_PORTS
    open_ports: list[int] = []

    def _probe(port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_probe, ports):
            if result:
                open_ports.append(result)
    return [_result(p) for p in sorted(open_ports)]


def _result(port: int) -> dict:
    return {"port": port, "service": SERVICES.get(port, "unknown")}
