"""Banner grabbing and TTL-based OS fingerprinting."""

from __future__ import annotations

import socket


def grab_banner(host: str, port: int, timeout: float = 4.0) -> str:
    """Connect and read the service banner (e.g. SSH, HTTP, FTP)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 443, 8080, 8443):
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\nUser-Agent: neteye\r\n\r\n" % host.encode())
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""
            return data.decode("utf-8", errors="replace").strip()[:300]
    except OSError:
        return ""


def banner_for_open_ports(host: str, open_ports: list[dict], timeout: float = 4.0) -> list[dict]:
    for entry in open_ports:
        entry["banner"] = grab_banner(host, entry["port"], timeout)
    return open_ports


def guess_os_by_ttl(ttl: int) -> str:
    """Rough OS guess from the TTL of observed traffic."""
    if ttl is None:
        return "unknown"
    if 110 <= ttl <= 128:
        return "Windows / Linux (default TTL 128/64 seen as 127/63 at hop 1)"
    if 56 <= ttl <= 64:
        return "Linux / Unix (default TTL 64)"
    if ttl == 255:
        return "Cisco / network device (default TTL 255)"
    if ttl == 32:
        return "Windows 9x / embedded (default TTL 32)"
    return "unknown"
