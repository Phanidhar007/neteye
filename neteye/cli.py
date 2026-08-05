"""CLI entry point for neteye."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .banner import banner_for_open_ports, guess_os_by_ttl
from .discovery import arp_sweep, ping_sweep
from .scan import connect_scan, syn_scan


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="neteye",
        description="Scapy-powered network reconnaissance: ARP discovery, SYN/connect port "
                    "scans, banner grabbing, OS guessing.",
        epilog="Requires: pip install scapy. Linux -> run as root. Windows -> install Npcap.",
    )
    p.add_argument("target", help="host, CIDR or 'auto' for local subnet")
    p.add_argument("--ports", help="comma-separated ports (default: top ~40)")
    p.add_argument("--mode", choices=["arp", "ping", "syn", "connect", "auto"], default="auto",
                   help="discovery/scan method")
    p.add_argument("--banners", action="store_true", help="grab banners from open ports")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--out", default="neteye_report")
    p.add_argument("-V", "--version", action="version", version=f"neteye {__version__}")
    return p


def _port_list(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    return [int(x) for x in raw.replace(" ", "").split(",") if x.strip()]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = {"tool": "neteye", "version": __version__, "target": args.target,
              "scanned_at": datetime.now(timezone.utc).isoformat()}

    try:
        if args.target == "auto":
            ips = _local_hosts()
            report["hosts"] = ips
            for ip in ips:
                print(f"[*] probing {ip}")
                _scan_ip(report, ip, args)
            _dump(report, args.out)
            return 0

        if "/" in args.target:
            print(f"[*] discovering hosts on {args.target} ...")
            hosts = arp_sweep(args.target, args.timeout) if args.mode in ("arp", "auto") \
                else [{"ip": i, "mac": ""} for i in ping_sweep(args.target, args.timeout)]
            report["alive"] = hosts
            print(f"    {len(hosts)} host(s) responded")
            for h in hosts:
                _scan_ip(report, h["ip"], args)
        else:
            _scan_ip(report, args.target, args)
        _dump(report, args.out)
        return 0
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _scan_ip(report: dict, ip: str, args) -> None:
    ports = _port_list(args.ports)
    mode = args.mode
    if mode == "auto":
        mode = "syn"
    try:
        if mode == "syn":
            open_ports = syn_scan(ip, ports, args.timeout)
        elif mode == "connect":
            open_ports = connect_scan(ip, ports, args.timeout)
        elif mode == "ping":
            open_ports = []
        else:
            open_ports = []
    except RuntimeError as e:
        print(f"    [!] {e}; falling back to connect scan")
        open_ports = connect_scan(ip, ports, args.timeout)

    if args.banners and open_ports:
        open_ports = banner_for_open_ports(ip, open_ports)
    report.setdefault("scans", []).append({"host": ip, "open_ports": open_ports})
    if open_ports:
        print(f"    open ports: {', '.join(str(p['port']) for p in open_ports)}")


def _local_hosts() -> list[str]:
    try:
        from scapy.all import conf
        iface = conf.iface
        import netifaces  # noqa: F401
        addrs = netifaces.ifaddresses(iface)
        return [a["addr"] for a in addrs.get(netifaces.AF_INET, [])]
    except Exception:
        return ["127.0.0.1"]


def _dump(report: dict, out: str) -> None:
    Path(f"{out}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] report: {out}.json")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
