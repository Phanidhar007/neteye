# neteye

> Network reconnaissance scanner built on **Scapy**: ARP host discovery, SYN (half-open) port scanning, banner grabbing and TTL-based OS fingerprinting.

A portfolio project demonstrating packet-level networking with [Scapy](https://github.com/secdev/scapy) — the standard Python packet manipulation library used by the security industry (also the base for many IDS/pen-test toolkits).

## 🌐 Live demo

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Phanidhar007/neteye)

Try the web demo (sandboxed TCP connect scan): **`https://neteye-demo.onrender.com`** (deploy it first — see [`demo/README.md`](demo/README.md)).

## Features

- 📡 **ARP host discovery** — sweep a CIDR, report live IPs, MACs and known OUI vendors (VMware, VirtualBox, Hyper-V, Docker, Raspberry Pi, QEMU)
- 🧭 **ICMP ping sweep** fallback
- ⚡ **SYN (half-open) scan** — raw TCP packets, stealthy, fast
- 🔌 **TCP connect scan** fallback — works without raw sockets
- 🏷️ **Banner grabbing** — SSH/HTTP/FTP/service banners for open ports
- 🖥️ **OS guessing** from observed TTL values
- 🗂️ JSON reports

## Install

```bash
git clone https://github.com/Phanidhar007/neteye.git
cd neteye
python -m venv .venv && .venv\Scripts\activate   # Windows
# source .venv/bin/activate                       # Linux/macOS
pip install -r requirements.txt
```

**Platform requirements for raw packets:**
- Linux/macOS: run as `root`/`sudo`
- Windows: install [Npcap](https://npcap.com) (or WinPcap legacy)

If raw sockets aren't available, neteye automatically falls back to a TCP connect scan.

## Usage

```bash
# ARP-sweep a /24 and scan alive hosts
sudo python -m neteye 192.168.1.0/24

# SYN scan a single host with specific ports
sudo python -m neteye 192.168.1.10 --ports 22,80,443,8080

# Connect scan + banners (no root needed)
python -m neteye 192.168.1.10 --mode connect --banners

# Auto-detect your local subnet
sudo python -m neteye auto
```

### Sample report (JSON)

```json
{
  "target": "192.168.1.0/24",
  "alive": [
    { "ip": "192.168.1.1", "mac": "00:0c:29:11:22:33", "vendor": "VMware" }
  ],
  "scans": [
    {
      "host": "192.168.1.1",
      "open_ports": [
        { "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.2" }
      ]
    }
  ]
}
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Authorized use only

Only scan networks and hosts you own or have explicit permission to test.

## License

MIT — see [LICENSE](LICENSE).
