# 🌐 neteye live demo

Browser demo: TCP connect port scan against a host you choose (sandboxed).

## Deploy on Vercel (free)

1. Push this repo to GitHub, then import it at [vercel.com](https://vercel.com) � it auto-detects `vercel.json` + `api/index.py`.
2. Your app is live at `https://neteye.vercel.app` (or the URL Vercel assigns).

## Run locally

```bash
pip install -r requirements.txt
python demo/app.py          # http://localhost:7860
```

## Sandbox limitations

- Uses the **TCP connect scanner** (no raw packets) with a fixed service list
  and 1.5s timeouts — safe for shared hosting IPs.
- Full ARP sweeps / SYN scans require **Scapy + root/Npcap** locally:
  `sudo python -m neteye 192.168.1.0/24`

## Notes

- Scan **only** hosts you own or are authorized to test.
