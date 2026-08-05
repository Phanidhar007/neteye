# 🌐 neteye live demo

Browser demo: TCP connect port scan against a host you choose (sandboxed).

## Try it

- **Render (one-click, recommended):** [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Phanidhar007/neteye)
- **Hugging Face Spaces:** Docker Space → `demo/Dockerfile`.
- **Vercel:** import the repo → `api/index.py` + `vercel.json`.

Live demo URL (after deploying): `https://neteye-demo.onrender.com`

## Run locally

```bash
pip install -r requirements.txt -r demo/requirements.txt
python demo/app.py          # http://localhost:7860
```

## Sandbox limitations

- Uses the **TCP connect scanner** (no raw packets) with a fixed service list
  and 1.5s timeouts — safe for shared hosting IPs.
- Full ARP sweeps / SYN scans require **Scapy + root/Npcap** locally:
  `sudo python -m neteye 192.168.1.0/24`

## Notes

- Scan **only** hosts you own or are authorized to test.
