"""neteye live web demo (Flask). Sandbox-friendly: TCP connect scan only.

Raw SYN/ARP scanning is not possible on shared hosting, so the demo uses
the built-in connect scanner against a small, explicit port list.
"""

from __future__ import annotations

import html
import os
import sys

from flask import Flask, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neteye.banner import guess_os_by_ttl  # noqa: E402
from neteye.scan import connect_scan  # noqa: E402

app = Flask(__name__)

BASE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>neteye demo</title>
<style>body{{font-family:system-ui;max-width:760px;margin:2rem auto;padding:0 1rem}}
input{{width:100%;padding:.6rem;font-size:1rem}}button{{padding:.6rem 1.2rem;font-size:1rem}}
table{{border-collapse:collapse;width:100%;margin-top:.5rem}}td,th{{border:1px solid #ddd;
padding:.5rem;text-align:left}}pre{{background:#f4f4f4;padding:1rem}}</style></head>
<body><h1>📡 neteye — live demo</h1>
<p>TCP connect port scan (sandboxed). Try <code>scanme.nmap.org</code> or your own host.</p>
<form method="post"><label>Host
<input name="host" placeholder="scanme.nmap.org" value="scanme.nmap.org" required></label>
<p style="margin-top:.5rem"><button type="submit">Scan</button></p></form>
{body}</body></html>"""

SAMPLE_PORTS = [21, 22, 25, 53, 80, 110, 443, 8080]


@app.get("/")
def index():
    return BASE.format(body="")


@app.post("/")
def run():
    host = (request.form.get("host") or "").strip()
    if not host:
        return BASE.format(body="<p>Enter a host.</p>")
    try:
        open_ports = connect_scan(host, SAMPLE_PORTS, timeout=1.5)
    except Exception as e:
        return BASE.format(body=f"<p>Error: {html.escape(str(e))}</p>")

    parts = [f"<h2>Open ports on {html.escape(host)}</h2>"]
    if open_ports:
        parts.append("<table><tr><th>Port</th><th>Service</th></tr>")
        for p in open_ports:
            parts.append(f"<tr><td>{p['port']}</td><td>{html.escape(p['service'])}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>No open ports found among checked services.</p>")
    parts.append(f"<p><small>OS guess (demo, TTL-based): {guess_os_by_ttl(64)}</small></p>")
    parts.append("<p><small>Demo scans only a fixed service list with short timeouts.</small></p>")
    return BASE.format(body="".join(parts))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "7860")))
