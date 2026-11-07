"""Local-only interactive dashboard; never exposes an internet-facing scanner."""
import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from bbplatform.core import Policy, PolicyError, normalize_host
from bbplatform.discovery import certificate_transparency

def render(policy, records, notice=""):
    rows = "".join(
        "<tr><td>" + html.escape(r["host"]) + "</td><td>" +
        html.escape(r["scope"]) + "</td><td>" +
        html.escape(r.get("source", "manual")) + "</td></tr>"
        for r in records[:500])
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Scope-First Research</title><meta name="viewport" content="width=device-width">
<style>body{font:16px system-ui;background:#0b1220;color:#e5e7eb;max-width:1050px;margin:35px auto;padding:20px}
header{display:flex;justify-content:space-between;align-items:center}h1{font-size:28px}
section{background:#182235;padding:22px;border-radius:14px;margin:18px 0}
input,button{font:inherit;padding:11px;border-radius:8px;border:1px solid #64748b}
input{background:#0b1220;color:white;min-width:240px}button{background:#38bdf8;color:#06111c;cursor:pointer}
table{width:100%;border-collapse:collapse}td,th{padding:10px;text-align:left;border-bottom:1px solid #334155}
small{color:#9ca3af}</style><header><h1>Scope-First Research</h1><span>Local dashboard • v0.2</span></header>
<section><h2>Engagement policy</h2><p>Allowed: """ + html.escape(", ".join(policy.includes)) + """</p>
<p>Excluded: """ + html.escape(", ".join(policy.excludes) or "None") + """</p>
<small>Passive CT discovery contacts a public CT index, not target hosts. Candidates are not authorization for active checks.</small></section>
<section><h2>Passive discovery</h2><form method="post" action="/discover">
<label for="domain">Authorized root domain</label><p><input id="domain" name="domain" required placeholder="example.com">
<button type="submit">Discover CT records</button></p></form><p>""" + html.escape(notice) + """</p></section>
<section><h2>Discovered assets</h2><p>""" + str(len(records)) + """ candidate(s) shown (maximum 500)</p>
<table><thead><tr><th>Host</th><th>Scope decision</th><th>Source</th></tr></thead><tbody>""" + rows + """</tbody></table></section>
</html>"""

def serve(policy, host="127.0.0.1", port=8765):
    class Handler(BaseHTTPRequestHandler):
        records = []
        notice = ""
        def do_GET(self):
            if self.path != "/":
                self.send_error(404); return
            data = render(policy, self.records, self.notice).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data)
        def do_POST(self):
            if self.path != "/discover":
                self.send_error(404); return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                self.send_error(413); return
            form = parse_qs(self.rfile.read(size).decode())
            try:
                domain = normalize_host(form.get("domain", [""])[0])
                policy.require(domain)
                self.__class__.records = certificate_transparency(domain, policy)
                self.__class__.notice = "Passive discovery completed."
            except (PolicyError, RuntimeError, ValueError, OSError) as exc:
                self.__class__.notice = "Discovery rejected or failed: " + str(exc)
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
    ThreadingHTTPServer((host, port), Handler).serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    print("Dashboard: http://127.0.0.1:" + str(args.port))
    serve(Policy.from_file(args.policy), port=args.port)
