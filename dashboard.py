"""Local-only researcher approval dashboard and passive CT discovery."""
import argparse
import html
import secrets
from http.cookies import SimpleCookie
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from bbplatform.core import Policy, PolicyError, normalize_host
from bbplatform.discovery import certificate_transparency
from bbplatform.approvals import connect, request, decide, requests, events
from bbplatform.identity import init as init_identity, login, session_user, logout, require_role
from bbplatform.evidence import init as init_evidence, submit as submit_evidence, review as review_evidence
from bbplatform.audit_chain import init as init_audit, append as audit_append, verify as audit_verify

def esc(x):
    return html.escape(str(x), quote=True)

def render(policy, records, db, csrf, notice="", user=None):
    discovered = "".join("<tr><td>" + esc(r["host"]) + "</td><td>" +
                         esc(r["scope"]) + "</td><td>" + esc(r.get("source", "manual")) +
                         "</td></tr>" for r in records[:500])
    approvals = ""
    for ident, host, reason, requester, status, created, reviewer, expires in requests(db):
        controls = ""
        if status == "pending":
            controls = ('<form method="post" action="/decide"><input type="hidden" name="csrf" value="' +
                        esc(csrf) + '"><input type="hidden" name="id" value="' + esc(ident) +
                        '">' +
                        '<button name="decision" value="approve">Approve 24h</button>' +
                        '<button name="decision" value="reject">Reject</button></form>')
        approvals += "<tr><td>" + esc(ident) + "</td><td>" + esc(host) + "</td><td>" + esc(requester) + "</td><td>" + esc(reason) + "</td><td>" + esc(status) + "</td><td>" + controls + "</td></tr>"
    audit = "".join("<tr>" + "".join("<td>" + esc(value) + "</td>" for value in event) + "</tr>"
                    for event in events(db))
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Scope Research • Approvals</title>
<style>body{font:15px system-ui;background:#0b1220;color:#e5e7eb;max-width:1200px;margin:28px auto;padding:18px}
header{display:flex;justify-content:space-between;align-items:center}
section{background:#182235;padding:20px;border-radius:12px;margin:16px 0;overflow:auto}
input,button{font:inherit;padding:9px;margin:3px;border-radius:7px;border:1px solid #64748b}
input{background:#0b1220;color:#fff}button{background:#38bdf8;color:#06111c;cursor:pointer}
table{width:100%;border-collapse:collapse}td,th{padding:9px;text-align:left;border-bottom:1px solid #334155}
small{color:#9ca3af}</style>
<header><h1>Scope-First Research</h1><span>Local dashboard • v0.4 | Signed in: """ + esc(user[0] if user else "anonymous") + """ (""" + esc(user[1] if user else "-") + """)</span></header>
<section><h2>Program scope</h2><p>Included: """ + esc(", ".join(policy.includes)) + """</p>
<p>Excluded: """ + esc(", ".join(policy.excludes)) + """</p>
<small>Approval is not proof of program permission or third-party infrastructure ownership.</small></section>
<section><h2>Passive discovery</h2><form action="/discover" method="post">
<input type="hidden" name="csrf" value='""" + esc(csrf) + """'>
<input name="domain" required placeholder="Authorized root domain">
<button>Discover CT records</button></form><p>""" + esc(notice) + """</p>
<table><tr><th>Host</th><th>Scope</th><th>Source</th></tr>""" + discovered + """</table></section>
<section><h2>Request an active metadata check</h2><form action="/request" method="post">
<input type="hidden" name="csrf" value='""" + esc(csrf) + """'>
<input name="host" required placeholder="Exact hostname">

<input name="reason" required maxlength="500" placeholder="Program authorization / justification">
<button>Submit request</button></form>
<small>Requests do not run scans. An independent reviewer label is required, but reviewers must use separate authenticated accounts.</small></section>
<section><h2>Approval queue</h2><table><tr><th>ID</th><th>Host</th><th>Requester</th><th>Justification</th><th>Status</th><th>Review</th></tr>""" + approvals + """</table></section>
<section><h2>Infrastructure evidence</h2><form action="/evidence" method="post"><input type="hidden" name="csrf" value='""" + esc(csrf) + """'><input name="host" required placeholder="Exact hostname"><input name="program" required placeholder="Program identifier"><input name="reference" required placeholder="Authorization reference URL or document ID"><button>Submit evidence</button></form><p>Network and CNAME attestations are copied from the active policy; reviewers must independently verify authorization.</p><table><tr><th>ID</th><th>Host</th><th>Program</th><th>Reference</th><th>Status</th><th>Review</th></tr>""" + "".join("<tr><td>"+esc(x[0])+"</td><td>"+esc(x[1])+"</td><td>"+esc(x[2])+"</td><td>"+esc(x[3])+"</td><td>"+esc(x[4])+"</td><td><form method=post action=/review-evidence><input type=hidden name=csrf value="+esc(csrf)+"><input type=hidden name=id value="+esc(x[0])+"><button name=decision value=approve>Verify 24h</button><button name=decision value=reject>Reject</button></form></td></tr>" for x in db.execute("SELECT id,host,program,reference,status FROM ownership_evidence ORDER BY id DESC LIMIT 100")) + """</table></section><section><h2>Audit trail</h2><table><tr><th>UTC</th><th>Actor</th><th>Event</th><th>Request ID</th><th>Details</th></tr>""" + audit + """</table></section></html>"""

def serve(policy, port=8765, db_path="state/approvals.sqlite3"):
    db = connect(db_path)
    init_identity(db)
    init_evidence(db)
    init_audit(db)
    csrf = secrets.token_urlsafe(32)
    class Handler(BaseHTTPRequestHandler):
        records = []
        notice = ""
        def current_user(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
                token = cookie["session"].value if "session" in cookie else ""
            except Exception:
                token = ""
            return session_user(db, token), token
        def do_GET(self):
            user, token = self.current_user()
            if not user:
                self.login_page(); return
            if self.path != "/":
                self.send_error(404); return
            data = render(policy, self.records, db, csrf, self.notice, user).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def login_page(self, message=""):
            page = ('<html><meta charset="utf-8"><title>Researcher login</title><body><h1>Researcher login</h1><p>'+esc(message)+'</p><form method="post" action="/login"><input name="username" required autocomplete="username"><input name="password" type="password" required autocomplete="current-password"><button>Sign in</button></form></body></html>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(page)
        def do_POST(self):
            if self.path not in ("/login", "/logout", "/discover", "/request", "/decide", "/evidence", "/review-evidence"):
                self.send_error(404); return
            origin = self.headers.get("Origin")
            if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
                self.send_error(403); return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400); return
            if not 0 < size <= 4096:
                self.send_error(413); return
            try:
                form = parse_qs(self.rfile.read(size).decode("utf-8"))
                val = lambda key: form.get(key, [""])[0]
                if self.path == "/login":
                    token = login(db, val("username"), val("password"))
                    audit_append(db, val("username"), "login", "session", "Local login")
                    self.send_response(303)
                    self.send_header("Set-Cookie", "session="+token+"; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800")
                    self.send_header("Location", "/")
                    self.end_headers(); return
                user, token = self.current_user()
                if not user or not secrets.compare_digest(val("csrf"), csrf):
                    self.send_error(403); return
                if self.path == "/logout":
                    logout(db, token)
                    self.send_response(303); self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"); self.send_header("Location", "/"); self.end_headers(); return
                if self.path == "/discover":
                    domain = policy.require(normalize_host(val("domain")))
                    self.__class__.records = certificate_transparency(domain, policy)
                    self.__class__.notice = "Passive discovery complete."
                elif self.path == "/request":
                    require_role(user, ("researcher", "reviewer", "admin"))
                    ident = request(db, policy, val("host"), val("reason"), user[0])
                    audit_append(db, user[0], "approval_requested", str(ident), val("host"))
                    self.__class__.notice = f"Approval request #{ident} queued."
                elif self.path == "/decide":
                    require_role(user, ("reviewer", "admin"))
                    if val("decision") not in ("approve", "reject"):
                        raise PolicyError("Invalid decision")
                    decide(db, policy, int(val("id")), user[0], val("decision") == "approve")
                    audit_append(db, user[0], "approval_"+val("decision"), val("id"), "Decision recorded")
                    self.__class__.notice = "Decision recorded."
                elif self.path == "/evidence":
                    require_role(user, ("researcher", "reviewer", "admin"))
                    host = policy.require(val("host"))
                    ident = submit_evidence(db, host, val("program"), val("reference"), policy.authorized_ip_cidrs, policy.authorized_cname_suffixes, user[0])
                    audit_append(db, user[0], "evidence_submitted", str(ident), host)
                    self.__class__.notice = "Evidence submitted for independent review."
                elif self.path == "/review-evidence":
                    require_role(user, ("reviewer", "admin"))
                    if val("decision") not in ("approve", "reject"):
                        raise PolicyError("Invalid evidence decision")
                    expires = (datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()
                    review_evidence(db, int(val("id")), user[0], val("decision")=="approve", expires)
                    audit_append(db, user[0], "evidence_"+val("decision"), val("id"), "Reviewed")
                    self.__class__.notice = "Evidence decision recorded."
            except (PolicyError, ValueError, RuntimeError, OSError) as exc:
                self.__class__.notice = "Action denied or failed: " + str(exc)
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Dashboard: http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--approval-db", default="state/approvals.sqlite3")
    args = parser.parse_args()
    serve(Policy.from_file(args.policy), args.port, args.approval_db)
