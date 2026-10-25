"""Deliberately vulnerable demo app for verifying Summit's detection.

This app exists so you (and our CI) can prove the scanner works without
touching any real target. Everything is simulated and local:

- the "database" is an in-memory SQLite behind a lock
- the "filesystem" is a virtual dict (no real files are ever read)
- the server binds to 127.0.0.1 only

Run it, then run Summit against it:

    python examples/vuln_app.py            # terminal 1
    summit scan http://127.0.0.1:8765      # terminal 2

Seeded vulnerabilities:
    - reflected XSS       /search?query=   (raw reflection in HTML body)
    - SQLi, error-based   /user?id=        (unquoted string concatenation)
    - SQLi, boolean-based /user?id=        (true/false response divergence)
    - open redirect       /redirect?url=   (unvalidated 302)
    - path traversal      /file?name=      (virtual filesystem read)
    - broken link         summer-promo     (dead external domain, NXDOMAIN)
    - WAF, bypassable     /protected?token= (naive filter + double decoding)
    - CAPTCHA challenge   /login           (reCAPTCHA marker, reported not solved)
    - resource takeover   /old-bucket      (404 + S3 NoSuchBucket signature)
    - host header inject  /reset?user=     (reflects the Host header into a reset link)
    - CORS reflection     /api?user=1      (reflects any Origin, credentials allowed)
    - broken authz        /admin?user=1    (admin panel served to any role - BOLA demo)
    - hidden parameter    /debug           (undocumented debug param, reflected)
    - OS command inject   /ping?host=      (simulated shell - deterministic, no real subprocess)
    - SSTI / RCE          /greet?name=     (naive template evaluates {{7*7}})
    - CRLF injection      /goto?to=        (Location header accepts CRLF)
    - sensitive file      /.env            (200 with APP_KEY/DB_PASSWORD content)
    - time-based SQLi     /user?id=        (SLEEP marker pauses the handler 0.25s)
    - GraphQL leak        /graphql         (introspection enabled in production)
    - GraphQL suggestions /graphql         (invalid fields leak schema names)
    - fuzz seed           /api/discount?code= (only valid codes diverge)
    - cache deception     /account         (session cookie + suffix-tolerant routing)
    - client CVE leak     (page references jQuery 3.4.1 + WordPress 5.7.1 banners)
    - missing security headers + version disclosure on every response
    - SSRF (OOB)          /fetch?url=      (fetches loopback URLs only - proven via callback)
    - XXE file read       /xml (POST)      (entities resolve against the virtual filesystem)
    - TRACE enabled       /                (echoes the request, marker header included)
    - hardcoded secret    /app.js          (AWS-shaped access key shipped in the bundle)
    - DOM XSS candidate   /dom             (location.hash flows into innerHTML)

The "partner" link (https://example.com) is a live negative control: a
healthy outbound link (HTTP 200) must NOT be reported.
"""

import json
import re
import sqlite3
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

PORT = 8765

PAGE = """<!doctype html>
<html><head><title>Summit demo shop</title></head>
<body>
<h1>Summit demo shop</h1>
<p>Deliberately vulnerable on purpose. Local only.</p>
<script src="/app.js"></script>
<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
<meta name="generator" content="WordPress 5.7.1">
<script src="/static/jquery-3.4.1.min.js"></script>
<meta name="generator" content="WordPress 5.7.1">
<ul>
  <li><a href="/search?query=laptop">search</a></li>
  <li><a href="/user?id=1">user</a></li>
  <li><a href="/redirect?url=https://example.com">redirect</a></li>
  <li><a href="/file?name=notes.txt">file</a></li>
  <li><a href="/protected?token=demo">protected</a></li>
  <li><a href="/login">login</a></li>
  <li><a href="/old-bucket">old-bucket</a></li>
  <li><a href="/reset?user=demo">reset</a></li>
  <li><a href="/api?user=1">api</a></li>
  <li><a href="/ping?host=demo.local">ping</a></li>
  <li><a href="/greet?name=world">greet</a></li>
  <li><a href="/goto?to=/">goto</a></li>
  <li><a href="/fetch?url=http://127.0.0.1:8765/">fetch</a></li>
  <li><a href="/xml">xml</a></li>
  <li><a href="/dom">dom</a></li>
  <li><a href="/.env">env</a></li>
  <li><a href="/api/discount?code=SUMMIT10">discount</a></li>
  <li><a href="/account">account</a></li>
  <li><a href="/graphql">graphql</a></li>
  <li><a href="/register?email=demo@demo.local">register</a></li>
  <li><a href="/files/">files</a></li>
  <li><a href="https://summit-demo-dead.example/old-promo">summer promo</a></li>
  <li><a href="https://example.com/">partner</a></li>
</ul>
</body></html>"""

# Virtual filesystem for the traversal demo. No real file is ever opened.
VFS = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
    ),
    "/windows/win.ini": "[fonts]\n[extensions]\n; for 16-bit app support\n[MCI Extensions.BAK]",
}

USERS = {
    1: ("admin", "admin@demo.local", "198.51.100.10"),
    2: ("kevin", "kevin@demo.local", "198.51.100.11"),
    3: ("sarah", "sarah@demo.local", "198.51.100.12"),
}


def seed_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT, last_ip TEXT)")
    for uid, (name, email, ip) in USERS.items():
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (uid, name, email, ip))
    conn.commit()
    return conn


DB = seed_db()
DB_LOCK = threading.Lock()


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "DemoShop/1.0"  # chatty Server header on purpose
    protocol_version = "HTTP/1.1"

    def _html(self, body: str, status: int = 200, extra_headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args) -> None:  # keep the demo output clean
        pass

    def _graphql_suggestions(self) -> None:
        body = json.dumps({"errors": [{
            "message": "Cannot query field 'summitNoSuchFieldProbe' on type 'Query'. "
                       "Did you mean 'summitSecretField' or 'summitAdminField'?",
        }]})
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        split = urlsplit(self.path)
        query = {key: values[0] for key, values in parse_qs(split.query, keep_blank_values=True).items()}
        path = split.path

        if path == "/":
            self._html(PAGE)

        elif path == "/search":
            # Vulnerable: raw reflection into the HTML body.
            term = query.get("query", "")
            self._html(f"<html><body><h1>Results for {term}</h1><p>No products matched.</p></body></html>")

        elif path == "/user":
            uid = query.get("id", "")
            # Vulnerable (time-based demo): a SLEEP marker in the input makes
            # the handler pause briefly - deterministic, capped at 0.25s, so
            # the time-based check can be demonstrated without hurting anyone.
            if "SLEEP" in uid:
                time.sleep(0.25)
            # Vulnerable: user input concatenated straight into SQL.
            sql = f"SELECT id, name, email, last_ip FROM users WHERE id = {uid}"
            try:
                with DB_LOCK:
                    rows = DB.execute(sql).fetchall()
            except sqlite3.Error as exc:
                # Vulnerable: verbose database error surfaced to the client.
                self._html(f"<html><body><p class='error'>Database error: {exc}</p></body></html>")
                return
            if not rows:
                self._html("<html><body><p>No user found.</p></body></html>")
                return
            blocks = "".join(
                f"<div class='user'><h2>{row[1]}</h2>"
                f"<p>Email: {row[2]}</p>"
                f"<p>Last login from: {row[3]}</p>"
                f"<p>Account created 2026-01-0{row[0]}, status: active, plan: pro. "
                f"Demo user record number {row[0]} with plenty of filler text so response "
                f"sizes differ meaningfully between hits and misses.</p></div>"
                for row in rows
            )
            self._html(f"<html><body>{blocks}</body></html>")

        elif path == "/protected":
            token = query.get("token", "")
            # Simulated WAF: it inspects the parameter as the request carries it
            # (no extra decoding - real WAFs sit in front of the app) and blocks
            # tag / quote injection markers. Note the app behind it decodes one
            # layer more than the filter ever looks at - that mismatch is the
            # whole vulnerability.
            inspected = token.lower()
            if "<svg" in inspected or "<script" in inspected or "'" in inspected:
                body = "<html><body><h1>403 Forbidden</h1><p>Request blocked. ModSecurity.</p></body></html>"
                data = body.encode("utf-8")
                self.send_response(403)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Server", "DemoShop/1.0 Mod_Security/2.9")
                self.end_headers()
                self.wfile.write(data)
                return
            # The layer behind the WAF decodes one more time than the filter
            # does - exactly that mismatch is the vulnerability.
            decoded = unquote(token)
            self._html(
                f"<html><body><p>Access for {decoded} granted.</p></body></html>",
                extra_headers={"Server": "DemoShop/1.0 Mod_Security/2.9"},
            )

        elif path == "/login":
            # Simulated login page behind a CAPTCHA. Summit reports the
            # challenge; solving it is a human's job.
            body = (
                "<html><head>"
                "<script src=\"https://www.google.com/recaptcha/api.js\"></script>"
                "</head><body><h1>Sign in</h1>"
                "<form method=\"POST\" action=\"/login\">"
                "<input type=\"text\" name=\"user\"><input type=\"password\" name=\"pass\">"
                "<div class=\"g-recaptcha\" data-sitekey=\"demo\"></div>"
                "<button type=\"submit\">Sign in</button></form></body></html>"
            )
            self._html(body)

        elif path == "/old-bucket":
            # Simulated decommissioned S3 bucket: the DNS still points here,
            # the bucket behind it is gone. The classic takeover setup.
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<Error><Code>NoSuchBucket</Code>"
                "<Message>The specified bucket does not exist</Message></Error>"
            )
            self._html(body, status=404, extra_headers={"Content-Type": "application/xml"})

        elif path == "/reset":
            # Vulnerable: the reset link is built from the Host header, so
            # whoever controls the header controls where the link points.
            host_header = self.headers.get("Host", "localhost")
            user = query.get("user", "")
            self._html(
                f"<html><body><p>Password reset for {user} sent: "
                f"http://{host_header}/reset?token=abc123</p></body></html>"
            )

        elif path == "/api":
            # Vulnerable: reflects an arbitrary Origin back into
            # Access-Control-Allow-Origin, with credentials allowed.
            origin = self.headers.get("Origin", "")
            data = '{"user":"demo","email":"admin@demo.local"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(data.encode())))
            self.end_headers()
            self.wfile.write(data.encode())

        elif path == "/admin":
            # Vulnerable: the admin panel is served to ANY role. The session
            # cookie is decorative - nothing is checked. This is the endpoint
            # `summit authorize` exists to catch.
            self._html(
                "<html><body><h1>Admin panel</h1>"
                "<p>Salary report: admin 9500, users 3200/3100/3000.</p>"
                "<p>Internal notes: acquisition planned Q3.</p></body></html>"
            )

        elif path == "/debug":
            # Vulnerable: an undocumented parameter flips the page into debug
            # mode and echoes its value. Nothing in the HTML advertises it -
            # exactly what `summit mine` is for.
            debug_value = query.get("debug", "")
            if debug_value:
                self._html(
                    f"<html><body><p>Normal page</p>"
                    f"<!-- debug mode enabled by request: {debug_value} --></body></html>"
                )
            else:
                self._html("<html><body><p>Normal page</p></body></html>")

        elif path == "/ping":
            # Vulnerable: simulates a shell wrapper. Everything after a shell
            # separator is treated as a second command - but only `echo <token>`
            # is implemented, so the demo is deterministic and never spawns a
            # real process.
            host = query.get("host", "")
            lines = [f"Pinging {host}..."]
            match = re.search(r"(?:;|\||&&|&|`|\$\()\s*echo\s+([A-Za-z0-9\-]+)", host)
            if match:
                lines.append(match.group(1))
            self._html("<html><body><pre>" + "\n".join(lines) + "</pre></body></html>")

        elif path == "/greet":
            # Vulnerable: a naive template engine that evaluates simple
            # arithmetic inside {{ }} - the classic SSTI canary condition.
            name = query.get("name", "")
            name = re.sub(r"\{\{(\d+\s*[\+\-\*/]\s*\d+)\}\}", lambda m: str(eval(m.group(1))), name)
            self._html(f"<html><body><h1>Hello {name}</h1><p>Welcome back.</p></body></html>")

        elif path == "/goto":
            # Vulnerable: redirects to a user-supplied target without
            # stripping CRLF - response splitting demo.
            target = query.get("to", "/")
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            if "\n" in target or "\r" in target:
                # Injected CR/LF breaks this response's framing - a strict
                # client would wait for a body that never comes. One
                # response per connection so every client still completes.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()

        elif path == "/.env":
            # Vulnerable: environment file left in the web root, served with
            # its real content (status-code-only scanners miss the difference).
            body = (
                "APP_KEY=base64:summitDemoKeyOnPurpose\n"
                "DB_PASSWORD=summit-demo-password\n"
                "DB_HOST=127.0.0.1\n"
            )
            self._html(body)

        elif path == "/account" or path.startswith("/account/"):
            # Seed for web cache deception: the response carries the session
            # cookie and the router ignores path suffixes, so
            # /account/anything.js answers with the same authenticated page -
            # exactly what a shared cache keys on.
            self._html(
                "<html><body><h1>Account</h1>"
                "<p>Plan: pro. Email: admin@demo.local.</p>"
                "<p>Billing history: 3 invoices, all paid.</p></body></html>",
                extra_headers={"Set-Cookie": "session=demo-static-session; Path=/"},
            )

        elif path == "/api/discount":
            # Seed for the Intruder-style fuzzer: the response only moves
            # for codes that actually exist - exactly the divergence a
            # payload run is looking for.
            code = query.get("code", "")
            if code == "SUMMIT10":
                self._html(
                    "<html><body><p>Discount applied: 10% off your order. "
                    "Have a nice day.</p></body></html>"
                )
            else:
                self._html(
                    "<html><body><p>Invalid discount code.</p></body></html>",
                    status=404,
                )

        elif path == "/graphql":
            # Vulnerable: introspection is enabled in production. Invalid
            # fields also get "Did you mean" suggestions back - the schema
            # leaks even where introspection has been switched off.
            if "summitNoSuchFieldProbe" in query.get("query", ""):
                self._graphql_suggestions()
                return
            body = json.dumps({
                "data": {"__schema": {"queryType": {"name": "Query"}, "types": [
                    {"name": "Query"}, {"name": "User"}, {"name": "Secret"},
                ]}}
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())

        elif path == "/register":
            # Vulnerable: the response tells attackers which emails exist.
            email = query.get("email", "")
            if email in ("admin@demo.local", "kevin@demo.local", "sarah@demo.local"):
                self._html(f"<html><body><p>Error: {email} is already registered.</p></body></html>")
            else:
                self._html(f"<html><body><p>Success! A confirmation was sent to {email}.</p></body></html>")

        elif path == "/files/":
            # Vulnerable: autoindex left on - every uploaded file is listed.
            body = (
                "<html><head><title>Directory listing for /files/</title></head><body>"
                "<h1>Directory listing for /files/</h1><hr><ul>"
                "<li><a href=\"/files/report-2026.pdf\">report-2026.pdf</a></li>"
                "<li><a href=\"/files/users.csv\">users.csv</a></li>"
                "</ul><hr></body></html>"
            )
            self._html(body)

        elif path == "/app.js":
            # Vulnerable: the bundle ships an AWS-shaped access key, and the
            # internal endpoint is only referenced from JavaScript - a plain
            # <a href> crawler never finds it, the AJAX-spider pass does.
            body = (
                "const AWS_ACCESS_KEY_ID = \"AKIA4QZ7R2NMSEC9XK3P\";\n"
                "fetch('/api/secret?token=abc123');\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/secret":
            # Vulnerable: internal API that leaks a token in its response,
            # with no cache restrictions. Only reachable via the JS pass.
            body = json.dumps({"token": "summit-demo-secret-token-9f3", "role": "internal"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())

        elif path == "/redirect":
            # Vulnerable: unvalidated redirect target.
            target = query.get("url", "/")
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            if "\n" in target or "\r" in target:
                # Injected CR/LF breaks this response's framing - a strict
                # client would wait for a body that never comes. One
                # response per connection so every client still completes.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()

        elif path == "/file":
            # Vulnerable: user-controlled path, resolved against a virtual
            # filesystem root (stand-in for a real file read).
            name = query.get("name", "")
            resolved = name if name.startswith("/") else "/" + name
            normalized = resolved.replace("\\", "/")
            while "/../" in normalized:
                normalized = normalized.replace("/../", "/")
            content = VFS.get(normalized)
            if content is None:
                self._html("<html><body><p>File not found.</p></body></html>", status=404)
            else:
                self._html(f"<html><body><pre>{content}</pre></body></html>")

        elif path == "/fetch":
            # Vulnerable: the server fetches a user-supplied URL - the SSRF
            # shape. Guarded to loopback on purpose: the demo proves the
            # detection (`summit scan --oob-listen`) without ever being
            # usable as a proxy against a third party. Real vulnerable
            # fetchers carry no such guard, which is why they leak cloud
            # metadata and internal services.
            target = query.get("url", "")
            absolute = target if "://" in target else ("http:" + target if target.startswith("//") else target)
            host = (urlsplit(absolute).hostname or "").lower()
            if host in ("127.0.0.1", "localhost", "::1"):
                outcome = "unreachable"
                try:
                    with urllib.request.urlopen(absolute, timeout=1.0) as fetched:
                        outcome = f"HTTP {fetched.status}"
                except Exception:
                    pass
                self._html(f"<html><body><p>Fetch complete: {outcome}.</p></body></html>")
            else:
                self._html("<html><body><p>Fetch skipped: this demo only calls back to localhost.</p></body></html>")

        elif path == "/xml":
            # Vulnerable: an "XML import" endpoint whose parser resolves
            # external entities against the virtual filesystem - post the
            # classic XXE payload and the "file contents" come back in the
            # reply (see summit/scan/modules/xxe.py for the payload used).
            self._html(
                "<html><body><h1>Document import</h1>"
                "<p>POST an XML document to this endpoint.</p></body></html>"
            )

        elif path == "/dom":
            # Vulnerable: the page's own script reads location.hash and
            # writes it into innerHTML - a DOM source-to-sink flow that
            # never crosses the network, so only static analysis sees it.
            self._html(
                "<html><head><title>Greeter</title></head><body>"
                "<div id=\"greeting\">Hello!</div>"
                "<script>"
                "function render() {"
                "  var who = decodeURIComponent(location.hash.slice(1));"
                "  document.getElementById(\"greeting\").innerHTML = \"Hello \" + who + \"!\";"
                "}"
                "render(); window.addEventListener(\"hashchange\", render);"
                "</script></body></html>"
            )

        else:
            self._html("<html><body><p>Not found.</p></body></html>", status=404)

    def do_POST(self) -> None:
        split = urlsplit(self.path)
        # Drain the body on every POST. A keep-alive connection whose body
        # is never read replays those bytes as the next request line
        # (HTTP/1.1 desync), and every request after it on that connection
        # gets a 400 instead of a real answer.
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if split.path == "/xml":
            # Vulnerable: the import parser resolves external entities and
            # "reads files" for whoever asks, mapping the paths onto the
            # virtual filesystem so nothing outside the demo is touched.
            parts: list[str] = []
            for match in re.finditer(r'SYSTEM\s+"file:///([^"]+)"', raw):
                file_path = "/" + match.group(1).lstrip("/")
                file_path = re.sub(r"^/[A-Za-z]:", "", file_path)
                parts.append(VFS.get(file_path, ""))
            body = "<?xml version=\"1.0\"?><import>" + "".join(parts) + "</import>"
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if split.path == "/graphql":
            # Same leak over POST: an unknown field comes back with field
            # suggestions, handing out real schema names.
            try:
                posted = json.loads(raw or "{}")
            except ValueError:
                posted = {}
            if "summitNoSuchFieldProbe" in str(posted.get("query", "")):
                self._graphql_suggestions()
                return
            body = json.dumps({"data": None})
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._html("<html><body><p>Not found.</p></body></html>", status=404)

    def do_TRACE(self) -> None:
        # Vulnerable: TRACE hands the request back to the caller - headers
        # and all. Legacy browsers turned that into Cross-Site Tracing;
        # modern ones block it, but the method being enabled is a finding.
        lines = [f"{self.command} {self.path} {self.request_version}"]
        lines.extend(f"{key}: {value}" for key, value in self.headers.items())
        data = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    print(f"[*] demo shop listening on http://127.0.0.1:{PORT} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()
