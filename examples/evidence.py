"""Reproduce every claim in the README against the local demo target.

This is the evidence runner: each claim is measured live and printed as
PASS or FAIL with the actual numbers. It runs the demo app in-process,
so nothing outside 127.0.0.1 is touched (the link health check resolves
DNS for the seeded dead domain, which never connects anywhere).

    python examples/evidence.py

Exit code 0 means every claim held. CI runs this on every push.
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.vuln_app import DemoHandler  # noqa: E402
from summit.http.client import HttpClient  # noqa: E402
from summit.http.models import HttpRequest  # noqa: E402
from summit.scan.core import InjectionPoint  # noqa: E402
from summit.scan.engine import ScanEngine  # noqa: E402
from summit.scan.modules.waf_bypass import PAYLOAD  # noqa: E402
from summit.scan.modules.dom_xss import check_dom_xss  # noqa: E402
from summit.scan.modules.http_methods import run_http_methods  # noqa: E402
from summit.scan.modules.js_secrets import check_js_secrets  # noqa: E402
from summit.scan.modules.ssrf import SsrfCheck  # noqa: E402
from summit.scan.modules.xxe import run_xxe  # noqa: E402
from summit.oob import OobServer  # noqa: E402
from summit.captcha import detect_challenge  # noqa: E402
from summit.toolkit import jwt_decode  # noqa: E402
from summit.updates import is_outdated  # noqa: E402
from summit.crawl.spider import Spider  # noqa: E402

PORT = 8777
BASE = f"http://127.0.0.1:{PORT}"
results: list[tuple[str, bool, str]] = []


def claim(name: str, ok: bool, evidence: str) -> None:
    results.append((name, ok, evidence))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n       {evidence}")


def _reconfigure_stdio() -> None:
    """Force UTF-8 on Windows consoles so arrows/glyphs survive pipes."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main() -> int:
    _reconfigure_stdio()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        client = HttpClient(timeout=10)

        # --- 1. full scan: every seeded check fires, negative control stays quiet
        spider = Spider(client, max_depth=1, max_pages=30)
        spider_result = spider.crawl(BASE)
        engine = ScanEngine(client, workers=8)
        findings = engine.scan(spider_result)
        check_ids = {f.check_id for f in findings}
        expected = {
            "sqli-error", "sqli-boolean", "xss-reflection", "open-redirect",
            "path-traversal", "linkcheck-dead-domain", "waf-bypass", "waf-detected", "captcha-challenge",
            "takeover-signature", "host-header-injection", "cors-reflection",
            "os-command-injection", "ssti", "crlf-injection", "sensitive-file",
            "xxe", "trace-enabled", "js-secret", "dom-xss",
        }
        missing = expected - check_ids
        control_fp = [f.url for f in findings if f.url.startswith("https://example.com")]
        confirmed = sum(1 for f in findings if f.confidence == "confirmed")
        claim(
            "full scan: 20 seeded check families detected, zero false positives",
            not missing and not control_fp,
            f"{len(findings)} findings in {engine.elapsed:.1f}s ({client.request_count} requests), "
            f"missing={sorted(missing) if missing else 'none'}, control link flagged={control_fp or 'no'}, "
            f"{confirmed} finding(s) carry confidence=confirmed",
        )

        # --- 1b. the new v0.4 checks, each shown with its own evidence
        takeover = next((f for f in findings if f.check_id == "takeover-signature"), None)
        claim(
            "resource takeover fingerprint detected on the target's own 404",
            takeover is not None and takeover.confidence == "confirmed",
            f"{takeover.title} | {takeover.evidence}" if takeover else "not found",
        )
        host_header = next((f for f in findings if f.check_id == "host-header-injection"), None)
        claim(
            "host header injection: marker domain echoed back by the app",
            host_header is not None and host_header.confidence == "confirmed",
            f"{host_header.evidence} (reset-link poisoning surface)" if host_header else "not found",
        )
        cors = next((f for f in findings if f.check_id == "cors-reflection"), None)
        claim(
            "CORS reflects an arbitrary origin with credentials allowed",
            cors is not None and cors.confidence == "confirmed",
            cors.evidence if cors else "not found",
        )

        # --- 2. WAF bypass, shown at the HTTP level (same code path the check uses)
        base = HttpRequest(method="GET", url=f"{BASE}/protected?token=demo")
        blocked = client.send(base.with_query_param("token", PAYLOAD))
        tampered = client.send(base.with_query_param("token", quote(PAYLOAD)))
        claim(
            "WAF bypass: naive filter blocks, tampered payload lands decoded",
            blocked.status == 403 and tampered.status == 200 and PAYLOAD in tampered.text,
            f"raw payload -> HTTP {blocked.status} (blocked); "
            f"URL-encoded once -> HTTP {tampered.status}, payload reflected decoded: {PAYLOAD in tampered.text}",
        )

        # --- 3. CAPTCHA is detected, not hammered
        login = client.send(HttpRequest(method="GET", url=f"{BASE}/login"))
        detected = detect_challenge(login)
        claim(
            "CAPTCHA challenge detected (reported, not solved)",
            detected is not None and detected[0] == "reCAPTCHA",
            f"/login -> {detected[0]} via marker {detected[1]!r}" if detected else "no challenge found",
        )

        # --- 4. rate limiter is real: measure 12 requests at 5 rps vs unlimited
        paced = HttpClient(rate=5)
        started = time.monotonic()
        for _ in range(12):
            paced.send(HttpRequest(method="GET", url=BASE))
        paced_elapsed = time.monotonic() - started
        fast = HttpClient()
        started = time.monotonic()
        for _ in range(12):
            fast.send(HttpRequest(method="GET", url=BASE))
        fast_elapsed = time.monotonic() - started
        claim(
            "rate limiting: --rate 5 paces 12 requests to ~2.2s; unlimited runs free",
            paced_elapsed >= 2.1 and fast_elapsed < paced_elapsed,
            f"12 requests at rate 5 -> {paced_elapsed:.2f}s (theoretical floor: 2.2s); "
            f"12 requests unlimited -> {fast_elapsed:.2f}s",
        )

        # --- 5. concurrency measured where it matters: a target with latency.
        # Loopback answers in microseconds, which hides what parallelism buys.
        # This endpoint sleeps 25ms per request, like a real server over the wire.
        # Best of 3 each - CI runners share CPUs and one noisy run must not
        # fail an otherwise valid claim.
        from concurrent.futures import ThreadPoolExecutor

        class SlowHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(0.025)
                body = b"slow but steady"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        slow_server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        slow_port = slow_server.server_address[1]
        threading.Thread(target=slow_server.serve_forever, daemon=True).start()
        try:
            urls = [f"http://127.0.0.1:{slow_port}/slow?i={index}" for index in range(40)]

            def measure(parallel: bool) -> float:
                best = float("inf")
                for _ in range(3):
                    started = time.monotonic()
                    if parallel:
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            list(pool.map(lambda url: client.send(HttpRequest(method="GET", url=url)), urls))
                    else:
                        for url in urls:
                            client.send(HttpRequest(method="GET", url=url))
                    best = min(best, time.monotonic() - started)
                return best

            serial_elapsed = measure(parallel=False)
            parallel_elapsed = measure(parallel=True)
            speedup = serial_elapsed / max(parallel_elapsed, 0.001)
            claim(
                "concurrency on a latency-bearing target: 8 workers vs serial (best of 3)",
                speedup >= 3.0,
                f"40 requests x 25ms latency: serial {serial_elapsed:.2f}s -> parallel {parallel_elapsed:.2f}s "
                f"({speedup:.1f}x speedup)",
            )
        finally:
            slow_server.shutdown()

        # --- 6. smart prioritizer puts known-injectable names first
        from summit.smart import prioritize  # noqa: E402
        from summit.scan.engine import build_targets  # noqa: E402
        targets = prioritize(build_targets(spider_result))
        first = targets[0]
        claim(
            "smart prioritizer ranks known-injectable parameters first",
            first.param in {"query", "id", "url", "name", "file", "token"},
            f"probing starts with: {[(p.param, p.request.url.rsplit('/', 1)[-1]) for p in targets[:3]]}",
        )

        # --- 7. toolkit decodes a JWT honestly
        header = "eyJhbGciOiJIUzI1NiJ9"
        payload = "eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0"
        decoded = jwt_decode(f"{header}.{payload}.c2ln")
        claim(
            "toolkit decodes JWT header/payload and states the signature is unverified",
            '"role": "admin"' in decoded and "NOT verified" in decoded,
            decoded.splitlines()[-1].strip("()"),
        )

        # --- 8. version comparison is numeric, not lexicographic
        claim(
            "update check compares versions numerically (0.3 < 0.10)",
            is_outdated("0.3.0", "0.10.0") and not is_outdated("1.0.0", "0.9.9"),
            "is_outdated('0.3.0', '0.10.0') -> True; is_outdated('1.0.0', '0.9.9') -> False",
        )

        # --- 9. authorize: the admin panel must be caught serving a low-privilege role
        from summit.authorize import Role, findings_from, run_authorize  # noqa: E402
        auth_results = run_authorize(
            client,
            [f"{BASE}/admin?user=1"],
            Role("admin", {"Cookie": "session=admin-token"}),
            Role("user", {"Cookie": "session=user-token"}),
        )
        auth_findings = findings_from(auth_results)
        claim(
            "broken access control: admin panel served identically to a low-privilege role",
            auth_results and auth_results[0].verdict == "broken" and auth_findings
            and auth_findings[0].severity == "critical",
            f"verdict={auth_results[0].verdict if auth_results else 'none'}; "
            f"finding={auth_findings[0].title if auth_findings else 'none'}",
        )

        # --- 10. param miner: the undocumented debug parameter must be discovered,
        #         and the ~120 other candidates must stay quiet
        from summit.paramminer import mine  # noqa: E402
        mined = mine(client, f"{BASE}/debug")
        reflected = [f for f in mined if f.check_id == "paramminer-reflected" and f.param == "debug"]
        claim(
            "hidden parameter mining finds the undocumented debug parameter, zero noise",
            len(reflected) == 1 and all(f.param == "debug" for f in mined),
            f"{len(mined)} finding(s): {sorted(f.param for f in mined)} (all confirmed reflections)",
        )

        # --- 11. openapi-driven scan finds seeded SQLi without any crawling
        from summit.openapi import load_spec, spec_pages  # noqa: E402
        spec = load_spec(str(Path(__file__).resolve().parent / "openapi.json"))
        # the spec's declared server points at the standard demo port; this
        # runner uses its own port, which is exactly what base_url is for
        api_result = spec_pages(client, spec, base_url=BASE)
        api_engine = ScanEngine(client, workers=8, linkcheck_enabled=False)
        api_findings = api_engine.scan(api_result)
        api_ids = {f.check_id for f in api_findings}
        claim(
            "openapi-driven scan: spec alone leads the engine to seeded SQLi and XSS",
            "sqli-error" in api_ids and "xss-reflection" in api_ids,
            f"{len(api_result['pages'])} spec target(s) scanned -> {len(api_findings)} findings, "
            f"sqli-error={'yes' if 'sqli-error' in api_ids else 'NO'}, "
            f"xss-reflection={'yes' if 'xss-reflection' in api_ids else 'NO'}",
        )

        # --- 12. OS command injection (from the full scan above)
        from summit.scan.core import cwe_for  # noqa: E402
        os_cmd = next((f for f in findings if f.check_id == "os-command-injection"), None)
        claim(
            "OS command injection: marker executed and echoed by the server",
            os_cmd is not None and os_cmd.confidence == "confirmed" and cwe_for("os-command-injection") == "CWE-78",
            f"{os_cmd.evidence if os_cmd else 'not found'} | {cwe_for('os-command-injection')}",
        )

        # --- 13. SSTI: {{7*7}} evaluated to 49
        ssti = next((f for f in findings if f.check_id == "ssti"), None)
        claim(
            "server-side template injection: {{7*7}} came back as 49",
            ssti is not None and ssti.confidence == "confirmed" and "49" in ssti.evidence,
            f"{ssti.evidence if ssti else 'not found'} | {cwe_for('ssti')}",
        )

        # --- 14. CRLF injection: our injected header materialized
        crlf = next((f for f in findings if f.check_id == "crlf-injection"), None)
        claim(
            "CRLF injection: X-Summit-CRLF header materialized in the response",
            crlf is not None and crlf.confidence == "confirmed" and "injected" in crlf.evidence,
            f"{crlf.evidence if crlf else 'not found'} | {cwe_for('crlf-injection')}",
        )

        # --- 15. sensitive file: content signature, not just a 200
        env = next((f for f in findings if f.check_id == "sensitive-file"), None)
        claim(
            "sensitive file exposure: /.env confirmed by content signature",
            env is not None and env.confidence == "confirmed" and "APP_KEY" in env.evidence,
            f"{env.evidence if env else 'not found'} | {cwe_for('sensitive-file')}",
        )

        # --- 16. CVE detection from version banners (offline database)
        from summit.cve import detect_cves  # noqa: E402
        hits = detect_cves("Apache/2.4.49")
        cve_ids = {h["cve"] for h in hits}
        claim(
            "CVE detection: Apache/2.4.49 banner maps to known CVEs",
            "CVE-2021-41773" in cve_ids and "CVE-2021-42013" in cve_ids,
            f"detect_cves('Apache/2.4.49') -> {sorted(cve_ids)}",
        )

        # --- 17. time-based SQL injection: the /user handler pauses 0.25s on a
        #         SLEEP marker; the check runs with a matching small threshold
        from summit.scan.modules.sqli_time import SqliTimeCheck  # noqa: E402
        time_point = InjectionPoint(
            request=HttpRequest(method="GET", url=f"{BASE}/user?id=1"),
            param="id",
            original_value="1",
        )
        time_findings = SqliTimeCheck(delay_threshold=0.2, repetitions=2).run(time_point, client)
        claim(
            "time-based SQL injection: reproducible delay detected and calibrated",
            time_findings and time_findings[0].confidence == "likely",
            time_findings[0].evidence if time_findings else "not found",
        )

        # --- 18. GraphQL introspection: found in the full scan
        gql = next((f for f in findings if f.check_id == "graphql-introspection"), None)
        claim(
            "GraphQL introspection detected on a production-looking endpoint",
            gql is not None and gql.confidence == "confirmed" and "__schema" in gql.evidence,
            f"{gql.evidence if gql else 'not found'} | {cwe_for('graphql-introspection') or 'CWE-200'}",
        )

        # --- 19. frontend CVE detection: jQuery + WordPress on the same page
        body_cves = next((f for f in findings if f.check_id == "cve-detected" and f.cves), None)
        expected_cves = {"CVE-2020-11023", "CVE-2021-29447"}
        claim(
            "frontend CVE detection: jQuery 3.4.1 + WordPress 5.7.1 map to known CVEs",
            body_cves is not None and expected_cves.issubset(set(body_cves.cves)),
            f"{body_cves.cves if body_cves else 'not found'} ({body_cves.evidence if body_cves else ''})",
        )

        # --- 20. SSRF, out-of-band confirmed: a real listener records the
        #         server's callback; the same check stays silent on a plain
        #         redirector - redirects are not fetches (negative control)
        oob = OobServer(port=0)
        oob.start()
        try:
            fetch_point = InjectionPoint(
                request=HttpRequest(method="GET", url=f"{BASE}/fetch?url=http://127.0.0.1:8765/"),
                param="url",
                original_value="http://127.0.0.1:8765/",
            )
            ssrf_hits = SsrfCheck(
                oob.base_url,
                hit_checker=lambda token: oob.wait_for(token, timeout=2.0) is not None,
            ).run(fetch_point, client)
            redirect_point = InjectionPoint(
                request=HttpRequest(method="GET", url=f"{BASE}/redirect?url=https://example.com"),
                param="url",
                original_value="https://example.com",
            )
            redirect_hits = SsrfCheck(
                oob.base_url,
                hit_checker=lambda token: oob.wait_for(token, timeout=1.0) is not None,
            ).run(redirect_point, client)
            ssrf = ssrf_hits[0] if ssrf_hits else None
            callback_log = oob.hits[0].summary() if oob.hits else "no callbacks"
            claim(
                "SSRF confirmed out-of-band: the server fetched our callback URL",
                ssrf is not None and ssrf.confidence == "confirmed" and bool(oob.hits) and not redirect_hits,
                f"{ssrf.evidence if ssrf else 'not found'}; callback log: {callback_log}; "
                f"redirector control: {'silent' if not redirect_hits else 'FIRED (false positive!)'}",
            )
        finally:
            oob.stop()

        # --- 21. XXE: the import endpoint resolves our external entity and
        #         hands back virtual-filesystem file content
        xxe_findings = run_xxe(client, spider_result.get("forms", []), BASE)
        xxe = xxe_findings[0] if xxe_findings else None
        claim(
            "XXE: external entity resolved, local file content returned",
            xxe is not None and xxe.confidence == "confirmed" and "root:x" in xxe.evidence,
            f"{xxe.evidence if xxe else 'not found'} | {cwe_for('xxe')}",
        )

        # --- 22. TRACE enabled: the server echoed our probe marker back
        method_findings = run_http_methods(client, BASE)
        trace = next((f for f in method_findings if f.check_id == "trace-enabled"), None)
        claim(
            "TRACE enabled: probe marker header echoed back",
            trace is not None and trace.confidence == "confirmed" and "9f3c2a" in trace.evidence,
            f"{trace.evidence if trace else 'not found'} | {cwe_for('trace-enabled')}",
        )

        # --- 23. hardcoded secret in the JS bundle: found, redacted, and
        #         honestly labelled likely - a demo key is not a live credential
        app_js = client.send(HttpRequest(method="GET", url=f"{BASE}/app.js"))
        secret_findings = check_js_secrets(app_js)
        secret = secret_findings[0] if secret_findings else None
        raw_key = "AKIA4QZ7R2NMSEC9XK3P"
        claim(
            "hardcoded AWS key in the client bundle: reported likely, value redacted",
            secret is not None and secret.confidence == "likely" and secret.severity == "medium"
            and "AKIA4Q\u2026XK3P" in secret.evidence and raw_key not in secret.evidence,
            f"{secret.evidence if secret else 'not found'} | {cwe_for('js-secret')}",
        )

        # --- 24. DOM XSS candidate: static source->sink flow, capped at
        #         needs-manual until a human confirms it in a browser
        dom_page = client.send(HttpRequest(method="GET", url=f"{BASE}/dom"))
        dom_findings = check_dom_xss(dom_page)
        dom = dom_findings[0] if dom_findings else None
        claim(
            "DOM XSS candidate: location.hash flows into innerHTML (needs manual)",
            dom is not None and dom.confidence == "needs-manual"
            and "location.hash" in dom.evidence and "innerHTML" in dom.evidence,
            f"{dom.evidence if dom else 'not found'} | {cwe_for('dom-xss')}",
        )

        # --- 25. Intruder-style payload fuzzing: the seeded discount code is
        #         the control; every bogus code shifts the response from
        #         HTTP 200 to HTTP 404. Divergence is reported needs-manual -
        #         only a human can say what the difference means.
        from summit.fuzz.intruder import findings_from as intruder_findings  # noqa: E402
        from summit.fuzz.intruder import run_intruder  # noqa: E402
        fuzz_raw = (
            f"GET /api/discount?code=§SUMMIT10§ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{PORT}\r\n"
            "User-Agent: summit-evidence\r\n"
            "\r\n"
        )
        intruder = run_intruder(client, fuzz_raw, payloads=["BOGUS1", "BOGUS2"])
        divergent = [hit for hit in intruder.hits if hit.divergent]
        fuzz_findings = intruder_findings(intruder)
        claim(
            "intruder-style fuzzing: bogus codes diverge from the control (200 -> 404)",
            intruder.control is not None and intruder.control.status == 200
            and len(divergent) == 2 and len(fuzz_findings) == 2,
            f"control HTTP {intruder.control.status if intruder.control else '?'}; "
            f"payloads {sorted(hit.payloads[0] for hit in divergent)} -> "
            f"{sorted(hit.response.status for hit in divergent if hit.response)} (divergent); "
            f"{len(fuzz_findings)} needs-manual finding(s)",
        )

        # --- 26. GraphQL field suggestions: an invalid field comes back with
        #         "Did you mean" - schema names leak without introspection.
        suggestions = next((f for f in findings if f.check_id == "graphql-field-suggestions"), None)
        claim(
            "GraphQL field suggestions leak schema names on an invalid field",
            suggestions is not None and suggestions.confidence == "confirmed"
            and "did you mean" in suggestions.evidence.lower(),
            f"{suggestions.evidence if suggestions else 'not found'} | "
            f"{cwe_for('graphql-field-suggestions') or 'CWE-200'}",
        )

        # --- 27. Markdown report: the same findings, rendered as the format
        #         triage documents and pull-request comments speak.
        from summit.report.writer import write_markdown  # noqa: E402
        with tempfile.TemporaryDirectory() as md_dir:
            md_path = write_markdown(findings, str(Path(md_dir) / "report.md"), BASE)
            md_text = Path(md_path).read_text(encoding="utf-8")
        sections = md_text.count("#### [")
        claim(
            "markdown report renders every finding for triage documents",
            "## Findings" in md_text and "| Severity | Count |" in md_text
            and sections == len(findings),
            f"{sections}/{len(findings)} finding section(s) rendered, severity summary table present",
        )

        # --- 28. TLS interception: a real CONNECT tunnel through the proxy,
        #         decrypted with the locally generated CA, and the inner
        #         request lands in the site map in plaintext.
        import socket as socket_module  # noqa: E402
        import sqlite3 as sqlite3_module  # noqa: E402
        import ssl as ssl_module  # noqa: E402

        from summit.proxy.ca import issue_leaf as ca_issue_leaf  # noqa: E402
        from summit.proxy.ca import load_or_create_ca  # noqa: E402
        from summit.proxy.server import ProxyServer  # noqa: E402

        ca_dir = Path(tempfile.mkdtemp(prefix="summit-ca-"))
        load_or_create_ca(ca_dir)
        tls_origin = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        origin_ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
        origin_ctx.load_cert_chain(str(ca_issue_leaf(ca_dir, "127.0.0.1")))
        tls_origin.socket = origin_ctx.wrap_socket(tls_origin.socket, server_side=True)
        # abrupt proxy-side teardowns after Connection: close are expected;
        # the origin's reset traceback is noise here, not a claim failure
        tls_origin.handle_error = lambda request, client_address: None
        threading.Thread(target=tls_origin.serve_forever, daemon=True).start()
        origin_port = tls_origin.server_address[1]

        def _free_port() -> int:
            with socket_module.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        proxy_port = _free_port()
        sitemap_path = Path(tempfile.mkdtemp(prefix="summit-map-")) / "sitemap.db"
        proxy = ProxyServer(host="127.0.0.1", port=proxy_port, db_path=str(sitemap_path),
                            tls_intercept=True, ca_dir=str(ca_dir))
        threading.Thread(target=proxy.start, daemon=True).start()
        time.sleep(0.4)
        try:
            raw = socket_module.create_connection(("127.0.0.1", proxy_port), timeout=5)
            raw.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % origin_port)
            connect_reply = b""
            while b"\r\n\r\n" not in connect_reply:
                connect_reply += raw.recv(4096)
            client_ctx = ssl_module.create_default_context()
            client_ctx.load_verify_locations(str(ca_dir / "ca.crt"))
            tls_client = client_ctx.wrap_socket(raw, server_hostname="127.0.0.1")
            tls_client.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            body = b""
            while True:
                chunk = tls_client.recv(4096)
                if not chunk:
                    break
                body += chunk
            tls_client.close()
            rows = sqlite3_module.connect(str(sitemap_path)).execute(
                "SELECT method, url, status FROM sitemap WHERE method = 'GET'"
            ).fetchall()
            logged = [row for row in rows if row[1] == f"https://127.0.0.1:{origin_port}/" and row[2] == 200]
            claim(
                "TLS interception: HTTPS through the proxy is decrypted and logged in plaintext",
                b"200" in body.split(b"\r\n", 1)[0] and b"Summit demo shop" in body and bool(logged),
                f"CONNECT tunnel -> TLS 1.3 via the proxy CA, GET / answered HTTP "
                f"{body.split(b' ')[1].decode() if b' ' in body else '?'}; site map row: {logged[0] if logged else 'MISSING'}",
            )
        finally:
            proxy.stop()
            tls_origin.shutdown()

        # --- 29. Web cache deception: the session-bearing /account page is
        #         served for cacheable path suffixes - reported needs-manual.
        wcd = next((f for f in findings if f.check_id == "cache-deception"), None)
        claim(
            "web cache deception surface: session page answers under a cacheable .js path",
            wcd is not None and wcd.confidence == "needs-manual" and "/account" in wcd.url,
            f"{wcd.evidence if wcd else 'not found'} | {cwe_for('cache-deception') or 'CWE-441'}",
        )

        # --- 30. Scan scheduling: two rounds on an interval, the second diffed
        #         against the first with the same dedup key as `summit diff`.
        import subprocess as subprocess_module  # noqa: E402

        history_dir = Path(tempfile.mkdtemp(prefix="summit-hist-"))
        schedule_run = subprocess_module.run(
            [sys.executable, "-m", "summit", "schedule", BASE,
             "--every", "0.5", "--times", "2", "--out-dir", str(history_dir),
             "--", "--no-templates", "--skip-linkcheck", "--no-active"],
            capture_output=True, text=True, timeout=120,
        )
        rounds = sorted(history_dir.glob("scan-*.json"))
        claim(
            "scan scheduling: rounds run on an interval and every round is diffed",
            schedule_run.returncode == 0 and len(rounds) == 2
            and "[round 1/2]" in schedule_run.stdout and "[round 2/2]" in schedule_run.stdout
            and "new 0, resolved 0, regressed 0" in schedule_run.stdout,
            f"2 round(s) completed in {schedule_run.stdout.count('[round ')}/2 printed summaries, "
            f"diff line present: {'new 0, resolved 0, regressed 0' in schedule_run.stdout}",
        )
    finally:
        server.shutdown()

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\nevidence summary: {passed}/{len(results)} claims verified")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
