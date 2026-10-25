"""v1.2.0 regressions: the Nuclei-style template engine, XPath/SSI checks,
the OOB spray (Log4Shell, Shellshock, blind XXE), the raw JNDI listener,
the expanded sensitive-file catalog and the builtin-template CLI default.

Everything here is offline unless noted: the live tests bind 127.0.0.1 on
an ephemeral port and always shut down in a finally block.
"""

import re
import socket
import textwrap
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from summit import __version__
from summit.cli import build_parser
from summit.http.client import HttpClient
from summit.http.models import HttpRequest, HttpResponse
from summit.oob import OobServer, _extract_raw_token, new_token
from summit.scan import runtime
from summit.scan.core import InjectionPoint
from summit.scan.engine import ScanEngine
from summit.scan.modules.oob_spray import run_oob_spray
from summit.scan.modules.sensitive_files import run_sensitive_files
from summit.scan.modules.ssi import SsiInjectionCheck
from summit.scan.modules.xpath import XpathInjectionCheck
from summit.templates import (
    TemplateMatcher,
    _match_content,
    _resolve_placeholders,
    load_template,
    run_template,
    validate_template,
)


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _write_template(
    tmp_path: Path,
    name: str,
    request_block: str,
    *,
    severity: str = "low",
    confidence: str = "confirmed",
    cwe: str = "CWE-200",
    extra_info: str = "",
    extra_top: str = "",
) -> str:
    text = (
        f"id: {name}\n"
        "info:\n"
        f"  name: {name}\n"
        f"  severity: {severity}\n"
        f"  confidence: {confidence}\n"
        f"  classification:\n    cwe-id: {cwe}\n"
        "  remediation: none\n"
        f"{extra_info}"
        f"{extra_top}"
        "requests:\n"
        + textwrap.indent(textwrap.dedent(request_block), "  ")
    )
    path = tmp_path / f"{name}.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


class TemplateHandler(BaseHTTPRequestHandler):
    routes = {
        "/second": (b"needle-unique", {"X-Summit-Test": "yes"}),
        "/third": (b"needle-unique", {"X-Summit-Test": "yes"}),
        "/both": (b"needle-unique also-here", {}),
        "/forbidden": (b"forbidden needle-unique", {}),
        "/final": (b"final-marker", {}),
    }

    def _respond(self, body: bytes, extra: dict[str, str], status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        for key, value in extra.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body, extra = self.routes.get(path, (b"nope", {}))
        self._respond(body, extra, 200 if path in self.routes else 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._respond(b"posted", {})

    def log_message(self, *args):
        pass


class XPathErrorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = b"XPathException: Invalid predicate" if "'" in query else b"<html>clean page</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class XPathCleanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html>clean page</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


_MARKER_RE = re.compile(r"echo (summit[0-9a-f]{12})")


class SsiExecHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        match = _MARKER_RE.search(query)
        body = f"ran {match.group(1)}".encode() if match else f"echo {query}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SsiReflectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = query.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SensitiveHandler(BaseHTTPRequestHandler):
    bodies = {
        "/.env": b"APP_KEY=secret\nDB_PASSWORD=hunter2\n",
        "/.git/config": b"[core]\n\trepositoryformatversion = 0\n",
        "/.env.local": b"APP_KEY=local-secret\n",
    }

    def do_GET(self):
        path = urlsplit(self.path).path
        body = self.bodies.get(path, b"<html>welcome</html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class OobWiringHandler(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply()

    def do_POST(self):
        self._reply()

    def log_message(self, *args):
        pass


# --- template engine -------------------------------------------------------


def test_template_placeholders_cover_nuclei_variables():
    split = urlsplit("https://example.com:8443/a/b.txt?x=1")
    resolved = _resolve_placeholders(
        "{{BaseURL}}|{{Host}}|{{Hostname}}|{{Port}}|{{Scheme}}|{{Path}}|{{File}}",
        split,
    )
    assert resolved == (
        "https://example.com:8443|example.com:8443|example.com|8443|https|/a/b.txt|b.txt"
    )


def test_template_path_list_fans_out(tmp_path):
    path = _write_template(
        tmp_path,
        "fanout",
        """
        - method: GET
          path:
            - '{{BaseURL}}/missing'
            - '{{BaseURL}}/second'
            - '{{BaseURL}}/third'
          matchers:
            - type: word
              part: body
              words:
                - 'needle-unique'
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        findings = run_template(load_template(path), HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        urls = [finding.url for finding in findings]
        assert len(findings) == 2
        assert urls[0].endswith("/second") and urls[1].endswith("/third")
    finally:
        server.shutdown()


def test_template_stop_at_first_match_returns_early(tmp_path):
    path = _write_template(
        tmp_path,
        "stop-early",
        """
        - method: GET
          path:
            - '{{BaseURL}}/second'
            - '{{BaseURL}}/third'
          matchers:
            - type: word
              part: body
              words:
                - 'needle-unique'
        """,
        extra_top="stop-at-first-match: true\n",
    )
    server, port = start_server(TemplateHandler)
    try:
        findings = run_template(load_template(path), HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        assert len(findings) == 1
        assert findings[0].url.endswith("/second")
    finally:
        server.shutdown()


def test_template_word_condition_and_requires_every_word(tmp_path):
    matching = _write_template(
        tmp_path,
        "and-words-ok",
        """
        - method: GET
          path: '{{BaseURL}}/both'
          matchers:
            - type: word
              part: body
              words:
                - 'needle-unique'
                - 'also-here'
              condition: and
        """,
    )
    missing = _write_template(
        tmp_path,
        "and-words-missing",
        """
        - method: GET
          path: '{{BaseURL}}/second'
          matchers:
            - type: word
              part: body
              words:
                - 'needle-unique'
                - 'absent-token'
              condition: and
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        client = HttpClient(timeout=3)
        base = f"http://127.0.0.1:{port}"
        assert len(run_template(load_template(matching), client, base)) == 1
        assert run_template(load_template(missing), client, base) == []
    finally:
        server.shutdown()


def test_template_regex_matcher(tmp_path):
    path = _write_template(
        tmp_path,
        "regex-check",
        """
        - method: GET
          path: '{{BaseURL}}/second'
          matchers:
            - type: regex
              part: body
              regex: 'needle-[a-z]+'
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        findings = run_template(load_template(path), HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        assert len(findings) == 1
        assert "regex" in findings[0].evidence
    finally:
        server.shutdown()


def test_template_negative_matcher(tmp_path):
    path = _write_template(
        tmp_path,
        "negative-check",
        """
        - method: GET
          path: '{{BaseURL}}/second'
          matchers:
            - type: word
              part: body
              words:
                - 'forbidden'
              negative: true
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        client = HttpClient(timeout=3)
        base = f"http://127.0.0.1:{port}"
        assert len(run_template(load_template(path), client, base)) == 1
        # /forbidden contains the word, so the negative matcher must not fire.
        template = load_template(path)
        template.requests[0].paths = ["{{BaseURL}}/forbidden"]
        assert run_template(template, client, base) == []
    finally:
        server.shutdown()


def test_template_dsl_forms_match(tmp_path):
    path = _write_template(
        tmp_path,
        "dsl-check",
        """
        - method: GET
          path: '{{BaseURL}}/second'
          matchers:
            - type: dsl
              dsl: 'status == 200'
            - type: dsl
              dsl: 'contains(header, "x-summit-test")'
            - type: dsl
              dsl: 'len(body) > 3'
          matchers-condition: and
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        findings = run_template(load_template(path), HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        assert len(findings) == 1
        assert "status 200" in findings[0].evidence
    finally:
        server.shutdown()


def test_template_header_word_matcher_uses_headers_text(tmp_path):
    path = _write_template(
        tmp_path,
        "header-matcher",
        """
        - method: GET
          path: '{{BaseURL}}/second'
          matchers:
            - type: word
              part: header
              words:
                - 'X-Summit-Test: yes'
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        findings = run_template(load_template(path), HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        assert len(findings) == 1
    finally:
        server.shutdown()


def test_template_follow_redirects_toggle(tmp_path):
    no_follow = _write_template(
        tmp_path,
        "no-follow",
        """
        - method: GET
          path: '{{BaseURL}}/redirect'
          matchers:
            - type: word
              part: body
              words:
                - 'final-marker'
        """,
    )
    follow = _write_template(
        tmp_path,
        "follow",
        """
        - method: GET
          path: '{{BaseURL}}/redirect'
          follow-redirects: true
          matchers:
            - type: word
              part: body
              words:
                - 'final-marker'
        """,
    )
    server, port = start_server(TemplateHandler)
    try:
        client = HttpClient(timeout=3)
        base = f"http://127.0.0.1:{port}"
        assert run_template(load_template(no_follow), client, base) == []
        assert len(run_template(load_template(follow), client, base)) == 1
    finally:
        server.shutdown()


def test_template_propagates_cwe_and_cves(tmp_path):
    path = tmp_path / "cve-meta.yaml"
    path.write_text(
        textwrap.dedent(
            """
            id: meta-check
            info:
              name: meta
              severity: medium
              confidence: confirmed
              classification:
                cwe-id: CWE-89
                cve-id:
                  - CVE-2024-0001
              remediation: none
            requests:
              - method: GET
                path: '{{BaseURL}}/second'
                matchers:
                  - type: word
                    part: body
                    words:
                      - 'needle-unique'
            """
        ),
        encoding="utf-8",
    )
    server, port = start_server(TemplateHandler)
    try:
        findings = run_template(load_template(str(path)), HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-89"
        assert findings[0].cves == ["CVE-2024-0001"]
    finally:
        server.shutdown()


def test_template_validation_rejects_missing_id(tmp_path):
    path = tmp_path / "no-id.yaml"
    path.write_text("info:\n  name: x\nrequests: []\n", encoding="utf-8")
    errors = validate_template(str(path))
    assert any("missing 'id'" in error for error in errors)


def test_template_validation_rejects_high_without_confidence_rule(tmp_path):
    path = tmp_path / "high-no-rule.yaml"
    path.write_text(
        textwrap.dedent(
            """
            id: high-no-rule
            info:
              name: no rule
              severity: high
              confidence: confirmed
            requests:
              - method: GET
                path: '/'
                matchers:
                  - type: status
                    status: 200
            """
        ),
        encoding="utf-8",
    )
    errors = validate_template(str(path))
    assert any("confidence-rule" in error for error in errors)


def test_template_validation_rejects_bad_regex_and_dsl(tmp_path):
    regex_template = _write_template(
        tmp_path,
        "bad-regex",
        """
        - method: GET
          path: '{{BaseURL}}/'
          matchers:
            - type: regex
              regex: '('
        """,
    )
    dsl_template = _write_template(
        tmp_path,
        "bad-dsl",
        """
        - method: GET
          path: '{{BaseURL}}/'
          matchers:
            - type: dsl
              dsl: 'body contains needle'
        """,
    )
    assert any("invalid regex" in error for error in validate_template(regex_template))
    assert any("unsupported dsl" in error for error in validate_template(dsl_template))


def test_template_validation_rejects_bad_part_and_type(tmp_path):
    part_template = _write_template(
        tmp_path,
        "bad-part",
        """
        - method: GET
          path: '{{BaseURL}}/'
          matchers:
            - type: word
              part: cookie
              words:
                - 'x'
        """,
    )
    type_template = _write_template(
        tmp_path,
        "bad-type",
        """
        - method: GET
          path: '{{BaseURL}}/'
          matchers:
            - type: hash
              words:
                - 'x'
        """,
    )
    assert any("invalid matcher part" in error for error in validate_template(part_template))
    assert any("invalid matcher type" in error for error in validate_template(type_template))


def test_template_send_failure_is_skipped(tmp_path):
    path = _write_template(
        tmp_path,
        "dead-target",
        """
        - method: GET
          path: '{{BaseURL}}/'
          matchers:
            - type: status
              status: 200
        """,
    )
    findings = run_template(load_template(path), HttpClient(timeout=1), "http://127.0.0.1:1")
    assert findings == []


def test_match_content_backward_compatible():
    response = HttpResponse(status=200, headers={"X-Test": "yes"}, body=b"needle")
    matcher = TemplateMatcher(type="word", part="body", words=["needle"])
    assert _match_content(response, matcher) is True


# --- XPath injection -------------------------------------------------------


def test_xpath_injection_confirms_fresh_parser_error():
    server, port = start_server(XPathErrorHandler)
    try:
        point = InjectionPoint(
            request=HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/search?q=alpha"),
            param="q",
            original_value="alpha",
        )
        findings = XpathInjectionCheck().run(point, HttpClient(timeout=3))
        assert len(findings) == 1
        assert findings[0].check_id == "xpath-injection"
        assert findings[0].confidence == "confirmed"
        assert "XPathException" in findings[0].evidence
    finally:
        server.shutdown()


def test_xpath_injection_quiet_when_baseline_already_has_error():
    server, port = start_server(XPathCleanHandler)
    try:
        point = InjectionPoint(
            request=HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/search?q=alpha"),
            param="q",
            original_value="alpha",
        )
        assert XpathInjectionCheck().run(point, HttpClient(timeout=3)) == []
    finally:
        server.shutdown()


# --- SSI injection ---------------------------------------------------------


def test_ssi_injection_requires_execution_not_reflection():
    server, port = start_server(SsiExecHandler)
    try:
        point = InjectionPoint(
            request=HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/render?q=hello"),
            param="q",
            original_value="hello",
        )
        findings = SsiInjectionCheck().run(point, HttpClient(timeout=3))
        assert len(findings) == 1
        assert findings[0].check_id == "ssi-injection"
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


def test_ssi_injection_quiet_when_payload_is_only_reflected():
    server, port = start_server(SsiReflectHandler)
    try:
        point = InjectionPoint(
            request=HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/render?q=hello"),
            param="q",
            original_value="hello",
        )
        assert SsiInjectionCheck().run(point, HttpClient(timeout=3)) == []
    finally:
        server.shutdown()


# --- OOB spray -------------------------------------------------------------


def test_oob_spray_reports_only_callback_confirmed_vectors():
    server, port = start_server(TemplateHandler)
    try:
        findings = run_oob_spray(
            HttpClient(timeout=3),
            f"http://127.0.0.1:{port}",
            [],
            "http://127.0.0.1:9",
            lambda token: True,
            jndi_base="127.0.0.1:1389",
        )
        assert {finding.check_id for finding in findings} == {"log4shell", "shellshock", "xxe-oob"}
        assert all(finding.confidence == "confirmed" for finding in findings)
    finally:
        server.shutdown()


def test_oob_spray_silent_without_callbacks():
    server, port = start_server(TemplateHandler)
    try:
        findings = run_oob_spray(
            HttpClient(timeout=3),
            f"http://127.0.0.1:{port}",
            [],
            "http://127.0.0.1:9",
            lambda token: False,
            jndi_base="127.0.0.1:1389",
        )
        assert findings == []
    finally:
        server.shutdown()


def test_engine_wires_oob_spray():
    server, port = start_server(OobWiringHandler)
    try:
        client = HttpClient(timeout=3)
        page = client.send(HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/"))
        engine = ScanEngine(
            client,
            checks=[],
            linkcheck_enabled=False,
            takeover=False,
            oob_callback_base="http://127.0.0.1:9",
            oob_raw_base="127.0.0.1:1389",
            oob_hit_checker=lambda token: True,
        )
        findings = engine.scan({"pages": [page], "forms": []})
        assert "log4shell" in {finding.check_id for finding in findings}
        assert "shellshock" in {finding.check_id for finding in findings}
        assert "xxe-oob" in {finding.check_id for finding in findings}
    finally:
        server.shutdown()


def test_extract_raw_token_handles_digits_in_prefix():
    token = new_token("log4j")
    payload = f"jndi:ldap://127.0.0.1:1389/{token}".encode()
    assert _extract_raw_token(payload) == token
    assert _extract_raw_token(b"no token here") == ""


def test_oob_raw_listener_captures_jndi_token():
    server = OobServer(port=0)
    try:
        server.start()
        token = new_token("log4j")
        assert server.raw_port > 0
        with socket.create_connection(("127.0.0.1", server.raw_port), timeout=2) as conn:
            conn.sendall(f"jndi:ldap://127.0.0.1:{server.raw_port}/{token}".encode())
        hit = server.wait_for(token, timeout=3)
        assert hit is not None
        assert hit.method == "TCP" and hit.path == "(jndi)"

        http_token = new_token("http")
        urllib.request.urlopen(server.callback_url(http_token), timeout=3).read()
        assert server.wait_for(http_token, timeout=3) is not None
    finally:
        server.stop()


# --- sensitive files -------------------------------------------------------


def test_sensitive_files_content_signatures_only():
    server, port = start_server(SensitiveHandler)
    try:
        base = f"http://127.0.0.1:{port}"
        findings = run_sensitive_files(HttpClient(timeout=3), base)
        urls = {finding.url for finding in findings}
        assert base + "/.env" in urls
        assert base + "/.git/config" in urls
        assert all(finding.confidence == "confirmed" for finding in findings)
        # A wildcard 200 that serves HTML must never be mistaken for a leak.
        assert base + "/phpinfo.php" not in urls
    finally:
        server.shutdown()


def test_sensitive_files_deep_mode_adds_variants():
    server, port = start_server(SensitiveHandler)
    original = runtime.deep()
    try:
        runtime.set_deep(True)
        findings = run_sensitive_files(HttpClient(timeout=3), f"http://127.0.0.1:{port}")
        assert any(finding.url.endswith("/.env.local") for finding in findings)
    finally:
        runtime.set_deep(original)
        server.shutdown()


# --- CLI + version ---------------------------------------------------------


def test_scan_parser_runs_builtin_templates_by_default():
    default_args = build_parser().parse_args(["scan", "http://127.0.0.1:1"])
    assert default_args.no_templates is False
    assert default_args.templates_path is None
    disabled_args = build_parser().parse_args(["scan", "http://127.0.0.1:1", "--no-templates"])
    assert disabled_args.no_templates is True


def test_run_templates_skipped_in_passive_only_mode(monkeypatch):
    import argparse

    from summit.cli import _run_templates

    calls = []
    monkeypatch.setattr("summit.templates.run_template", lambda *a, **k: calls.append(1) or [])
    args = argparse.Namespace(
        no_templates=False, no_active=True, templates_path=None, url="http://127.0.0.1:1"
    )
    _run_templates(args, None, None, None, {})
    assert calls == []


def test_version_is_1_3_0():
    assert __version__ == "2.1.0"
