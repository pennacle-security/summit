"""v2.1.0 regressions: TLS-intercepting proxy, scan scheduling, and the
web cache deception check."""

from __future__ import annotations

import ipaddress
import socket
import sqlite3
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="TLS interception needs the optional [proxy] extra")

from summit.proxy.ca import issue_leaf, load_or_create_ca  # noqa: E402
from summit.proxy.server import ProxyServer  # noqa: E402
from summit.scan.modules.cache_deception import run_cache_deception  # noqa: E402
from summit.http.client import HttpClient  # noqa: E402
from summit.http.models import HttpRequest  # noqa: E402


# ---------------------------------------------------------------------------
# certificate authority
# ---------------------------------------------------------------------------


def test_ca_is_created_once_and_reused(tmp_path):
    cert_one, key_one = load_or_create_ca(tmp_path)
    cert_two, key_two = load_or_create_ca(tmp_path)
    assert cert_one == cert_two and key_one == key_two
    assert b"BEGIN CERTIFICATE" in cert_one and b"PRIVATE KEY" in key_one
    assert (tmp_path / "ca.crt").exists() and (tmp_path / "ca.key").exists()


def test_leaf_is_signed_by_the_ca_and_caches(tmp_path):
    load_or_create_ca(tmp_path)
    leaf = issue_leaf(tmp_path, "target.test")
    assert leaf.exists()
    assert issue_leaf(tmp_path, "target.test") == leaf

    from cryptography import x509

    chain = x509.load_pem_x509_certificates(leaf.read_bytes())
    ca = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
    assert len(chain) == 2  # leaf + CA chain, ready for load_cert_chain
    assert chain[0].issuer == ca.subject
    san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["target.test"]


def test_leaf_san_includes_loopback_ip(tmp_path):
    load_or_create_ca(tmp_path)
    leaf = issue_leaf(tmp_path, "127.0.0.1")

    from cryptography import x509

    chain = x509.load_pem_x509_certificates(leaf.read_bytes())
    san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert [str(address) for address in san.value.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]


# ---------------------------------------------------------------------------
# proxy TLS interception (real handshake loopback, nothing leaves the machine)
# ---------------------------------------------------------------------------


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        body = b"<html><body>origin served over TLS</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


@pytest.fixture
def tls_origin(tmp_path):
    """An HTTPS origin whose certificate no proxy would trust - by design."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_file, key_file = tmp_path / "origin.crt", tmp_path / "origin.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_file), str(key_file))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _proxy_connect(proxy_port: int, origin_port: int, ca_dir: Path) -> ssl.SSLSocket:
    """Do CONNECT against the proxy, then TLS with the proxy CA trusted."""
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    raw.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % origin_port)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = raw.recv(4096)
        if not chunk:
            break
        response += chunk
    assert b"200" in response.split(b"\r\n", 1)[0], response

    ctx = ssl.create_default_context()
    ctx.load_verify_locations(str(ca_dir / "ca.crt"))  # the proxy CA, trusted on purpose
    return ctx.wrap_socket(raw, server_hostname="127.0.0.1")


def test_tls_intercept_logs_decrypted_requests(tmp_path, tls_origin):
    proxy_port = _free_port()
    db_path = tmp_path / "sitemap.db"
    server = ProxyServer(
        host="127.0.0.1", port=proxy_port, db_path=str(db_path),
        tls_intercept=True, ca_dir=str(tmp_path / "ca"),
    )
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    try:
        client_tls = _proxy_connect(proxy_port, tls_origin, tmp_path / "ca")
        client_tls.sendall(
            b"GET /account/settings HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n"
        )
        response = b""
        while True:
            chunk = client_tls.recv(4096)
            if not chunk:
                break
            response += chunk
        client_tls.close()

        assert b"200" in response.split(b"\r\n", 1)[0]
        assert b"origin served over TLS" in response

        rows = sqlite3.connect(str(db_path)).execute(
            "SELECT method, url, status FROM sitemap WHERE method = 'GET'"
        ).fetchall()
        match = [row for row in rows if row[1] == f"https://127.0.0.1:{tls_origin}/account/settings" and row[2] == 200]
        assert match, rows  # the decrypted inner request landed in the site map
    finally:
        server.stop()


def test_plain_connect_still_passes_through_when_interception_off(tmp_path, tls_origin):
    """Default mode must stay a pass-through: no CA, no decryption."""
    proxy_port = _free_port()
    server = ProxyServer(host="127.0.0.1", port=proxy_port, db_path=str(tmp_path / "map.db"))
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    try:
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
        raw.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % tls_origin)
        response = b""
        while b"\r\n\r\n" not in response:
            response += raw.recv(4096)
        assert b"200" in response.split(b"\r\n", 1)[0]

        # client speaks TLS straight to the origin - the proxy never sees plaintext
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the origin's own cert, trusted here for the test
        tls = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        tls.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        assert b"origin served over TLS" in data
        assert not (tmp_path / "ca").exists()
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# scan scheduling
# ---------------------------------------------------------------------------


def test_schedule_runs_rounds_and_diffs(tmp_path, cache_target):
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parent.parent
    command = [
        sys.executable, "-m", "summit", "schedule", cache_target,
        "--every", "0.5", "--times", "2", "--out-dir", str(tmp_path / "history"),
        "--",
        "--no-templates", "--skip-linkcheck", "--no-active", "--depth", "1", "--max-pages", "2",
    ]
    result = subprocess.run(command, cwd=repo_root, capture_output=True, text=True, timeout=90)

    assert result.returncode == 0, result.stdout + result.stderr
    history = sorted((tmp_path / "history").glob("scan-*.json"))
    assert len(history) == 2  # one report per round, ready for `summit diff`
    assert "[round 1/2]" in result.stdout and "[round 2/2]" in result.stdout
    # the second round diffs against the first with the shared dedup key
    assert "new 0, resolved 0, regressed 0" in result.stdout


# ---------------------------------------------------------------------------
# web cache deception
# ---------------------------------------------------------------------------


class _CacheHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        split_path = self.path.split("?")[0]
        if split_path == "/account" or split_path.startswith("/account/"):
            body = b"<html><body><h1>Account</h1><p>Private settings page.</p></body></html>"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=demo-session; Path=/")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif split_path == "/strict":
            body = b"<html><body><h1>Account</h1><p>Private settings page.</p></body></html>"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=demo-session; Path=/")
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif split_path == "/other":
            body = b"<html><body><h1>Public marketing page.</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        return


@pytest.fixture
def cache_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CacheHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _get(client: HttpClient, url: str):
    return client.send(HttpRequest(method="GET", url=url))


def test_cache_deception_flags_suffix_tolerant_session_page(cache_target):
    client = HttpClient(timeout=3)
    original = _get(client, f"{cache_target}/account")
    findings = run_cache_deception(client, [original])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "cache-deception"
    assert finding.confidence == "needs-manual"
    # the severity cap: needs-manual findings can never pose as medium
    assert finding.severity == "low"
    assert "/account/summit-wcd-session.js" in finding.url


def test_cache_deception_quiet_on_uncacheable_response(cache_target):
    client = HttpClient(timeout=3)
    original = _get(client, f"{cache_target}/strict")
    assert run_cache_deception(client, [original]) == []


def test_cache_deception_quiet_without_session(cache_target):
    # /other carries no Set-Cookie -> not even probed
    client = HttpClient(timeout=3)
    original = _get(client, f"{cache_target}/other")
    assert run_cache_deception(client, [original]) == []


def test_cache_deception_quiet_when_suffix_changes_the_response(cache_target):
    # a router that answers the suffix with different content: no deception
    client = HttpClient(timeout=3)
    original = _get(client, f"{cache_target}/account")
    from summit.http.models import HttpRequest as Req, HttpResponse

    forged = HttpResponse(
        status=200,
        headers=original.headers,
        body=b"<html><body>totally different content</body></html>",
        request=Req(method="GET", url=original.request.url),
        set_cookies=original.set_cookies,
    )
    assert run_cache_deception(client, [forged]) == []


def test_cache_deception_finding_documented():
    from summit.scan.core import cwe_for, impact_for

    assert cwe_for("cache-deception") == "CWE-441"
    assert "cache" in impact_for("cache-deception").lower()
