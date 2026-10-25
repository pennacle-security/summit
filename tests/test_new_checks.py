import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from summit.http.client import HttpClient
from summit.http.models import HttpRequest, HttpResponse
from summit.scan.core import InjectionPoint
from summit.scan.modules.cors_reflect import CorsReflectionCheck
from summit.scan.modules.host_header import HostHeaderInjectionCheck
from summit.takeover import check_takeover, fingerprint_takeover


def make_response(body, status=200, headers=None):
    return HttpResponse(
        status=status,
        headers=headers or {},
        body=body if isinstance(body, bytes) else body.encode(),
        request=HttpRequest(method="GET", url="http://test.local/"),
    )


# --- takeover fingerprints (pure, offline) ---

def test_s3_nosuchbucket_on_404_detected():
    body = '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>'
    findings = check_takeover(make_response(body, status=404))
    assert len(findings) == 1
    assert "AWS S3" in findings[0].title
    assert findings[0].confidence == "confirmed"


def test_takeover_not_reported_on_200():
    body = '<Error><Code>NoSuchBucket</Code></Error>'  # even with the marker
    assert check_takeover(make_response(body, status=200)) == []


def test_plain_404_not_flagged():
    assert check_takeover(make_response(b"<html>not found</html>", status=404)) == []


def test_fingerprint_helper():
    assert fingerprint_takeover("Heroku | No such app for this dyno") == ("Heroku", "no such app")
    assert fingerprint_takeover("everything is fine") is None


def test_webflow_takeover_detected():
    body = "<html>Oops. The page you are looking for doesn&#x27;t exist or has been moved.</html>"
    findings = check_takeover(make_response(body, status=404))
    assert len(findings) == 1
    assert "Webflow" in findings[0].title


def test_webflow_marker_on_200_is_not_takeover():
    body = "The page you are looking for doesn&#x27;t exist or has been moved."
    assert check_takeover(make_response(body, status=200)) == []


# --- Host header injection + CORS reflection (live mini servers) ---

class EchoHostHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "localhost")
        body = f"<html><body>reset link: http://{host}/reset?token=abc</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CorsEchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        origin = self.headers.get("Origin", "")
        body = b'{"ok":true}'
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def test_host_header_injection_detected_live():
    server, port = start_server(EchoHostHandler)
    try:
        client = HttpClient()
        request = HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/reset?user=demo")
        point = InjectionPoint(request=request, param="user", original_value="demo")
        findings = HostHeaderInjectionCheck().run(point, client)
        assert len(findings) == 1
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


def test_host_header_check_quiet_without_reflection():
    server, port = start_server(CorsEchoHandler)  # does not echo Host
    try:
        client = HttpClient()
        request = HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/api?user=1")
        point = InjectionPoint(request=request, param="user", original_value="1")
        assert HostHeaderInjectionCheck().run(point, client) == []
    finally:
        server.shutdown()


def test_cors_reflection_detected_live():
    server, port = start_server(CorsEchoHandler)
    try:
        client = HttpClient()
        request = HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/api?user=1")
        point = InjectionPoint(request=request, param="user", original_value="1")
        findings = CorsReflectionCheck().run(point, client)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


def test_cors_check_quiet_without_reflection():
    server, port = start_server(EchoHostHandler)  # no CORS headers at all
    try:
        client = HttpClient()
        request = HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/reset?user=demo")
        point = InjectionPoint(request=request, param="user", original_value="demo")
        assert CorsReflectionCheck().run(point, client) == []
    finally:
        server.shutdown()
