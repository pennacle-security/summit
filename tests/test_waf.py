import base64
import ipaddress  # noqa: F401  (keeps the import list honest if helpers move)

from summit.captcha import detect_challenge
from summit.ratelimit import RateLimiter
from summit.smart import prioritize, score_point
from summit.toolkit import decode_text, encode_text, jwt_decode
from summit.updates import is_outdated
from summit.waf import detect_waf
from summit.http.models import HttpRequest, HttpResponse


def make_response(body=b"", headers=None):
    return HttpResponse(
        status=200,
        headers=headers or {},
        body=body,
        request=HttpRequest(method="GET", url="http://test.local/"),
    )


# --- WAF fingerprinting ---

def test_cloudflare_detected_by_header():
    detected = detect_waf(make_response(headers={"cf-ray": "abc", "server": "cloudflare"}))
    assert detected is not None and detected[0] == "Cloudflare"


def test_modsecurity_detected_by_server_string():
    detected = detect_waf(make_response(headers={"Server": "DemoShop/1.0 Mod_Security/2.9"}))
    assert detected is not None and detected[0] == "ModSecurity"


def test_incapsula_detected_by_body():
    detected = detect_waf(make_response(b"Request unsuccessful. Incapsula incident ID."))
    assert detected is not None and detected[0] == "Imperva Incapsula"


def test_plain_page_no_waf():
    assert detect_waf(make_response(b"<html>normal blog about firewalls</html>")) is None


def test_sitelock_detected_by_header():
    detected = detect_waf(make_response(headers={"x-sitelock-id": "abc123"}))
    assert detected is not None and detected[0] == "SiteLock"


def test_normal_page_not_flagged_as_sitelock():
    assert detect_waf(make_response(b"we use sitelock at work")) is None


# --- CAPTCHA / challenge detection ---

def test_recaptcha_detected():
    detected = detect_challenge(make_response(b'<script src="https://www.google.com/recaptcha/api.js"></script>'))
    assert detected is not None and detected[0] == "reCAPTCHA"


def test_hcaptcha_detected():
    detected = detect_challenge(make_response(b'<script src="https://hcaptcha.com/1/api.js"></script>'))
    assert detected is not None and detected[0] == "hCaptcha"


def test_no_challenge_on_plain_page():
    assert detect_challenge(make_response(b"<html><body>hi</body></html>")) is None


# --- rate limiter (injected clock, no real sleeping) ---

def test_rate_limiter_paces_requests():
    now = {"t": 100.0}
    sleeps: list[float] = []
    def sleeper(seconds: float) -> None:
        sleeps.append(seconds)
        now["t"] += seconds
    limiter = RateLimiter(0.1, clock=lambda: now["t"], sleeper=sleeper)
    limiter.wait()  # first request starts immediately - the slot opens at "now"
    limiter.wait()
    limiter.wait()
    assert len(sleeps) == 2
    assert all(abs(seconds - 0.1) < 1e-6 for seconds in sleeps)


def test_rate_limiter_zero_interval_never_sleeps():
    sleeps: list[float] = []
    limiter = RateLimiter(0.0, clock=lambda: 0.0, sleeper=sleeps.append)
    limiter.wait()
    limiter.wait()
    assert sleeps == []


# --- smart prioritizer ---

def test_named_param_scores_higher_than_unknown():
    request = HttpRequest(method="GET", url="http://x.local/?id=1&zzz=1")
    points = sorted([make_point("zzz", "1"), make_point("id", "1")], key=score_point, reverse=True)
    assert points[0].param == "id"
    assert score_point(make_point("url", "https://x")) == 3


def test_prioritize_orders_high_signal_first():
    points = [make_point("zzz", "abc"), make_point("file", "a.txt"), make_point("q", "term")]
    ordered = prioritize(points)
    assert ordered[0].param in {"file", "q"}  # both score 3
    assert ordered[-1].param == "zzz"


def make_point(name: str, value: str):
    return type("P", (), {"param": name, "original_value": value})()


# --- toolkit (Burp Decoder equivalents) ---

def test_b64_round_trip():
    assert decode_text(encode_text("summit <test>", "b64"), "b64") == "summit <test>"


def test_url_and_hex_round_trip():
    assert decode_text(encode_text("a&b=c", "url"), "url") == "a&b=c"
    assert decode_text(encode_text("ping", "hex"), "hex") == "ping"


def test_jwt_decode_shows_payload_and_honesty_note():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1","role":"admin"}').decode().rstrip("=")
    token = f"{header}.{payload}.c2ln"
    decoded = jwt_decode(token)
    assert '"role": "admin"' in decoded
    assert "NOT verified" in decoded


def test_jwt_decode_rejects_two_parts():
    try:
        jwt_decode("abc.def")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# --- update comparison ---

def test_version_comparison_is_numeric_not_lexicographic():
    assert is_outdated("0.3.0", "0.10.0")  # lexicographic would say 0.3 > 0.10
    assert is_outdated("0.3.0", "0.3.1")
    assert not is_outdated("1.0.0", "0.9.9")
    assert not is_outdated("0.3.0", "0.3.0")
