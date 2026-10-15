import ipaddress

from summit.scan.engine import _is_probe_worthy
from summit.scan.linkcheck import _is_sensitive_ip, parking_match


# --- sensitive IP guard (SSRF protection) ---

def test_private_ipv4_flagged():
    assert _is_sensitive_ip(ipaddress.ip_address("10.0.0.5"))
    assert _is_sensitive_ip(ipaddress.ip_address("192.168.1.1"))
    assert _is_sensitive_ip(ipaddress.ip_address("172.16.0.9"))


def test_loopback_and_link_local_flagged():
    assert _is_sensitive_ip(ipaddress.ip_address("127.0.0.1"))
    assert _is_sensitive_ip(ipaddress.ip_address("169.254.169.254"))  # cloud metadata
    assert _is_sensitive_ip(ipaddress.ip_address("::1"))


def test_public_ips_not_flagged():
    assert not _is_sensitive_ip(ipaddress.ip_address("93.184.216.34"))
    assert not _is_sensitive_ip(ipaddress.ip_address("140.82.121.4"))
    assert not _is_sensitive_ip(ipaddress.ip_address("2606:4700::6810:85e5"))


# --- parking page fingerprints ---

def test_parking_signature_detected():
    assert parking_match("Welcome! This domain is parked. Contact us.") == "this domain is parked"
    assert parking_match("<title>Buy this domain</title>") == "buy this domain"
    assert parking_match("redirect: sedoparking.com") == "sedoparking"


def test_normal_page_not_flagged():
    assert parking_match("<html><body>hello world blog post about domains</body></html>") is None
    assert parking_match("") is None


def test_godaddy_parked_page_detected():
    assert parking_match("This page is parked free, courtesy of GoDaddy.") == "this page is parked free, courtesy of godaddy"


def test_godaddy_customer_site_not_flagged():
    assert parking_match("Hosted with GoDaddy - visit godaddy.com for support") is None


# --- smart parameter targeting ---

def test_tracker_params_skipped():
    assert not _is_probe_worthy("utm_source", "newsletter")
    assert not _is_probe_worthy("fbclid", "IwAR123")
    assert not _is_probe_worthy("gclid", "EAIaIQob")


def test_opaque_token_values_skipped():
    assert not _is_probe_worthy("state", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0")


def test_normal_params_kept():
    assert _is_probe_worthy("q", "search term")
    assert _is_probe_worthy("id", "3")
    assert _is_probe_worthy("url", "https://example.com/page")
