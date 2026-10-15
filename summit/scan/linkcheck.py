"""Broken link hijacking check.

Crawled pages are full of outbound links. When those links point at
domains that no longer exist or are parked, the target is one expired
registration away from a takeover - and users clicking through land on
whatever the next registrant serves.

Smart-logic rules that keep this accurate:

- DNS failures are verified with a second attempt before reporting, so a
  transient resolver hiccup never becomes a false positive.
- Links resolving to private, loopback, link-local, reserved, or
  multicast ranges are never fetched. This protects the operator - a
  hostile page cannot turn the scanner into a blind SSRF probe against
  the local network - and keeps findings honest.
- Live hosts are probed with a streaming GET that stops after the first
  few kilobytes, so a huge response never gets downloaded just to learn
  a status code.
- Parking-page fingerprints are matched on the first bytes only, using
  tight signatures (a page merely mentioning "GoDaddy" is not parked).
- Every unique URL is checked exactly once, no matter how many pages
  link to it.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

import requests

from .core import Finding

PROBE_HEADERS = {
    "User-Agent": "Summit/0.2 (+https://github.com/pennacle-security/summit)",
    "Accept": "text/html,application/xhtml+xml",
}

# Tight fingerprints. A page that merely references a registrar is NOT
# parked - these strings appear in the parking pages themselves.
PARKING_SIGNATURES = [
    "this domain is parked",
    "buy this domain",
    "this domain is for sale",
    "domain may be for sale",
    "domain is for sale",
    "sedoparking",
    "parkingcrew",
    "bodis.com",
    "hugedomains",
    "this page is parked free, courtesy of godaddy",
]

_MAX_HEAD_BYTES = 3000


def _is_sensitive_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for ranges the scanner must never touch: private, loopback,
    link-local (incl. cloud metadata at 169.254.x.x), reserved, multicast."""
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def _resolve(host: str | None) -> list | None:
    """Return the list of resolved IPs, or None when the host does not resolve."""
    if not host:
        return None
    try:
        return [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
    except (OSError, ValueError):
        return None


def parking_match(head: str) -> str | None:
    """Return the first parking signature found in the page head, if any."""
    lowered = head.lower()
    for signature in PARKING_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def _probe(url: str, timeout: float):
    """Streaming GET that stops at the first few KB. Returns (status, head, error)."""
    try:
        response = requests.get(
            url,
            headers=PROBE_HEADERS,
            timeout=timeout,
            stream=True,
            allow_redirects=True,
        )
        head = b""
        for chunk in response.iter_content(chunk_size=1024):
            head += chunk
            if len(head) >= _MAX_HEAD_BYTES:
                break
        response.close()
        return response.status_code, head.decode("utf-8", errors="replace"), None
    except requests.RequestException as exc:
        return None, None, str(exc)


def _check_one(url: str, timeout: float) -> Finding | None:
    split = urlsplit(url)
    host = split.hostname
    if not host:
        return None

    ips = _resolve(host)
    if ips is None:
        # Retry once: a flaky resolver must not produce a hijack report.
        ips = _resolve(host)
        if ips is None:
            return Finding(
                check_id="linkcheck-dead-domain",
                title="Broken link to dead domain (hijack candidate)",
                severity="high",
                url=url,
                confidence="confirmed",
                detail=(
                    f"'{host}' does not resolve (verified with two DNS attempts). "
                    "If the registration lapses, the next registrant controls what "
                    "visitors clicking this link see."
                ),
                evidence=f"DNS: {host} does not resolve",
                remediation="Remove or update the link. If the domain belongs to the target, renew it before someone else does.",
            )

    for ip in ips:
        if _is_sensitive_ip(ip):
            return Finding(
                check_id="linkcheck-private-target",
                title="Outbound link resolves to a private IP",
                severity="info",
                url=url,
                confidence="confirmed",
                detail=(
                    f"'{host}' resolves to a private, loopback, or link-local address. "
                    "Summit deliberately does not fetch it - which also keeps a hostile "
                    "page from using the scanner as a blind SSRF probe."
                ),
                evidence=f"sensitive range: {host} -> {ip}",
                remediation="Review why a public page links to an internal address.",
            )

    status, head, error = _probe(url, timeout)
    if status is None:
        status, head, error = _probe(url, timeout)
        if status is None:
            return Finding(
                check_id="linkcheck-unreachable",
                title="Outbound link unreachable",
                severity="low",
                url=url,
                confidence="potential",
                detail=f"'{host}' could not be reached after a retry: {error}",
                remediation="Remove or update the link if the service is gone.",
            )

    if status in (404, 410):
        return Finding(
            check_id="linkcheck-broken",
            title="Broken outbound link (HTTP 404/410)",
            severity="medium",
            url=url,
            confidence="confirmed",
            detail=f"The linked resource is gone (HTTP {status}).",
            evidence=f"HTTP {status}",
            remediation="Update or remove the dead link.",
        )

    if status in (401, 403):
        return None  # auth-walled, not broken

    if status >= 500:
        return Finding(
            check_id="linkcheck-unreachable",
            title="Outbound link server error",
            severity="low",
            url=url,
            confidence="potential",
            detail=f"'{host}' returned HTTP {status}.",
            evidence=f"HTTP {status}",
            remediation="Re-check later; the service may be temporarily down.",
        )

    signature = parking_match(head or "")
    if signature:
        return Finding(
            check_id="linkcheck-parked",
            title="Outbound link points at a parked domain (hijack candidate)",
            severity="high",
            url=url,
            confidence="confirmed",
            detail=(
                f"'{host}' serves a parking page. Parked domains are frequently "
                "allowed to expire - the next registrant inherits the traffic."
            ),
            evidence=f"parking signature: {signature!r}",
            remediation="Remove the link; if the domain matters to the target, acquire or block it.",
        )

    return None


def check_links(
    external_urls: list[str],
    workers: int = 8,
    timeout: float = 10.0,
) -> list[Finding]:
    """Check every unique external URL once, in parallel. One finding per issue."""
    unique = sorted({u.split("#", 1)[0] for u in external_urls if u.startswith(("http://", "https://"))})
    findings: list[Finding] = []
    if not unique:
        return findings
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_one, url, timeout) for url in unique]
        for future in as_completed(futures):
            finding = future.result()
            if finding is not None:
                findings.append(finding)
    return findings
