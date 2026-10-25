"""Web cache deception detection (CWE-441) - path-confusion differential.

Web cache deception tricks a shared cache into storing an authenticated
page under a URL an attacker can read: append a cacheable-looking suffix
(`/settings/anything.js`) and, if the application ignores the suffix
while the cache keys on it, the victim's private response becomes public
property on the next request.

Detection here is a differential probe, never a guess: the confused path
must answer with the same authenticated response (same status, matching
body prefix and size), the response must not opt out of caching, and the
original request must have carried a session cookie - without a session
there is nothing private to leak. Everything ships `needs-manual`,
because only a human with the application's cache topology in front of
them can confirm the stored entry is actually reachable third-party.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...http.client import HttpClient
from ...http.models import HttpRequest, HttpResponse
from ...scan.core import Finding
from ..runtime import deep

# Per-candidate probe cost is two requests; keep the scan polite.
MAX_CANDIDATES = 5
MAX_CANDIDATES_DEEP = 10

# Body similarity: same status, size within this many bytes, and a
# matching 128-byte prefix. Tight enough to require the real page,
# loose enough for embedded cache-buster echoes.
LENGTH_TOLERANCE = 128
PREFIX_BYTES = 128


def _cacheable(headers: dict[str, str]) -> bool:
    """A response is a deception candidate when it does not opt out of caching."""
    control = next(
        (value for key, value in headers.items() if key.lower() == "cache-control"),
        "",
    )
    lowered = control.lower()
    return not any(marker in lowered for marker in ("no-store", "private", "no-cache"))


def _similar(original: HttpResponse, confused: HttpResponse) -> bool:
    if confused.status != original.status:
        return False
    if abs(len(confused.body) - len(original.body)) > LENGTH_TOLERANCE:
        return False
    return confused.body[:PREFIX_BYTES] == original.body[:PREFIX_BYTES]


def run_cache_deception(client: HttpClient, pages: list[HttpResponse]) -> list[Finding]:
    """Probe session-bearing pages with a cacheable-looking path suffix.

    Only pages that answered with a Set-Cookie are candidates - an
    unauthenticated page has nothing private to cache-leak. Each candidate
    gets exactly one confused-path probe.
    """
    candidates = [page for page in pages if page.set_cookies][: (MAX_CANDIDATES_DEEP if deep() else MAX_CANDIDATES)]
    findings: list[Finding] = []
    for page in candidates:
        split = urlsplit(page.request.url)
        origin = f"{split.scheme}://{split.netloc}"
        base_path = split.path.rstrip("/") or "/"
        suffix = f"summit-wcd-{next(iter(page.set_cookies)).split('=')[0]}.js"
        confused_url = f"{origin}{base_path}/{suffix}"
        try:
            confused = client.send(HttpRequest(method="GET", url=confused_url))
        except Exception:
            continue
        if confused.status != 200 or not _similar(page, confused):
            continue
        if not _cacheable(confused.headers):
            continue
        control_header = next(
            (value for key, value in confused.headers.items() if key.lower() == "cache-control"),
            "",
        )
        findings.append(
            Finding(
                check_id="cache-deception",
                title=f"Web cache deception surface: {base_path}",
                severity="medium",
                url=confused_url,
                confidence="needs-manual",
                detail=(
                    "A cacheable-looking path suffix returns the same session-bearing response as "
                    "the original page. If a shared cache sits in front of the application and keys "
                    "on the full URL, the authenticated response is stored under an address anyone "
                    "can fetch. Confirm against the actual cache: request the confused URL from an "
                    "unauthenticated client and compare."
                ),
                evidence=(
                    f"GET {base_path}/{suffix} -> HTTP {confused.status} mirrors {base_path} "
                    f"({len(confused.body)}B vs {len(page.body)}B); "
                    f"Cache-Control: {control_header or 'not set (defaults apply)'}; "
                    "session cookie present"
                ),
                remediation=(
                    "Make the cache key on the session cookie (or mark session-bearing responses "
                    "private/no-store), and reject unknown path suffixes at the router."
                ),
                verification_steps=(
                    "1. Fetch the confused URL with a clean (cookie-less) browser or curl.\n"
                    "2. Compare the response with the authenticated page.\n"
                    "3. If it comes back identical from the cache, the deception is confirmed; "
                    "otherwise the cache topology does not leak here."
                ),
            )
        )
    return findings
