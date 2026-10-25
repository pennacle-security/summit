"""Resource takeover fingerprints.

When a target serves a provider's "this resource does not exist" page,
the underlying resource (bucket, site, distribution) may be unclaimed.
Whoever registers it next inherits the URL. This module fingerprints the
classic providers from the response body alone - no DNS tricks, no
active claiming, ever. A finding here means "reclaim or remove", not
"we took it over".
"""

from __future__ import annotations

from .http.models import HttpResponse
from .scan.core import Finding

# (service, body marker) - markers are matched lowercase against the first
# 20 KB. Each one is the provider's own unclaimed-resource page.
TAKEOVER_SIGNATURES: list[tuple[str, str]] = [
    ("AWS S3", "nosuchbucket"),
    ("GitHub Pages", "there isn't a github pages site here"),
    ("Heroku", "no such app"),
    ("Azure", "404 web site not found"),
    ("Shopify", "sorry, this shop is currently unavailable"),
    ("Fastly", "fastly error: unknown domain"),
    ("Pantheon", "the gods are wise, but do not know of the site which you seek"),
    ("Tumblr", "doesn't currently exist at this address"),
    ("Surge.sh", "project not found"),
    ("Bitbucket", "repository not found"),
    ("Webflow", "the page you are looking for doesn&#x27;t exist or has been moved"),
]

_MAX_BODY = 20_000


def fingerprint_takeover(body: str) -> tuple[str, str] | None:
    """Return (service, marker) when the body matches an unclaimed-resource page."""
    lowered = body[:_MAX_BODY].lower()
    for service, marker in TAKEOVER_SIGNATURES:
        if marker in lowered:
            return service, marker
    return None


def check_takeover(response: HttpResponse) -> list[Finding]:
    if response.status not in (404, 410):
        return []
    detected = fingerprint_takeover(response.text)
    if not detected:
        return []
    service, marker = detected
    return [
        Finding(
            check_id="takeover-signature",
            title=f"Possible {service} resource takeover",
            severity="high",
            url=response.request.url,
            confidence="confirmed",
            detail=(
                f"The target answers HTTP {response.status} with {service}'s unclaimed-resource "
                "page. If the underlying resource is really unregistered, claiming it hands "
                "this URL - and everything that still points at it - to the next person."
            ),
            evidence=f"{service}: {marker!r}",
            remediation=f"Reclaim or rebind the {service} resource, or remove whatever still points at it.",
        )
    ]
