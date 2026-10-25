from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode

from ..http.client import HttpClient
from ..http.models import HttpRequest

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

CONFIDENCE_LEVELS = ("confirmed", "likely", "needs-manual", "info")
_CONFIDENCE_RANK = {name: index for index, name in enumerate(CONFIDENCE_LEVELS)}

_CONFIDENCE_SEVERITY_CAP = {
    "confirmed": "critical",
    "likely": "medium",
    "needs-manual": "low",
    "info": "info",
}


def cap_severity(severity: str, confidence: str) -> str:
    """Cap severity based on confidence. Unverified findings can never be
    CRITICAL or HIGH."""
    cap = _CONFIDENCE_SEVERITY_CAP.get(confidence, "info")
    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(cap, 0):
        return cap
    return severity


def min_severity(severity: str) -> str:
    """Smallest severity name whose rank covers `severity` (for --min-severity)."""
    return severity if severity in SEVERITY_RANK else "info"


def filter_by_severities(findings: list["Finding"], allowed: set[str]) -> list["Finding"]:
    return [f for f in findings if f.severity in allowed]


def filter_by_min_severity(findings: list["Finding"], minimum: str) -> list["Finding"]:
    floor = SEVERITY_RANK.get(minimum, 0)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= floor]

# Central CWE mapping: every check_id gets its CWE so findings are
# referenceable without each module repeating the constant.
CWE_BY_CHECK_ID = {
    "passive-security-headers": "CWE-693",
    "passive-cookie-flags": "CWE-614",
    "passive-error-disclosure": "CWE-209",
    "passive-info-disclosure": "CWE-200",
    "passive-cors": "CWE-942",
    "passive-email-leak": "CWE-359",
    "waf-detected": "CWE-693",
    "captcha-challenge": "CWE-807",
    "takeover-signature": "CWE-350",
    "sqli-error": "CWE-89",
    "sqli-boolean": "CWE-89",
    "xss-reflection": "CWE-79",
    "xss-reflection-hardened": "CWE-79",
    "waf-bypass": "CWE-693",
    "host-header-injection": "CWE-640",
    "cors-reflection": "CWE-942",
    "open-redirect": "CWE-601",
    "path-traversal": "CWE-22",
    "authorize-bypass": "CWE-639",
    "authorize-partial": "CWE-639",
    "paramminer-reflected": "CWE-200",
    "paramminer-behavior": "CWE-200",
    "fuzz-dir": "CWE-538",
    "fuzz-divergence": "CWE-200",
    "linkcheck-dead-domain": "CWE-350",
    "linkcheck-parked": "CWE-350",
    "linkcheck-broken": "CWE-350",
    "linkcheck-unreachable": "CWE-350",
    "linkcheck-private-target": "CWE-918",
    "os-command-injection": "CWE-78",
    "ssti": "CWE-1336",
    "crlf-injection": "CWE-113",
    "sensitive-file": "CWE-538",
    "cve-detected": "CWE-1104",
    "tls-legacy-versions": "CWE-326",
    "tls-cert-self-signed": "CWE-295",
    "tls-cert-expiring": "CWE-295",
    "tls-cert-expired": "CWE-295",
    "subdomain-takeover": "CWE-350",
    "hpp": "CWE-235",
    "sqli-time": "CWE-89",
    "graphql-introspection": "CWE-200",
    "graphql-field-suggestions": "CWE-200",
    "email-enumeration": "CWE-204",
    "directory-listing": "CWE-548",
    "cache-deception": "CWE-441",
    "cacheable-sensitive": "CWE-524",
    "headers-grade": "CWE-693",
    "csrf-missing": "CWE-352",
    "nosql-injection": "CWE-943",
    "ldap-injection": "CWE-90",
    "format-string": "CWE-134",
    "race-condition": "CWE-362",
    "jwt-security": "CWE-347",
    "jwt-alg-none-attack": "CWE-347",
    "session-fixation": "CWE-384",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "js-secret": "CWE-798",
    "dom-xss": "CWE-79",
    "trace-enabled": "CWE-693",
    "http-methods-advertised": "CWE-650",
    "xpath-injection": "CWE-643",
    "ssi-injection": "CWE-96",
    "log4shell": "CWE-917",
    "shellshock": "CWE-78",
    "xxe-oob": "CWE-611",
}

# Security impact per check: what an attacker concretely achieves, not
# a textbook definition. Shown in every report next to the finding.
IMPACT_BY_CHECK_ID = {
    "passive-security-headers": "Browsers miss out on built-in protections - clickjacking, MIME sniffing and downgrade attacks become possible.",
    "passive-cookie-flags": "Session cookies can be stolen via plain HTTP or read by XSS payloads.",
    "passive-error-disclosure": "Attackers learn the exact database engine, table structure "
    "and framework version - turning blind guesses into targeted exploits.",
    "passive-info-disclosure": "Attackers skip fingerprinting and go straight to version-specific exploits.",
    "passive-cors": "Third-party websites may read authenticated responses from your users' browsers.",
    "passive-email-leak": "Employee emails feed phishing campaigns and credential-stuffing lists.",
    "waf-detected": "The attacker knows which bypass techniques to try.",
    "captcha-challenge": "The endpoint is hardened against automation - manual testing required.",
    "takeover-signature": "The next person to register that resource controls what your visitors see.",
    "sqli-error": "Full database access: read, modify or destroy every record the application account can reach.",
    "sqli-boolean": "Blind data extraction - one character per request, but the entire database is readable.",
    "sqli-time": "Blind data extraction without visible error output - slower but equally complete.",
    "xss-reflection": "Attacker-run JavaScript in your users' browsers: session theft, credential phishing, full page takeover.",
    "xss-reflection-hardened": "The output encoding is holding - keep it through framework upgrades.",
    "waf-bypass": "The WAF protection layer can be walked past - every payload behind it reaches the application.",
    "os-command-injection": "Operating-system command execution on the server: full system compromise.",
    "ssti": "Template engine code execution: file read/write, remote code execution depending on the engine.",
    "crlf-injection": "Response splitting: cache poisoning, session fixation, and XSS via injected headers.",
    "host-header-injection": "Password-reset emails with attacker-controlled links - account takeover via email interception.",
    "cors-reflection": "Any website can read authenticated responses from your users' browsers.",
    "open-redirect": "Phishing links that carry your domain - users trust the URL bar.",
    "path-traversal": "Arbitrary file read on the server: source code, configuration files, credentials.",
    "email-enumeration": "Attackers confirm which email addresses have accounts - targeted phishing and credential stuffing.",
    "directory-listing": "Every file in the directory is visible and downloadable to anyone.",
    "cache-deception": "The victim's authenticated response is stored in a shared cache under a URL "
    "anyone can fetch - their private page becomes public.",
    "cacheable-sensitive": "Credentials retained in browser and proxy caches - readable by the next user of the machine.",
    "headers-grade": "Summary of browser-side protection coverage.",
    "csrf-missing": "Other websites can submit this form as your logged-in users.",
    "authorize-bypass": "Low-privilege users access admin data and functions - full horizontal and vertical privilege escalation.",
    "authorize-partial": "Response differences between roles may leak privileged data.",
    "paramminer-reflected": "An undocumented parameter that reflects input - a new injection surface nobody was testing.",
    "paramminer-behavior": "An undocumented parameter that changes server behavior - attack surface nobody knew about.",
    "linkcheck-dead-domain": "Whoever registers the dead domain controls the page your users click through to.",
    "linkcheck-parked": "A parked domain your users click through to - one expiry away from hijack.",
    "linkcheck-broken": "Dead links damage user trust and SEO; they also signal unmaintained surface.",
    "linkcheck-unreachable": "The linked service may be permanently gone.",
    "linkcheck-private-target": "Internal services are referenced from public pages - internal network mapping for free.",
    "sensitive-file": "Credentials and configuration readable by anyone with the URL.",
    "cve-detected": "A known, published vulnerability applies to this version - public exploits may exist.",
    "tls-legacy-versions": "Known protocol weaknesses - fails modern compliance scans.",
    "tls-cert-self-signed": "No third-party identity guarantee for visitors.",
    "tls-cert-expiring": "Certificate automation is broken - the site will go down.",
    "tls-cert-expired": "Visitors see browser warnings, many clients refuse the connection.",
    "subdomain-takeover": "Full control of the subdomain - serving arbitrary content on a trusted domain.",
    "session-fixation": "Attacker pre-sets the session ID and hijacks the authenticated session.",
    "race-condition": "Concurrent requests bypass state checks - double-spending, over-withdrawing.",
    "nosql-injection": "NoSQL operators bypass authentication and extract the entire database.",
    "ldap-injection": "LDAP filters manipulated to reveal directory entries.",
    "jwt-security": "Forged JWT claims grant admin access without knowing the secret.",
    "jwt-alg-none-attack": "Arbitrary admin tokens forged - full authentication bypass.",
    "hpp": "WAF validation bypassed via parameter duplication.",
    "graphql-introspection": "Complete schema map exposed - every type, field, and mutation visible.",
    "graphql-field-suggestions": "Schema names leak one suggestion at a time - the full API surface can be enumerated even with introspection off.",
    "fuzz-dir": "Undocumented paths and files discovered - expands the attack surface map.",
    "fuzz-divergence": "A payload changed the application's behavior - hidden endpoints, debug flags and "
    "privilege boundaries often show up exactly like this.",
    "format-string": "Stack memory read or written - information leak leading to full exploitation.",
    "ssrf": "The server itself fetches attacker-chosen URLs - internal services, cloud metadata and localhost become reachable from outside.",
    "xxe": "Arbitrary file read on the server via the XML parser; escalates to SSRF and denial of service on unhardened parsers.",
    "js-secret": "Credentials readable by anyone who loads the page - billing abuse, data access and account takeover until rotated.",
    "dom-xss": "Client-side script execution controlled through the URL - session theft and page takeover without a server reflection.",
    "trace-enabled": "TRACE reflects requests verbatim - re-exposing cookies to cross-site scripting on legacy clients.",
    "http-methods-advertised": "Write methods exposed to unauthenticated callers are a direct path to data tampering.",
    "xpath-injection": "The XML document behind the query is readable - user records, credentials and business rules included.",
    "ssi-injection": "Arbitrary commands run on the web server as its OS user - full host compromise.",
    "log4shell": "JNDI lookups load attacker-controlled code - textbook remote code execution.",
    "shellshock": "A crafted header executes shell commands on the server - full host compromise.",
    "xxe-oob": "Blind external-entity resolution: internal files and services reachable from the server side.",
}


def cwe_for(check_id: str) -> str:
    return CWE_BY_CHECK_ID.get(check_id, "")


def impact_for(check_id: str) -> str:
    return IMPACT_BY_CHECK_ID.get(check_id, "")


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    url: str
    param: str = ""
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    # "confirmed" = observed fact. "likely" = strong signal, not proven.
    # "needs-manual" = heuristic only. "info" = informational.
    confidence: str = "needs-manual"
    # CWE identifier, resolved from check_id when the module does not set it.
    cwe: str = ""
    # CVE identifiers detected for this finding (e.g. from version banners).
    cves: list[str] = field(default_factory=list)
    # Security impact: what an attacker concretely achieves.
    impact: str = ""
    # A reproducible curl command or step-by-step verification procedure.
    poc: str = ""
    # Human-readable steps to verify this finding manually.
    verification_steps: str = ""
    # All affected URLs (for deduplicated findings).
    affected_urls: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.severity = cap_severity(self.severity, self.confidence)

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "param": self.param,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "cwe": self.cwe or cwe_for(self.check_id),
            "cves": list(self.cves),
            "impact": self.impact or impact_for(self.check_id),
            "poc": self.poc,
            "verification_steps": self.verification_steps,
            "affected_urls": list(self.affected_urls),
        }


@dataclass
class InjectionPoint:
    request: HttpRequest
    param: str
    original_value: str
    location: str = "query"

    def with_value(self, value: str) -> HttpRequest:
        """Replace this parameter's value, wherever it lives.

        Query parameters use the URL, form bodies are re-encoded, and
        header locations swap the header. Every active check goes through
        this method so one payload set covers every injection surface.
        """
        if self.location == "body":
            raw = (self.request.body or b"").decode("utf-8", errors="replace")
            pairs = parse_qsl(raw, keep_blank_values=True)
            updated = [
                (key, value if key == self.param else original)
                for key, original in pairs
            ]
            if self.param not in {key for key, _ in pairs}:
                updated.append((self.param, value))
            headers = dict(self.request.headers)
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return HttpRequest(
                method=self.request.method,
                url=self.request.url,
                headers=headers,
                body=urlencode(updated).encode(),
            )
        if self.location == "header":
            return self.request.with_header(self.param, value)
        return self.request.with_query_param(self.param, value)


class Check:
    """Base class for active checks. Subclass and override ``run``."""

    check_id: str = "generic"
    title: str = "Generic check"
    severity: str = "medium"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        raise NotImplementedError
