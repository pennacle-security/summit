<p align="center">
  <img src="docs/assets/banner.png" alt="summit" width="760">
</p>

<p align="center">
  <a href="https://github.com/pennacle-security/summit/actions/workflows/tests.yml"><img src="https://github.com/pennacle-security/summit/actions/workflows/tests.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/pennacle-security/summit/releases"><img src="https://img.shields.io/github/v/tag/pennacle-security/summit?label=release&color=2ea44f" alt="release"></a>
  <a href="https://pypi.org/project/summit-scanner/"><img src="https://img.shields.io/pypi/v/summit-scanner?label=pypi&color=306998" alt="PyPI"></a>
  <a href="https://www.bestpractices.dev/projects/15532"><img src="https://www.bestpractices.dev/projects/15532/badge" alt="CII Best Practices"></a>
  <a href="https://api.scorecard.dev/projects/github.com/pennacle-security/summit/badge"><img src="https://api.scorecard.dev/projects/github.com/pennacle-security/summit/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://pennacle-security.github.io/summit/"><img src="https://img.shields.io/badge/docs-live-2ea44f" alt="docs"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab" alt="python 3.10+">
  <img src="https://img.shields.io/github/license/pennacle-security/summit?color=8b949e" alt="MIT license">
  <img src="https://img.shields.io/badge/dependencies-3%20core%20%2B%201%20optional-8b949e" alt="dependencies">
</p>

<p align="center">One scriptable CLI for web security testing: scanner, TLS-intercepting proxy, fuzzer, authorization testing, WAF analysis, link-hijack detection, race conditions, scheduled monitoring and recon.<br>58+ checks across 11 families, 37 bundled YAML templates, Intruder-style payload fuzzing and a no-traffic attack-surface map. Free where the equivalents are paid - by <a href="https://github.com/pennacle-security">Pennacle Security</a>.</p>

---

We use Burp and ZAP every day. We also kept wanting three things they are not: a scanner we can script against in CI, findings that tell us how sure they are, and a codebase small enough to read in one sitting. Summit now has 58+ checks across 11 families, a one-command attack-surface map, payload fuzzing that speaks the Intruder file format, and a proxy that decrypts HTTPS with a CA it generates itself. Summit is that tool - v2.1.0, MIT, built in the open. Three core dependencies (`requests`, `pyyaml`, `packaging`) plus one optional (`cryptography`, only for TLS interception), all FLOSS, all standard.

**Full documentation:** [pennacle-security.github.io/summit](https://pennacle-security.github.io/summit/)

## Contents

1. [At a glance](#at-a-glance)
2. [Quick start](#quick-start)
3. [Proof, not promises](#proof-not-promises)
4. [Commands](#commands)
5. [Feature notes](#feature-notes)
6. [Anti false positives and false negatives](#anti-false-positives-and-false-negatives)
7. [Check catalog](#check-catalog)
8. [How summit compares](#how-summit-compares)
9. [Roadmap](#roadmap)
10. [Community and contributors](#community-and-contributors)
11. [Contributing and security](#contributing-and-security)
12. [Legal and license](#legal-and-license)

## At a glance

Capabilities that usually sit behind paid tooling, plus the scanning core:

| Capability | Summit | The usual route |
|---|---|---|
| Broken access control testing (BOLA/IDOR) | `summit authorize` | Autorize-style add-on / paid workflows |
| Hidden parameter discovery | `summit mine` | Param Miner-style add-on |
| OpenAPI-driven scanning | `summit scan --openapi` | add-ons |
| WAF fingerprinting + bypass probing | built in | partial / add-ons |
| Attack-surface mapping | `summit map` | add-ons / paid workflows |
| SQLi, XSS, redirect, traversal, takeover, host header, CORS | built in | core scanners (free) |
| Recon chain: subfinder -> httpx -> nmap | `summit recon` | manual gluing |
| Race condition detection | `summit race` | Burp Turbo Intruder (paid) |
| Intruder-style payload fuzzing | `summit fuzz --request` | paid (Intruder) |
| TLS-intercepting proxy | `summit proxy --tls-intercept` | paid core |
| Scheduled scans with per-round diffing | `summit schedule` | cron + glue scripts |
| TLS certificate audit | `summit tls` | manual / sslscan |
| Rate limiting, retries, JWT/encoder toolkit | built in | add-ons / paid |
| CI-ready, confidence-labelled, CWE/CVE-tagged findings | the whole point | paid automation |
| SARIF + JUnit XML output | built in | paid reporting |
| Pre-built binaries (linux/amd64, arm64, windows) | every release | N/A |

Every finding carries a confidence label - `confirmed` (an observed fact), `likely` (strong evidence), `needs-manual` (a heuristic for a human to check) or `info` - and the label caps severity, so a guess can never pose as critical. That distinction runs through the entire tool.

## Quick start

```bash
git clone https://github.com/pennacle-security/summit.git
cd summit
pip install -e .
```

Python 3.10+. Dependencies: `requests`, `pyyaml`, `packaging` - all FLOSS, all standard.

**Install from PyPI:**

```bash
pip install summit-scanner
```

**Or from source:**

```bash
git clone https://github.com/pennacle-security/summit.git
cd summit
pip install -e .
```

**Pre-built binaries** available on every [release](https://github.com/pennacle-security/summit/releases):
- `summit-linux-amd64` - Linux x86_64 (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- `summit-linux-arm64` - Linux ARM64 (AWS Graviton, Raspberry Pi 4+, Apple Silicon)
- `summit-windows-amd64.exe` - Windows 10+ / Windows Server 2019+

No Python installation required for binaries.

Then watch it work against a deliberately vulnerable local target:

```bash
python examples/vuln_app.py        # terminal 1 - the target (127.0.0.1 only)
summit map http://127.0.0.1:8765   # attack-surface map, no attack traffic
summit scan http://127.0.0.1:8765  # terminal 2 - the scan
```

A fuller pass on a real engagement looks like this:

```bash
summit recon target.com --json recon.json                 # subdomains -> hosts -> ports
summit scan https://target.com --depth 2 --rate 10        # crawl + all checks
summit scan --openapi api-spec.json                       # API: scan what the spec admits to
summit authorize https://target.com/admin?user=1 \
  --role 'admin=Cookie: session=abc' \
  --role 'user=Cookie: session=xyz'                       # BOLA/IDOR testing
```

## Proof, not promises

Every claim on this page is reproduced by [`examples/evidence.py`](examples/evidence.py) - it runs the demo target live, measures each feature, and prints PASS/FAIL with the real numbers. CI executes it on every push; a claim that stops holding fails the build.

<details>
<summary>Latest measured run (<code>python examples/evidence.py</code>)</summary>

```text
[PASS] full scan: 20 seeded check families detected, zero false positives
       154 findings in 7.1s (1095 requests), missing=none, control link flagged=no, 51 finding(s) carry confidence=confirmed
[PASS] resource takeover fingerprint detected on the target's own 404
       Possible AWS S3 resource takeover | AWS S3: 'nosuchbucket'
[PASS] host header injection: marker domain echoed back by the app
       Host: summit-host-probe.example -> reflected (reset-link poisoning surface)
[PASS] CORS reflects an arbitrary origin with credentials allowed
       ACAO: https://summit-cors-probe.example; ACAC: true
[PASS] WAF bypass: naive filter blocks, tampered payload lands decoded
       raw payload -> HTTP 403 (blocked); URL-encoded once -> HTTP 200, payload reflected decoded: True
[PASS] CAPTCHA challenge detected (reported, not solved)
       /login -> reCAPTCHA via marker 'recaptcha/api.js'
[PASS] rate limiting: --rate 5 paces 12 requests to ~2.2s; unlimited runs free
       12 requests at rate 5 -> 2.20s (theoretical floor: 2.2s); 12 requests unlimited -> 0.03s
[PASS] concurrency on a latency-bearing target: 8 workers vs serial (best of 3)
       40 requests x 25ms latency: serial 1.38s -> parallel 0.17s (7.9x speedup)
[PASS] smart prioritizer ranks known-injectable parameters first
       probing starts with: [('query', 'search?query=laptop'), ('id', 'user?id=1'), ('url', 'example.com')]
[PASS] toolkit decodes JWT header/payload and states the signature is unverified
       signature NOT verified - decoding only
[PASS] update check compares versions numerically (0.3 < 0.10)
       is_outdated('0.3.0', '0.10.0') -> True; is_outdated('1.0.0', '0.9.9') -> False
[PASS] broken access control: admin panel served identically to a low-privilege role
       verdict=broken; finding=Broken access control (BOLA/IDOR candidate)
[PASS] hidden parameter mining finds the undocumented debug parameter, zero noise
       1 finding(s): ['debug'] (all confirmed reflections)
[PASS] openapi-driven scan: spec alone leads the engine to seeded SQLi and XSS
       2 spec target(s) scanned -> 18 findings, sqli-error=yes, xss-reflection=yes
[PASS] OS command injection: marker executed and echoed by the server
       semicolon: exec marker x2, control marker x1 | CWE-78
[PASS] server-side template injection: {{7*7}} came back as 49
       Jinja2/Twig: {{7*7}} -> 49 | CWE-1336
[PASS] CRLF injection: X-Summit-CRLF header materialized in the response
       X-Summit-CRLF: injected | CWE-113
[PASS] sensitive file exposure: /.env confirmed by content signature
       content signature: 'APP_KEY=' | CWE-538
[PASS] CVE detection: Apache/2.4.49 banner maps to known CVEs
       detect_cves('Apache/2.4.49') -> ['CVE-2021-41773', 'CVE-2021-42013']
[PASS] time-based SQL injection: reproducible delay detected and calibrated
       MySQL: baseline 0.00s, probes 0.25s, 0.25s (threshold 0.2s)
[PASS] GraphQL introspection detected on a production-looking endpoint
       POST /graphql -> HTTP 200 with __schema payload | CWE-200
[PASS] frontend CVE detection: jQuery 3.4.1 + WordPress 5.7.1 map to known CVEs
       ['CVE-2020-11023', 'CVE-2021-29447'] (body signatures: CVE-2020-11023, CVE-2021-29447 (3.4.1, 5.7.1))
[PASS] SSRF confirmed out-of-band: the server fetched our callback URL
       OOB hit received for token ssrf20e95990eeac7203 after payload http://127.0.0.1:56202/ssrf20e95990eeac7203; callback log: 06:50:16  GET    /ssrf20e95990eeac7203  from 127.0.0.1  token=ssrf20e95990eeac7203; redirector control: silent
[PASS] XXE: external entity resolved, local file content returned
       file content signature in response: 'root:x:0:0:' | CWE-611
[PASS] TRACE enabled: probe marker header echoed back
       TRACE http://127.0.0.1:8777 echoed X-Summit-Trace: summit-trace-probe-9f3c2a | CWE-693
[PASS] hardcoded AWS key in the client bundle: reported likely, value redacted
       AWS access key: AKIA4Q…XK3P | CWE-798
[PASS] DOM XSS candidate: location.hash flows into innerHTML (needs manual)
       source→sink: location.hash → innerHTML | CWE-79
[PASS] intruder-style fuzzing: bogus codes diverge from the control (200 -> 404)
       control HTTP 200; payloads ['BOGUS1', 'BOGUS2'] -> [404, 404] (divergent); 2 needs-manual finding(s)
[PASS] GraphQL field suggestions leak schema names on an invalid field
       POST /graphql -> Cannot query field 'summitNoSuchFieldProbe' on type 'Query'. Did you mean 'summitSecretField' or 'summitAdminField'? | CWE-200
[PASS] markdown report renders every finding for triage documents
       154/154 finding section(s) rendered, severity summary table present
[PASS] TLS interception: HTTPS through the proxy is decrypted and logged in plaintext
       CONNECT tunnel -> TLS 1.3 via the proxy CA, GET / answered HTTP 200; site map row: ('GET', 'https://127.0.0.1:56206/', 200)
[PASS] web cache deception surface: session page answers under a cacheable .js path
       GET /account/summit-wcd-session.js -> HTTP 200 mirrors /account (129B vs 129B); Cache-Control: not set (defaults apply); session cookie present | CWE-441
[PASS] scan scheduling: rounds run on an interval and every round is diffed
       2 round(s) completed in 2/2 printed summaries, diff line present: True

evidence summary: 33/33 claims verified
```

</details>

A visual of a real scan against the demo target:

<p align="center">
  <img src="docs/assets/demo.png" alt="real summit scan output against the local demo target" width="760">
</p>

Reproduce everything yourself:

```bash
python examples/vuln_app.py    # terminal 1 - the target
summit scan http://127.0.0.1:8765
python examples/evidence.py    # re-verify every claim above
```

The demo seeds a *healthy* outbound link (`https://example.com`) as a negative control - it must never be reported, and CI asserts that alongside the seeded detections. Found something wrong anyway? [Report it](https://github.com/pennacle-security/summit/issues/new?template=bug_report.yml).

## Commands

| Command | What it does |
|---|---|
| `summit scan <url>` | crawl, then passive + active checks, link health, WAF analysis. The 37 bundled YAML templates run by default; `--no-templates` skips them. `--openapi` scans a spec instead of crawling. `--auto-html` writes an HTML report automatically; `--markdown` renders a triage-friendly Markdown report; `--render` adds headless-Chromium JS rendering (`pip install playwright`). |
| `summit map <url>` | crawl once and map pages, forms, technologies, outbound links and parameters without attack traffic. |
| `summit authorize <url...>` | BOLA/IDOR testing: compare responses between two roles. |
| `summit mine <url>` | hidden parameter discovery (~120 candidates, marker-based). |
| `summit fuzz <url>` | directory brute force with wildcard-baseline filtering - or Intruder-style payload fuzzing: `fuzz --request req.txt --payloads 'a,b,c'` walks payloads through `§positions§` in a raw request (sniper/pitchfork, `none`/`url`/`b64` encoders, divergence judged against a control request). |
| `summit recon <domain>` | chain subfinder -> httpx -> nmap into one report. |
| `summit tls <host>` | certificate expiry / self-signed / legacy TLS version audit. |
| `summit proxy` | intercepting HTTP proxy with a SQLite site map. `--tls-intercept` decrypts HTTPS with a locally generated CA - trust it once, every inner request lands in the site map in plaintext (needs `pip install 'summit-scanner[proxy]'`). |
| `summit schedule <url>` | run a scan on an interval and diff every round against the previous one (`--fail-on` gates on new or regressed findings; cron-friendly). |
| `summit repeater <file>` | send a raw request file (Burp-style). |
| `summit encode` / `summit decode` | base64, URL, hex, JWT (decode-only, honestly unverified). |
| `summit race <url>` | fire a burst of concurrent requests to surface race windows. |
| `summit diff <before.json> <after.json>` | compare two scan reports: new, resolved, regressed (`--fail-on` for CI). |
| `summit oob` | out-of-band callback listener: HTTP callbacks plus a raw TCP JNDI channel; proves blind SSRF / Log4Shell / Shellshock / blind XXE with a real hit. |
| `summit templates` | list or validate the 37 bundled YAML check templates. `--tags` / `--severity` narrow the list, `--json` emits machine-readable metadata. |
| `summit setup` | interactive setup wizard; saves defaults to `~/.summit/config.json`. |
| `summit --check-update` / `--auto-update` / `--install-tools` | versioning and recon tool installer. |

Shared flags on scanning commands: `--workers`, `--rate` (requests/second ceiling), `--retries` (with `Retry-After` support), `--timeout`, `--delay`, and `--progress` / `--no-progress` (live per-request log). CI gates: `--fail-on high` exits 1 when a reported finding is at or above that severity; add `--baseline previous.json` and only new or regressed findings count.

## Feature notes

**Authorization testing.** Requests each URL as a privileged and a low-privilege role, then compares. Verdicts: `enforced` (roles differ), `broken` (identical response for the low-privilege role - critical, `confirmed`), `partial` (same status, different body - `needs-manual`). Measured on the demo: the admin panel serves salaries to both roles, caught as `confirmed`.

**Hidden parameter mining.** Servers read parameters the HTML never mentions - debug switches, feature flags, internal overrides. ~120 candidate names are probed with unique markers; reflection findings are `confirmed`, status/size shifts are `needs-manual`. Measured: the demo's undocumented `debug` switch found as `confirmed`, the other candidates silent - zero noise.

**OpenAPI-driven scanning.** Every documented endpoint becomes a target, with path params filled from examples and defaults - no crawling, no guessing. Measured: the spec alone leads the engine to the seeded SQLi and XSS. JSON specs natively; YAML needs converting first (the dependency list stays at exactly one).

**Attack surface map before any attack traffic.** `summit map URL` crawls the target once, then inventories pages, titles, forms, parameters, JS endpoints, outbound links, and technologies. It also lists the injection points the scanner would probe. No attack traffic, no templates, no exploitation - just a clean map you can hand to another engineer.

**Payload fuzzing, Intruder-style.** Mark the spots worth varying in a raw request with `§positions§` - the same convention Burp uses, so request files paste straight in - and `summit fuzz --request req.txt --payloads 'a,b,c'` walks them. Sniper varies one position at a time; pitchfork pairs each position with its own payload file; payloads can pass through URL or base64 encoders. A control request is measured first, and a response only counts as a divergence when its status or body size really moved from that control - divergence is where hidden behavior lives (valid identifiers, debug flags, privilege boundaries), and it is always reported `needs-manual` for a human to judge. Results print per payload and export as JSON.

**GraphQL leaks beyond introspection.** Servers that answer an invalid field with "Did you mean ..." hand out real schema names one probe at a time - even with introspection disabled. The check confirms only on GraphQL-shaped validation errors, so plain 404s and non-GraphQL endpoints stay quiet.

**TLS interception, with a CA the tool generates itself.** `summit proxy --tls-intercept` generates a local CA on first run (after that, everything reuses it), issues a per-host leaf certificate for every CONNECT tunnel, and logs every decrypted request into the SQLite site map. Trust the printed CA once in your browser or OS and HTTPS traffic through the proxy reads like HTTP. The origin gets its own TLS session with verification off - the nature of an intercepting proxy. Optional `cryptography` dependency, stdlib alone cannot mint certificates.

**Scan scheduling - monitoring with a memory.** `summit schedule URL --every 900 --times 8 --fail-on high` runs the real scanner as a subprocess on an interval, keeps one JSON report per round, and diffs every round against the previous one with the same dedup key as `summit diff`. A new or regressed finding at or above the gate fails the run, so a cron job becomes a regression alarm instead of a growing pile of unexamined reports.

**Web cache deception, honestly gated.** A cacheable-looking path suffix (`/account/anything.js`) that returns the same session-bearing response as the original page is a deception surface - if a shared cache keys on the full URL, the victim's private page becomes public. The probe only fires on responses that carry a session cookie, must byte-match the original, and must not opt out of caching; it always ships `needs-manual`, because only a human who knows the cache topology can confirm the stored entry is reachable third-party.

**OS command injection, SSTI, CRLF, sensitive files, XPath, SSI.** Each ships with a hard confirmation rule: OS command injection uses an exec marker plus a control probe (a server that merely reflects input shows both markers; a server that executes shows the exec marker more often - measured `x2 vs x1`), SSTI requires `{{7*7}}` to come back as `49`, CRLF requires our injected header to materialize, sensitive files (`.env`, `.git/config`, cloud keys, Terraform state, dumps, backups) require a content signature - never just a 200, XPath requires a fresh XML parser error that the baseline did not contain, and SSI requires the `exec` marker to be printed **without** the raw directive (reflection alone never counts). Every finding is tagged with its CWE automatically (CWE-78, CWE-1336, CWE-113, CWE-538, CWE-643, CWE-96), and version banners are matched against an offline CVE database (spoofable banners stay `needs-manual`).

**Log4Shell, Shellshock and blind XXE, proven out-of-band.** A response body cannot prove a blind injection. With `--oob-listen`, summit sprays JNDI lookups into logged headers (`User-Agent`, `X-Forwarded-For`, `Referer`), a Shellshock function definition into `User-Agent`, and external entities at XML endpoints. The listener accepts both HTTP callbacks and raw JNDI/LDAP binds, and a finding is written only when the unique token arrives. No callback, no finding.

**YAML check templates, without leaving the CLI.** 37 Nuclei-style templates ship in the package and run by default: 18 new CVE/exposure checks (Apache 2.4.50 traversal, Flink, Grafana, Citrix, Pulse Secure, Fortinet SSL-VPN, F5 iControl, PHPUnit, PHP-CGI, Symfony profiler, Go pprof, Swagger UI, ASP.NET trace, ELMAH, Tomcat examples, phpMyAdmin setup, permissive crossdomain policy, WordPress XML-RPC) plus the core admin/actuator/Docker/Kubernetes/source-map/WP-JSON checks and v1.4 exposure checks for Git metadata, .env, AWS credentials, SSH keys, SQL backups, phpinfo, server-status, etcd, Consul, Docker registries, and Jupyter. The engine supports path lists, word/regex/status/DSL matchers, negative matchers, `stop-at-first-match`, `follow-redirects` and Nuclei placeholders. `--no-templates` skips them; `--templates FILE_OR_DIR` adds your own; `--template-tags`, `--template-exclude-tags` and `--template-severity` select a subset; `summit templates --json` inventories them.

**CI gates that separate old noise from new risk.** `summit scan ... --fail-on high` exits 1 when any reported finding is high or critical. Add `--baseline previous.json` and the gate only counts findings that are new or have regressed since that report - the failure your pipeline actually needs to act on. Reports are still written before the gate runs, and an unreadable baseline exits 2 rather than silently passing. The gate is deterministic, uses the same dedup key as `summit diff`, and keeps the exit-code contract stable for CI.

**CAPTCHA: detect, do not solve.** reCAPTCHA, hCaptcha, Cloudflare Turnstile and challenge pages are detected and reported. Solving them automatically is out of scope by design - that line does not move.

**Broken-link hijacking.** Every outbound link is health-checked: dead domains (DNS verified twice), parked domains (tight fingerprints), broken links (404/410), unreachable hosts, and private-target links - recorded but never fetched, so a hostile page cannot weaponize your scanner as an SSRF probe.

**Resource takeover fingerprints.** A 404 answered with a provider's unclaimed-resource page (AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Pantheon, Tumblr, Surge, Bitbucket) is a takeover setup. Fingerprint-only: no DNS tricks, no active claiming, ever.

**Recon orchestration.** subfinder -> httpx -> nmap, whichever are installed, with defensive parsing: passive-DNS noise capped, per-tool timeouts degrade into notes, and a crashed nmap is reported as *failed* - never as "no open ports".

**Rate limiting and prioritization.** `--rate` is a thread-safe requests/second ceiling (measured: 12 requests paced to 2.20s at rate 5; 0.02s unlimited). A transparent scoring model orders high-signal parameters first - deterministic and auditable, deliberately not a "neural network" claim.

**Toolkit and updates.** JWT decode with an honest "signature NOT verified" note, base64/URL/hex both directions, numeric version comparison against GitHub releases (`0.3 < 0.10`), self-update from a git checkout.

## Anti false positives and false negatives

False positives waste your triage time. False negatives get clients breached. Summit engineers against both, and the evidence runner proves it:

| Mechanism | What it kills |
|---|---|
| **Two-stage XSS check** - a unique canary goes first; payloads only fire on parameters that actually reflect | payload noise on parameters that never reflect |
| **Baseline diffing** - every probe compared against the same request untouched | error strings already sitting in the page |
| **Divergence + baseline match** (boolean SQLi) - `AND 1=1` must match the baseline, `AND 1=2` must differ | pages that simply vary per request |
| **Wildcard baseline** (fuzzer) - a random nonexistent path is measured first | "everything returns 200" servers flooding the report |
| **DNS double-check** (linkcheck) - a host must fail to resolve twice | transient resolver hiccups becoming fake hijack reports |
| **SSRF guard** - private/link-local/metadata ranges recorded, never fetched | your scanner weaponized against internal networks |
| **Tamper honesty** (WAF bypass) - requires the payload decoded in the response | bypass reports that would not survive a browser |
| **Tracker/opaque param filter** - `utm_*`, `fbclid`, 40+ char tokens never probed | wasted requests and padded reports |
| **Negative control in CI** - a healthy link that must stay unreported, asserted every push | silent regressions into false-positive territory |
| **Scope lock** - the spider never leaves the target host | crawling half the internet, and legal exposure |
| **Confidence labels + severity caps** - fact, strong likelihood or needs-manual, and the label caps severity | one flat "everything is critical" triage queue |
| **Unbreakable probe hosts** - `.example` cannot resolve | third-party callbacks and accidental DoS |

## Check catalog

| Check | Type | Severity | Confirmation basis |
|---|---|---|---|
| Missing security headers | passive | low | header absence |
| Cookie flags (Secure / HttpOnly / SameSite) | passive | low | header parse |
| SQL error / stack-trace disclosure | passive | low | baseline-diffed signatures |
| Server and tech version disclosure | passive | info | header parse |
| CORS wildcard with credentials | passive | low | header parse |
| Email exposure | passive | info | regex |
| WAF fingerprint | passive | info | tight vendor signatures |
| CAPTCHA / anti-bot challenge | passive | info | challenge markers, reported not solved |
| Resource takeover signature | passive | high | provider unclaimed-resource page on 404 -> `confirmed` |
| CNAME-level subdomain takeover | dns | critical | dangling CNAME resolves to an unclaimed service -> `confirmed`, CWE-350 |
| SQL injection, error-based | active | critical | fresh DB error vs baseline -> `confirmed` |
| SQL injection, boolean-based | active | medium | response divergence -> `likely` |
| SQL injection, time-based blind | active | medium | calibrated delay reproduced on every probe -> `likely` |
| GraphQL introspection enabled | passive-origin | low | real `__schema` payload -> `confirmed` |
| GraphQL field suggestions (schema leak) | passive-origin | low | "Did you mean" on an invalid field -> `confirmed`, CWE-200 |
| Reflected XSS | active | high | canary + raw payload reflection -> `confirmed` |
| DOM XSS candidate (source->sink in inline JS) | active | low | `location.hash` flows into `innerHTML` -> `needs-manual`, CWE-79 |
| WAF filter bypass | active | high | tampered payload lands decoded -> `confirmed` |
| Host header injection | active | high | marker domain echoed vs baseline -> `confirmed` |
| HTTP parameter pollution | active | medium | both injected markers land, in order -> `confirmed`, CWE-235 |
| CORS origin reflection | active | high | arbitrary origin reflected + credentials -> `confirmed` |
| OS command injection | active | critical | exec marker outruns control marker -> `confirmed`, CWE-78 |
| Server-side template injection (RCE) | active | critical | `{{7*7}}` evaluates to 49 -> `confirmed`, CWE-1336 |
| CRLF injection / response splitting | active | high | injected header materializes -> `confirmed`, CWE-113 |
| TRACE method enabled (XST surface) | active | high | marker header echoed back by TRACE -> `confirmed`, CWE-693 |
| Risky HTTP methods advertised | active | medium | Allow header lists TRACE/PUT/DELETE -> `likely`, CWE-650 |
| Sensitive file exposure (.env, .git, cloud keys, dumps, backups) | passive-origin | high | content signature, not just a 200 -> `confirmed`, CWE-538 |
| XXE (file disclosure via external entity) | active | high | local file content returned via entity -> `confirmed`, CWE-611 |
| SSRF (out-of-band confirmed) | active | high | listener received the callback -> `confirmed`, CWE-918 |
| Hardcoded secret in client-side code | passive | medium | vendor pattern + entropy, redacted -> `likely` (private keys `confirmed`), CWE-798 |
| Known CVE in version banner | passive | low | offline CVE database match -> `needs-manual` (banners spoof) |
| Open redirect | active | medium | 3xx Location to probe host -> `confirmed` |
| Path traversal | active | high | OS file indicators -> `confirmed` |
| XPath injection | active | high | fresh XML parser error vs baseline -> `confirmed`, CWE-643 |
| Server-side includes injection | active | high | `exec` marker printed without the raw directive -> `confirmed`, CWE-96 |
| Log4Shell (JNDI, OOB-confirmed) | active | critical | JNDI lookup reached our raw listener -> `confirmed`, CWE-917 |
| Shellshock (Bash, OOB-confirmed) | active | critical | crafted header triggered a callback -> `confirmed`, CWE-78 |
| Blind XXE (OOB-confirmed) | active | high | external entity fetched by the target -> `confirmed`, CWE-611 |
| Broken access control (BOLA/IDOR) | authorize | critical | identical response for low-privilege role -> `confirmed` |
| Email/user enumeration | active | medium | differential response for unknown identities -> `likely` |
| Directory listing | passive-origin | medium | "Index of /" content signature -> `confirmed` |
| Cacheable sensitive response | passive | low | sensitive marker + no Cache-Control -> `needs-manual` |
| Web cache deception surface | active-origin | low | cacheable suffix mirrors session page -> `needs-manual`, CWE-441 |
| Security headers grade | passive | info | deterministic A..F roll-up |
| Form missing CSRF token | passive-origin | medium | POST/password form without CSRF field -> `likely` |
| Hidden parameter (reflected) | mine | medium | unique marker reflected -> `confirmed` |
| Hidden parameter (behavior) | mine | low | status/size shift -> `needs-manual` |
| Link to dead domain (hijack) | linkcheck | high | DNS failure, verified twice -> `confirmed` |
| Link to parked domain (hijack) | linkcheck | high | tight parking fingerprints -> `confirmed` |
| Broken outbound link | linkcheck | medium | HTTP 404/410 -> `confirmed` |
| Unreachable outbound link | linkcheck | low | fails after retry -> `likely` |
| Outbound link to private IP | linkcheck | info | DNS resolution -> `confirmed`, never fetched |
| TLS certificate expired / self-signed | tls | high-medium | certificate dates and issuer -> `confirmed` |
| Legacy TLS versions accepted | tls | medium | handshake completed with TLSv1.0/1.1 -> `confirmed` |
| Directory fuzz | fuzz | info | status + wildcard baseline |
| Payload divergence (fuzzer) | fuzz | low | status/size shift vs the control request -> `needs-manual`, CWE-200 |

## How summit compares

| | summit | ZAP | Burp Suite |
|---|---|---|---|
| Price | free, MIT | free | paid core |
| UI | CLI + HTML/JSON reports | full GUI | full GUI |
| Scriptable in CI | yes, that is the point | add-ons | paid automation |
| Confidence-labelled findings | yes | partial | partial |
| Authorization testing (Autorize-style) | built in, scriptable | add-on | paid workflows |
| Hidden parameter mining (Param Miner-style) | built in | add-on | add-on |
| OpenAPI-driven scanning | built in | add-on | add-on |
| WAF detection + bypass probing | built in | partial | partial |
| Broken-link hijacking | built in | add-on | paid extension |
| Rate limiting | built in, thread-safe | add-on | paid |
| JWT/encoder toolkit | built in | add-on | built in |
| Takeover fingerprints, host header, CORS | built in | add-ons | add-ons |
| Codebase you can audit in an afternoon | ~7.5k lines | large | closed source |
| TLS-intercepting proxy | built in (`--tls-intercept`) | yes | yes |
| Race condition detection | `summit race` | add-on | paid (Turbo Intruder) |
| Intruder-style payload fuzzing | built in | add-on | paid (Intruder) |
| TLS certificate audit | `summit tls` | add-on | built in |
| SARIF output | built in | no | no |
| Pre-built binaries per release | yes | no | no |

We are not trying to replace either of them. Summit is the small tool you drop into a pipeline or onto a VPS box, and the codebase you can actually read line by line.

## Roadmap

- [x] ~~TLS interception in the proxy (generated CA)~~
- [x] ~~Scan scheduling~~
- [ ] Proxy match & replace rules (request interception beyond logging)
- [ ] HTTP/2-specific probes
- [x] ~~POST form and JSON body injection points~~
- [x] ~~Authenticated scanning (cookies, headers)~~
- [x] ~~CNAME-level subdomain takeover (DNS resolution + service verification)~~
- [x] ~~Plugin API for custom checks~~
- [x] ~~Request interception UI~~
- [x] ~~Collaboration server (out-of-band detection via HTTP callbacks)~~
- [x] ~~Headless browser integration (JS rendering + DOM-based XSS)~~
- [x] ~~Scan diffing (compare scans over time)~~

## Community and contributors

A repository that helps people back grows through word-of-mouth:

- **Questions** -> [Q&A discussion](https://github.com/pennacle-security/summit/discussions/categories/q-a) - beginner questions welcome, answered gladly
- **Ideas & roadmap votes** -> [Ideas](https://github.com/pennacle-security/summit/discussions/categories/ideas)
- **Show what you scanned** -> [Show and tell](https://github.com/pennacle-security/summit/discussions/categories/show-and-tell)
- **Your first contribution** -> [good first issues](https://github.com/pennacle-security/summit/labels/good%20first%20issue) come with step-by-step instructions
- First issues and PRs get a personal review and a spot below; the welcome bot says hello too

If summit saved you time on an engagement, a star helps the next person find it.

<!-- markdownlint-enable -->
<!-- prettier-ignore-end -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

## Contributing and security

PRs welcome - the [contributing guide](https://github.com/pennacle-security/.github/blob/main/CONTRIBUTING.md) covers the process, and adding a scan check is roughly thirty lines if you follow the pattern. [examples/vuln_app.py](examples/vuln_app.py) gives you a live target to test against.

Security issues go through private disclosure only. Details in the [security policy](https://github.com/pennacle-security/.github/blob/main/SECURITY.md).

## Legal and license

Summit is built for authorized security testing: your own systems, or systems you have written permission to test. We are not responsible for misuse. Licensed under [MIT](LICENSE).
