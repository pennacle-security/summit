# Changelog

All notable changes to summit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [v2.1.0] - 2026-10-26

### Added

- TLS interception in the proxy (the top roadmap item): `summit proxy
  --tls-intercept` generates a local CA on first run (`~/.summit/proxy-ca`,
  or `--ca-dir`), issues a per-host leaf certificate for every CONNECT
  tunnel, and logs every decrypted inner request into the SQLite site map.
  Trust the printed CA once and HTTPS through the proxy reads like HTTP;
  the origin gets its own TLS session with verification off. Needs the new
  optional `cryptography` dependency - `pip install 'summit-scanner[proxy]'`.
  Pass-through mode (the old behavior) stays the default and is now covered
  by tests - which caught and fixed a pre-existing bug where a tunnel whose
  origin closed first (Connection: close) left the client waiting for an
  EOF that never came.
- Scan scheduling (the last roadmap item): `summit schedule URL --every
  900 --times 8` runs the real scanner as a subprocess on an interval,
  keeps one JSON report per round, and diffs every round against the
  previous one with the same dedup key as `summit diff`. `--fail-on`
  gates on new or regressed findings per round, so a cron job becomes a
  regression alarm. Extra scan flags pass through after a bare `--`.
- Web cache deception check (CWE-441): a cacheable-looking path suffix
  that returns the same session-bearing response as the original page is
  reported `needs-manual`. Fires only on responses carrying a session
  cookie, requires a byte-prefix match with the original, and skips
  responses that opt out of caching (`no-store`/`private`/`no-cache`).
- Demo-target seed for the deception check (`/account`, session cookie
  plus suffix-tolerant routing). The evidence runner grew from 30 to 33
  claims; the README example output carries the v2.1.0 run.

### Changed

- The proxy's relay now fixes response framing (Transfer-Encoding dropped,
  Content-Length set from the decoded body) instead of passing chunked
  framing alongside a decoded body.
- `cryptography>=42` ships as an optional extra (`[proxy]`); the core
  dependency list stays at three. CI installs the extra so the TLS proxy
  is tested on every push.


## [v2.0.0] - 2026-10-25

### Added

- Intruder-style payload fuzzing: `summit fuzz --request FILE` runs a payload
  list through `§positions§` in a raw request - the Burp convention, so
  existing request files paste straight in. Sniper (one position at a time)
  and pitchfork (position i paired with payload file i) modes, `none`/`url`/
  `b64` encoders, and a control request measured first: a response only
  becomes a finding when its status code or body size really moved from the
  control, and divergences stay `needs-manual` for a human to judge. Results
  print as a per-payload table and export with `--json`.
- GraphQL field-suggestion check (CWE-200): a deliberately invalid field is
  probed against the common GraphQL paths; servers that answer "Did you
  mean ..." leak schema names one probe at a time even with introspection
  disabled. Confirmed only on GraphQL-shaped validation errors - plain 404s
  and non-GraphQL endpoints stay quiet.
- Markdown reports: `scan --markdown report.md` renders the same
  severity-grouped findings as a triage document - severity summary table,
  per-finding sections with check, confidence, CWE, evidence, impact and
  remediation.
- Demo-target seeds for the new checks: `/api/discount?code=` (only valid
  codes diverge - the fuzzer's showcase) and field suggestions on `/graphql`.
- The evidence runner grew from 27 to 30 claims; the README example output
  carries the v2.0.0 run.

### Changed

- `summit fuzz` now accepts two modes: a URL with a wordlist (unchanged) or
  a raw request with payload positions (`--request`); the URL argument is
  optional so `--request` can stand alone. Existing invocations keep working.


## [v1.5.0] - 2026-10-25

### Added

- New `summit map` command: crawl a target once and produce a structured
  attack-surface map without sending attack traffic.
- `map` can export JSON, Markdown and a self-contained HTML report.
- The map inventories crawled pages, titles, forms, parameters, JavaScript
  endpoints discovered by the spider, outbound links, technologies, and the
  injection points the scanner would target.
- `map --progress` / `--no-progress` reuse the live per-request log from v1.4.0.
- 12 new exposure templates: Git metadata, `.env`, AWS credentials, SSH
  private keys, SQL backups, phpinfo, Apache server-status, etcd, Consul,
  Docker registry, and the Jupyter contents API. The bundle now contains
  37 templates.
- `classification.cve-id` on every bundled CVE template, and a consistency
  check between the `cve` tag and the CVE metadata.
- Template validation now requires a CWE id, rejects malformed or duplicate
  CVE ids, and refuses `confirmed` templates whose only evidence is a status
  code.


## [v1.4.0] - 2026-10-24

### Added

- Live scan progress: every crawl, check, link validation, deep probe, and
  template request prints the method and URL while the scan is running.
  Interactive terminals update one line; piped logs keep one line per event.
  `--progress` forces it on and `--no-progress` turns it off.
- 12 new exposure templates: Git metadata, `.env`, AWS credentials, SSH
  private keys, SQL backups, phpinfo, Apache server-status, etcd, Consul,
  Docker registry, and the Jupyter contents API. The bundle now contains
  37 templates.
- `classification.cve-id` on every bundled CVE template, and a consistency
  check between the `cve` tag and the CVE metadata.
- Template validation now requires a CWE id, rejects malformed or duplicate
  CVE ids, and refuses `confirmed` templates whose only evidence is a status
  code.

### Changed

- The `TEMPLATES` phase reports the actual template request URL and finding
  count as it runs.
- Documentation, quick-start output, and template inventory now describe the
  37-template bundle.

## [v1.3.0] - 2026-10-20

### Added

- CI severity gates: `scan --fail-on SEVERITY` exits 1 when a reported
  finding is at or above the chosen severity. Reports are written before the
  gate is evaluated.
- Baseline-aware gating: `scan --baseline previous.json` diffs the current
  findings against an earlier report with the same dedup key as `summit diff`;
  only new or regressed findings count toward `--fail-on`. An unreadable
  baseline exits 2 instead of passing silently.
- Template selection: `scan --template-tags`, `--template-exclude-tags` and
  `--template-severity` choose a subset of the 25 bundled templates.
- `summit templates --tags/--exclude-tags/--severity` filters the inventory,
  and `summit templates --json` emits machine-readable template metadata.

### Changed

- The `TEMPLATES` phase reports how many templates actually ran after
  filtering, not how many files were considered.

## [v1.2.0] - 2026-10-20

### Added

- Nuclei-style YAML template engine: path lists, word/regex/status/DSL
  matchers, negative matchers, `stop-at-first-match`, `follow-redirects`
  and Nuclei placeholders. The 25 bundled templates now run with every
  scan by default; `--no-templates` skips them and `--templates` adds custom
  checks.
- 18 new bundled CVE/exposure templates: Apache 2.4.50 traversal, Flink,
  Grafana, Citrix, Pulse Secure, Fortinet SSL-VPN, F5 iControl, PHPUnit,
  PHP-CGI, Symfony profiler, Go pprof, Swagger UI, ASP.NET trace, ELMAH,
  Tomcat examples, phpMyAdmin setup, permissive crossdomain and WordPress
  XML-RPC.
- New checks: XPath injection (CWE-643), SSI injection (CWE-96), Log4Shell
  (CWE-917), Shellshock (CWE-78) and blind XXE (CWE-611). The last three are
  reported only after a real out-of-band callback.
- The OOB listener accepts raw JNDI/LDAP binds on a second TCP port;
  `--oob-listen` now sprays Log4Shell, Shellshock and blind XXE payloads.
- Sensitive-file catalog expanded to 26 default and 26 deep paths: cloud
  credentials, Kubernetes/Docker auth, Terraform state, private keys,
  database dumps and application logs.

### Changed

- Built-in templates run automatically during `scan`; `--no-templates`
  restores the previous behavior. Five duplicate or weak templates were
  removed and the admin-panel check now requires a password field.
- Header matchers use `HttpResponse.headers_text()` instead of relying on a
  method that did not exist.

### Fixed

- Raw JNDI token extraction now handles prefixes containing digits
  (`log4j...`), so Log4Shell callbacks correlate correctly.

## [v1.1.0] - 2026-10-18

### Added

- `summit setup` - first-run wizard; saves defaults to `~/.summit/config.json`.
- `summit oob` - out-of-band HTTP callback listener; `summit scan --oob-listen PORT`
  confirms blind SSRF/XXE with a real callback hit.
- `--auto-html` writes an HTML report automatically after every scan (into
  `summit-reports/`, or the `output_dir` saved by setup).
- `--render` scans JavaScript-rendered pages via headless Chromium
  (optional: `pip install playwright`).
- CNAME-level subdomain takeover verification: DNS resolution plus
  unclaimed-service fingerprint, confirmation-only (no claiming).
- New checks: XXE (CWE-611), out-of-band SSRF (CWE-918), DOM XSS candidate
  (CWE-79), hardcoded secrets in client-side code (CWE-798, values redacted),
  HTTP parameter pollution (CWE-235), TRACE / risky HTTP methods
  (CWE-693, CWE-650).

### Changed

- Four confidence levels - `confirmed`, `likely`, `needs-manual`, `info` - and
  the label now caps severity (`likely` -> max medium, `needs-manual` -> max low):
  heuristic findings can no longer surface as critical.
- Colorized console output and an ASCII banner; respects `NO_COLOR`,
  `TERM=dumb` and `--no-color` (piped output stays plain).

### Fixed

- Redirect handling hardened: environment proxies are ignored
  (`trust_env=False`), CRLF-shaped `Location` values get `Connection: close`,
  and link checks no longer crash on malformed URLs.

## [v0.7.1] - 2026-10-16

### Fixed

- `build_requests` crashed with `AttributeError` when an OpenAPI spec contained
  a `null` path entry (e.g. `"/x": null`). Non-dict path values are now skipped
  instead of crashing the entire scan. Found by stability testing, covered by a
  regression test.
- `__init__.py` and `pyproject.toml` now carry the correct version (0.7.1,
  not the stale 0.6.0 they were carrying from a missed version bump).

### Changed

- Stability audit: 30+ edge-case tests run against the full codebase - empty
  findings, malformed specs, unreachable targets, dirty severity filters,
  duplicate links, None banners, negative rate-limiter intervals, concurrent
  proxy port binding. All pass.

## [v0.7.0] - 2026-10-16

### Added

- Impact-first reporting: 30+ impact statements per check, shown in every
  console, JSON and HTML report next to the finding.

## [v0.6.9] - 2026-10-16

### Added

- Body-based CVE detection: jQuery < 3.5.0 (CVE-2020-11023), lodash < 4.17.19
  (CVE-2020-8203), WordPress 5.7.0/5.7.1 (CVE-2021-29447) - detected from
  script URLs and meta generator tags.

## [v0.6.8] - 2026-10-16

### Added

- JS endpoint extraction (AJAX-spider pass): fetch/axios/XHR targets hidden
  in JavaScript are now crawled and scanned - a major FN killer.
- CSRF form check (CWE-352): state-changing forms without CSRF tokens.

## [v0.6.7] - 2026-10-16

### Added

- Email enumeration (CWE-204): differential responses on identity-shaped params.
- Directory listing (CWE-548): content-signature detection on autoindex pages.
- Cacheable sensitive response (CWE-524): sensitive content without Cache-Control.
- Security headers grade: deterministic A..F roll-up.

## [v0.6.6] - 2026-10-16

### Added

- Severity filtering: `--severity high,critical` and `--min-severity medium`.
- Per-severity breakdown in console and HTML reports.

## [v0.6.5] - 2026-10-16

### Added

- Documentation site (MkDocs Material) and complete usage reference.

## [v0.6.4] - 2026-10-16

### Added

- `summit tls` certificate and protocol audit command.
- Spider follows redirects (FN reduction).

## [v0.6.3] - 2026-10-16

### Added

- Range-based CVE matching with `packaging`; Heartbleed and Ghostcat entries.
- YAML OpenAPI spec support (PyYAML).

### Changed

- New dependencies: `pyyaml>=6.0`, `packaging>=23.0`.

## [v0.6.2] - 2026-10-16

### Added

- Time-based blind SQL injection (CWE-89): baseline-calibrated, reproducible.
- GraphQL introspection detection (CWE-200).
- Param miner expanded to ~120 candidates.
- Sensitive paths: /.git/HEAD, /.aws/credentials.

## [v0.6.1] - 2026-10-16

### Fixed

- authorize guard: login-redirect wall suppressed (not reported as BOLA).
- SSTI guard: echoed template + incidental "49" suppressed (not reported as injection).
- Evidence is no longer truncated in any report output.

## [v0.6.0] - 2026-10-16

### Added

- OS command injection (CWE-78) with anti-FP control probe.
- SSTI (CWE-1336) with math-canary detection.
- CRLF injection (CWE-113) with injected-header materialization.
- Sensitive file exposure (CWE-538) with content signatures.
- CWE tagging on every finding (central map, 30+ check ids).
- CVE detection from version banners (offline curated database).

## [v0.5.0] - 2026-10-16

### Added

- `summit authorize` (Autorize workflow) - broken access control testing.
- `summit mine` (Param Miner approach) - hidden parameter discovery.
- OpenAPI-driven scanning - spec becomes targets, no crawling.
- Demo app: /admin, /debug, examples/openapi.json.

## [v0.4.0] - 2026-10-16

### Added

- Resource takeover fingerprints (S3, GitHub Pages, Heroku, Azure, etc.).
- Host header injection, CORS origin reflection checks.
- Thread-safe engine, latency-based concurrency benchmark.

## [v0.3.0] - 2026-10-16

### Added

- WAF fingerprinting and bypass probing.
- CAPTCHA detection (reported, not solved).
- Rate limiting, retries, smart prioritization.
- Recon orchestration (subfinder/httpx/nmap).
- Toolkit (JWT, base64, URL, hex).
- Evidence runner.

## [v0.2.0] - 2026-10-16

### Added

- Broken link hijacking with confidence labels.
- Concurrent engine, tracker/opaque param filter.
- Demo target with negative control.

## [v0.1.0] - 2026-10-16

### Added

- First public release.
- CLI: scan / fuzz / proxy / repeater.
- Passive and active checks, JSON and HTML reports.

