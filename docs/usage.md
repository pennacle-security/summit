# Usage

Every command follows the same shape: plain flags, honest output, `--json` where a report makes sense.

## scan - the main event

```bash
summit scan https://testsite.local --depth 2 --workers 8 --rate 10
```

Crawls the target (same-host only), then runs passive checks on every page, active checks on every injectable parameter, and link-health checks on every outbound link.

| Flag | Meaning |
|---|---|
| `--depth N` / `--max-pages N` | crawl limits (default 3 / 50) |
| `--workers N` | parallel check workers (default 8) |
| `--rate R` | hard requests-per-second ceiling across all threads |
| `--timeout S` / `--retries N` | per-request timeout; retries on connection errors and 429/503 with `Retry-After` support |
| `--no-active` | passive only - zero attack traffic |
| `--skip-linkcheck` | skip outbound-link health checks |
| `--progress` / `--no-progress` | show the live per-request log (default: on in a terminal, off when piped) |
| `--json` / `--html` | write reports |
| `--auto-html` | write an HTML report automatically after the scan, into `summit-reports/` (`--no-auto-html` to disable) |
| `--render` | render JavaScript pages with headless Chromium (needs `pip install playwright`) |
| `--oob-listen PORT` | run the OOB listener (HTTP + raw JNDI TCP) and confirm blind SSRF / Log4Shell / Shellshock / blind XXE with real callbacks |
| `--templates FILE_OR_DIR` | add YAML check templates to this scan (the 37 built-ins always run) |
| `--no-templates` | skip the bundled YAML templates for this run |
| `--template-tags TAGS` | run only templates carrying any of these comma-separated tags, e.g. `cve,rce` |
| `--template-exclude-tags TAGS` | skip templates carrying any of these tags, e.g. `dos,wordpress` |
| `--template-severity LIST` | run only templates with these severities, e.g. `critical,high` |
| `--fail-on SEVERITY` | exit 1 when a reported finding is at or above this severity (CI gate) |
| `--baseline FILE` | previous scan JSON; with `--fail-on`, only new or regressed findings count |

Output includes an honest count: `1061 request(s) in 3.4s (workers=8, rate=unlimited, retries=1)` (`rate=10.0` when you pass `--rate 10`) plus the prioritizer's note (`smart order: N high-signal injection point(s) probed first`).

## CI gates - fail the build on real risk

```bash
summit scan https://testsite.local --json current.json --fail-on high
summit scan https://testsite.local --json current.json --baseline previous.json --fail-on high
```

`--fail-on` exits **1** when any reported finding is at or above that severity. With `--baseline`, summit diffs the current findings against the earlier JSON using the same dedup key as `summit diff`; only **new** or **regressed** findings can fail the gate. Reports are written before the gate is evaluated, so CI keeps the artifact either way. An unreadable baseline exits **2** instead of silently passing. Exit **0** means the gate passed.

## fuzz - directory brute force

```bash
summit fuzz https://testsite.local -w wordlist.txt -e php,bak -t 20
```

Measures a wildcard baseline first (a random nonexistent path) and filters everything that answers identically - "everything returns 200" servers cannot flood the report.

## fuzz - Intruder-style payload fuzzing

```bash
summit fuzz --request req.txt --payloads 'SUMMIT10,BOGUS1,BOGUS2' --json fuzz.json
```

Mark the spots worth varying in a raw request with `§positions§` (the Burp Intruder convention, so existing request files paste straight in). A control request built from the untouched originals is measured first; a response counts as divergent when its status or body size really moved from the control. Sniper mode varies one position at a time; `--mode pitchfork` pairs position i with the i-th `--payload-file`. Payloads can pass through `--encoder none|url|b64`. Divergences print per payload and are reported `needs-manual` - only a human can say what the difference means.

## proxy - local intercepting proxy

```bash
summit proxy --port 8080
```

Plain HTTP is forwarded and logged into a SQLite site map. HTTPS CONNECT tunnels are logged and passed through.

```bash
summit proxy --port 8080 --tls-intercept
```

With `--tls-intercept`, the proxy generates a local CA on first run
(`~/.summit/proxy-ca`, override with `--ca-dir`), issues a per-host leaf
certificate for every tunnel, and logs every decrypted request into the
site map. Trust the printed `ca.crt` once in your browser or OS; the
origin is reached with its own TLS session, verification off. Needs the
optional `cryptography` package: `pip install 'summit-scanner[proxy]'`.

## schedule - scan on an interval, diff every round

```bash
summit schedule https://app.local --every 900 --times 8 --fail-on high --out-dir summit-history
```

Runs the real scanner as a subprocess per round, writes `scan-NNN.json`
per round, and diffs each round against the previous one with the same
dedup key as `summit diff`. `--fail-on` exits 1 when a round reports a
new or regressed finding at or above the severity - a cron job becomes a
regression alarm. Extra scan flags pass through after `--`:

```bash
summit schedule https://app.local --every 3600 -- --rate 5 --no-templates
```

## repeater - raw request sender

```bash
summit repeater examples/request.txt
```

Burp-style raw request files. Host headers in the file are honored.

## authorize - broken access control testing

```bash
summit authorize https://app.local/admin?user=1 \
  --role 'admin=Cookie: session=admintoken' \
  --role 'user=Cookie: session=usertoken'
```

First `--role` is the privileged baseline; the second is what an attacker would have. Verdicts: `enforced`, `broken` (identical response for the low-privilege role - critical), `partial` (same status, different body).

## mine - hidden parameter discovery

```bash
summit mine https://app.local/debug --workers 8
```

Probes ~120 undocumented parameter names with unique markers. Reflection findings are `confirmed`; behavior changes are `needs-manual`.

## race - concurrent-request probing

```bash
summit race https://app.local/api/claim -n 10 --json race.json
```

Fires a burst of identical concurrent requests (`-n` / `--concurrency`, default 10) and reports response divergence inside the window as a `needs-manual` candidate - evidence for a human to confirm, not a verdict. `--method`, `--data` and `--cookie` shape the request; `--json` writes the report.

## diff - compare two scans

```bash
summit diff before.json after.json --fail-on regressed
```

Matches findings between two scan JSON reports and classifies them as new, resolved or regressed. `--fail-on new|regressed|any` turns it into a CI gate.

## oob - out-of-band callback listener

```bash
summit oob --port 9999                               # terminal 1: the listener
summit scan https://target.local --oob-listen 9999   # terminal 2: scan with OOB
```

A local listener with two channels: an HTTP listener for blind SSRF and blind XXE callbacks, and a raw TCP listener that catches JNDI/LDAP binds (Log4Shell). With `--oob-listen PORT`, a scan sprays log4shell JNDI headers, a Shellshock `User-Agent` and external entities at XML endpoints; findings fire only when the unique token actually reaches the listener. No callback, no finding.

## templates - YAML check templates

```bash
summit templates                                # list the 37 built-in templates
summit templates --tags cve --severity critical # filter the inventory
summit templates --json                         # machine-readable metadata
summit templates path/to/template.yaml          # validate one file or directory
summit scan https://target.local --templates path/to/dir
summit scan https://target.local --no-templates
summit scan https://target.local --template-tags cve --template-severity critical
```

The 37 bundled templates run on every scan by default. Nuclei-style matchers (`word`, `regex`, `status`, `dsl`), path lists, negative matchers, `stop-at-first-match`, `follow-redirects` and `{{BaseURL}}` / `{{Host}}` / `{{Path}}` placeholders are supported; HIGH/CRITICAL templates must state a `confidence-rule` or they fail validation. `--template-tags`, `--template-exclude-tags` and `--template-severity` select a subset at scan time. `--templates` adds custom checks, `--no-templates` skips the bundle, and `summit setup --template-dir` persists a template directory as the default. In `summit templates`, filters apply to list mode; validate mode always checks every file it is given.

## map - inventory the attack surface

```bash
summit map http://target.local --depth 3 --max-pages 50
summit map http://target.local --json surface.json --markdown surface.md --html surface.html
```

Crawl once, then inventory pages, titles, forms, parameters, outbound links, technologies and the injection points summit would probe. This is reconnaissance only - no attack traffic, no templates and no exploitation. Use it before `scan` when you want to understand the target or hand a clean surface map to another engineer.

## setup - persist your defaults

```bash
summit setup
```

Interactive wizard that saves your defaults to `~/.summit/config.json`; later scans pick them up without repeating flags.

## tls - certificate and protocol audit

```bash
summit tls target.com --port 443 --json tls.json
```

Checks certificate expiry, self-signing and whether legacy TLS versions (v1.0/1.1) still complete handshakes. Standalone command - it talks to the network by definition.

## OpenAPI-driven scanning

```bash
summit scan https://api.local --openapi api-spec.json
```

Every documented path becomes a target (path params filled from examples and defaults). JSON and YAML specs both supported (PyYAML ships as a dependency).

## recon - chain your tools

```bash
summit recon testsite.local --json recon.json
```

subfinder -> httpx -> nmap, whichever are installed. Subfinder noise on common domains is capped, per-tool timeouts degrade into notes, and a crashed nmap is reported as *failed* - never as "no open ports".

## encode / decode - the toolkit

```bash
summit decode -f jwt "eyJhbGci..."   # header + payload, honest "signature NOT verified" note
summit decode -f b64 c3VtbWl0
summit encode -f url "admin' OR 1=1--"
summit encode -f hex "ping"
```

## housekeeping

```bash
summit --check-update   # numeric comparison against the latest GitHub release
summit --auto-update    # git pull when running from a checkout
summit --install-tools  # best-effort installer for recon integrations
```
