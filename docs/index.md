# summit

Proxy, scanner, fuzzer, WAF analysis and recon orchestration in one scriptable CLI.

Summit exists because we use Burp and ZAP every day and kept wanting three things they are not: a scanner we can script against in CI, findings that tell us how sure they are, and a codebase small enough to read in one sitting.

The rule that shapes everything else: **every claim is measured**. [`examples/evidence.py`](https://github.com/pennacle-security/summit/blob/main/examples/evidence.py) runs the demo target live and verifies each feature with real numbers. CI executes it on every push.

## Two-minute start

```bash
git clone https://github.com/pennacle-security/summit.git
cd summit
pip install -e .

python examples/vuln_app.py        # terminal 1: a vulnerable local target
summit scan http://127.0.0.1:8765  # terminal 2: watch it work
```

No internet needed for the core demo. The target binds to 127.0.0.1 only.

## What it does today

| Area | Coverage |
|---|---|
| Scanner | passive checks (headers, cookies, error leaks, CORS, WAF, CAPTCHA, takeover, JS secrets, CSRF, cache hygiene) + active checks (SQLi error/boolean/time, XSS and DOM-XSS candidates, WAF bypass, host header, CORS, redirect, traversal, XPath, SSI, XXE, SSRF, Log4Shell, Shellshock, command injection, SSTI, CRLF, HPP, HTTP method hygiene) |
| Templates | 37 bundled Nuclei-style YAML checks (CVE/exposure), run by default with `--no-templates` opt-out; tag and severity filters |
| CI gates | `--fail-on SEVERITY` and `--baseline previous.json` diff gating with stable 0/1/2 exit codes |
| Link health | broken-link hijacking: dead domains, parked domains, private-range guard |
| Attack surface | crawl once and inventory pages, forms, parameters, technologies and outbound links |
| Fuzzing | directory brute force with wildcard-baseline filtering, plus Intruder-style payload fuzzing of raw `§position§` requests |
| Proxy | intercepting HTTP proxy with a SQLite site map; `--tls-intercept` decrypts HTTPS with a self-generated CA |
| Recon | chains subfinder -> httpx -> nmap, with honest failure notes |
| Toolkit | JWT / base64 / URL / hex encode & decode |

Findings carry **confidence labels**: `confirmed` (observed fact), `likely` (strong evidence), `needs-manual` (heuristic for a human), `info` - and the label caps severity, so a heuristic can never pose as critical. That distinction runs through the whole tool.

## Legal

Authorized testing only: your own systems, or systems you have written permission to test. We are not responsible for misuse.

## Release history

See the [changelog](https://github.com/pennacle-security/summit/blob/main/CHANGELOG.md) for what shipped in each version.
