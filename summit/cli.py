"""Summit command line - colourful, configurable, scriptable.

The CLI is the product's front door, so it gets the full treatment:
gradient banner on interactive terminals, phase-tagged progress lines,
severity-badged findings, and a setup wizard that persists defaults to
~/.summit/config.json. Behaviour stays boring where it matters: every
command remains usable in CI (no colour when piped, compact banner,
stable exit codes), and flags always override saved settings.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__, colors
from .authorize import findings_from, parse_role, run_authorize
from .banner import render_banner
from .config import Settings, default_config_path, load_settings, resolve_paths, save_settings
from .crawl.spider import Spider
from .diff import diff_finding_lists, diff_reports, load_findings
from .fuzz.dirbuster import fuzz
from .fuzz.intruder import findings_from as intruder_findings_from
from .fuzz.intruder import run_intruder
from .http.client import HttpClient
from .http.models import HttpRequest
from .oob import OobServer
from .openapi import load_spec, spec_pages
from .paramminer import mine
from .progress import ProgressReporter
from .proxy.server import ProxyServer
from .race import findings_from as race_findings_from, run_race_test
from .recon import missing_tools, render_report, run_recon
from .report.writer import write_console, write_html, write_json, write_markdown
from .scan.core import SEVERITIES, SEVERITY_RANK, filter_by_min_severity, filter_by_severities
from .scan.engine import ScanEngine
from .scan.modules.ssrf import SsrfCheck
from .toolkit import decode_text, encode_text
from .tls import audit as tls_audit
from .updates import fetch_latest_version, install_tools, is_outdated, self_update

_SILENT = False
_PROGRESS: ProgressReporter | None = None


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _reconfigure_stdio() -> None:
    """Force UTF-8 on Windows consoles so glyphs and user data survive."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (AttributeError, ValueError, OSError, TypeError):
            pass


def _has_flag(argv: list[str] | None, flag: str) -> bool:
    if argv is None:
        argv = sys.argv[1:]
    return flag in argv


def _log(msg: str) -> None:
    """Print a progress line unless --silent is active."""
    if not _SILENT:
        if _PROGRESS is not None:
            _PROGRESS.clear()
        print(msg)


def _phase(tag: str, message: str) -> None:
    """Progress line with a coloured phase tag: `│ ▸ SCAN running checks ...`."""
    _log(f"{colors.phase_tag(tag)} {message}")


def _banner(compact: bool = False) -> None:
    """Full art on interactive terminals, one-liner when piped or asked."""
    if _SILENT:
        return
    if not compact and not sys.stdout.isatty():
        compact = True
    print(render_banner(__version__, compact=compact))


def _fmt_duration(seconds: float) -> str:
    """Format seconds as human-readable duration (e.g. '1m 23s', '2h 5m 3s')."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {secs}s"


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="summit",
        description="Summit - open-source web security testing platform (proxy, scanner, fuzzer, link hijack detection).",
    )
    parser.add_argument("--version", action="version", version=f"summit {__version__}")
    parser.add_argument("--silent", action="store_true", help="suppress all progress/debug output, only show findings")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output (same as NO_COLOR=1)")
    parser.add_argument("--check-update", action="store_true", help="compare the installed version against the latest GitHub release")
    parser.add_argument("--auto-update", action="store_true", help="update summit in place (git checkout) or print exact install steps")
    parser.add_argument("--install-tools", action="store_true", help="install recon tools (nmap, httpx, subfinder) via the available package manager")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="crawl a target and run passive + active checks")
    scan.add_argument("url", nargs="?", help="target URL, e.g. https://testsite.local (required unless --openapi is used)")
    scan.add_argument("--openapi", dest="openapi_path", help="scan an OpenAPI/JSON spec instead of crawling (paths become targets)")
    scan.add_argument("--depth", type=int, default=None, help="max crawl depth (default 3, deep 5)")
    scan.add_argument("--max-pages", type=int, default=None, help="max pages to visit (default 50, deep 200)")
    scan.add_argument("--no-active", action="store_true", help="skip active checks (passive only)")
    scan.add_argument("--skip-linkcheck", action="store_true", help="skip broken link / hijack check")
    scan.add_argument("--workers", type=int, default=None, help="parallel check workers (default 8, deep 12)")
    scan.add_argument("--rate", type=float, default=None, help="max requests per second across all workers, e.g. --rate 5")
    scan.add_argument("--retries", type=int, default=None, help="retries on connection errors and 429/503 (default 1, deep 2)")
    scan.add_argument("--delay", type=float, default=None, help="seconds between requests (be nice)")
    scan.add_argument("--timeout", type=float, default=None, help="request timeout in seconds")
    scan.add_argument("--deep", action=argparse.BooleanOptionalAction, default=None,
                      help="deep mode: extended payload sets and larger crawl defaults (persist with `summit setup`)")
    scan.add_argument("--render", action="store_true", help="render JavaScript pages with headless Chromium (needs: pip install playwright)")
    scan.add_argument("--templates", dest="templates_path", default=None,
                      help="add YAML check templates from a file or directory (built-ins run by default; persist with `summit setup --template-dir`)")
    scan.add_argument("--no-templates", dest="no_templates", action="store_true",
                      help="skip the built-in YAML templates for this run")
    scan.add_argument("--template-tags", dest="template_tags", default=None,
                      help="only run templates carrying any of these tags (comma separated)")
    scan.add_argument("--template-exclude-tags", dest="template_exclude_tags", default=None,
                      help="skip templates carrying any of these tags (comma separated)")
    scan.add_argument("--template-severity", dest="template_severity", default=None,
                      help="only run templates with these severities (comma separated, e.g. critical,high)")
    scan.add_argument("--oob-listen", dest="oob_listen", type=int, default=None, metavar="PORT",
                      help="start a local out-of-band listener and confirm blind SSRF / Log4Shell / Shellshock / XXE by real callback")
    scan.add_argument("--oob-url", dest="oob_url", default=None,
                      help="external OOB base URL (informational only - callbacks over it cannot be auto-verified)")
    scan.add_argument("--oob-bind", dest="oob_bind", default="127.0.0.1", help="address the OOB listener binds to (default 127.0.0.1)")
    scan.add_argument("--oob-advertise", dest="oob_advertise", default="", metavar="HOST",
                      help="hostname the target should use to reach the listener (default: the bind address)")
    scan.add_argument("--no-takeover", dest="no_takeover", action="store_true", help="skip the CNAME subdomain-takeover check")
    scan.add_argument("--auto-html", action=argparse.BooleanOptionalAction, default=None,
                      help="write an HTML report automatically (persist with `summit setup`)")
    scan.add_argument("--header", action="append", default=None, metavar="NAME: VALUE", help="extra request header, repeatable")
    scan.add_argument("--cookie", default=None, help="Cookie header value")
    scan.add_argument("--user-agent", dest="user_agent", default=None, help="override the User-Agent header")
    scan.add_argument("--json", dest="json_path", help="write a JSON report to this path")
    scan.add_argument("--html", dest="html_path", help="write an HTML report to this path")
    scan.add_argument("--sarif", dest="sarif_path", help="write a SARIF 2.1.0 report (GitHub code scanning compatible)")
    scan.add_argument("--junit", dest="junit_path", help="write a JUnit XML report (CI/CD pipeline compatible)")
    scan.add_argument("--markdown", dest="markdown_path", help="write a Markdown report (triage documents, PR comments)")
    scan.add_argument("--severity", default=None, help="only report these severities, comma separated: high,critical")
    scan.add_argument("--min-severity", dest="min_severity", default=None,
                      choices=list(SEVERITIES), help="report findings at or above this severity")
    scan.add_argument("--fail-on", dest="fail_on", choices=list(SEVERITIES), default=None,
                      help="exit 1 when a reported finding is at or above this severity (CI gate)")
    scan.add_argument("--baseline", dest="baseline_path", default=None,
                      help="previous scan JSON; with --fail-on, only new or regressed findings count")
    scan.add_argument("--silent", action="store_true", help="suppress all progress/debug output, only show findings")
    scan.add_argument("--progress", action=argparse.BooleanOptionalAction, default=None,
                      help="show the live per-request scan log (default: on in a terminal, off when piped)")
    scan.add_argument("--no-color", action="store_true", help="disable coloured output for this run")

    setup = sub.add_parser("setup", help="interactive setup wizard - saves defaults to ~/.summit/config.json")
    setup.add_argument("--yes", action="store_true", help="accept current values, skip the prompts (scriptable)")
    setup.add_argument("--show", action="store_true", help="print the current settings and exit")
    setup.add_argument("--reset", action="store_true", help="delete the config file and exit")
    setup.add_argument("--output-dir", dest="output_dir", default=None, help="default report directory")
    setup.add_argument("--workers", type=int, default=None, help="default worker count")
    setup.add_argument("--rate", type=float, default=None, help="default rate limit (requests/second)")
    setup.add_argument("--timeout", type=float, default=None, help="default request timeout (seconds)")
    setup.add_argument("--retries", type=int, default=None, help="default retry count")
    setup.add_argument("--delay", type=float, default=None, help="default delay between requests (seconds)")
    setup.add_argument("--auto-html", action=argparse.BooleanOptionalAction, default=None, help="write HTML reports automatically")
    setup.add_argument("--deep", action=argparse.BooleanOptionalAction, default=None, help="enable deep mode by default")
    setup.add_argument("--oob-url", dest="oob_url", default=None, help="external OOB base URL")
    setup.add_argument("--template-dir", dest="template_dir", default=None, help="default YAML template directory")
    setup.add_argument("--user-agent", dest="user_agent", default=None, help="default User-Agent override")
    setup.add_argument("--cookie", default=None, help="default Cookie header value")
    setup.add_argument("--header", action="append", default=None, metavar="NAME: VALUE", help="default extra header, repeatable")
    setup.add_argument("--no-color", action="store_true", help="persist: disable colours in every run")

    diff_p = sub.add_parser("diff", help="compare two scan JSON reports (new / resolved / regressed)")
    diff_p.add_argument("old", help="previous scan JSON report")
    diff_p.add_argument("new", help="current scan JSON report")
    diff_p.add_argument("--json", dest="json_path", help="write the diff summary as JSON")
    diff_p.add_argument("--fail-on", dest="fail_on", choices=["new", "regressed", "any"], default=None,
                        help="exit 1 when the chosen class is non-empty - a CI gate")

    tpl = sub.add_parser("templates", help="list or validate YAML check templates")
    tpl.add_argument("action", nargs="?", choices=["list", "validate"], default="list", help="what to do (default: list)")
    tpl.add_argument("path", nargs="?", default=None, help="template file or directory (default: the built-in templates)")
    tpl.add_argument("--tags", default=None, help="list only templates carrying any of these tags (comma separated)")
    tpl.add_argument("--exclude-tags", dest="exclude_tags", default=None,
                     help="skip templates carrying any of these tags (comma separated)")
    tpl.add_argument("--severity", default=None, help="list only these severities (comma separated)")
    tpl.add_argument("--json", dest="as_json", action="store_true", help="print template metadata as JSON")

    oob_p = sub.add_parser("oob", help="run the out-of-band callback listener (blind SSRF / XXE proof)")
    oob_p.add_argument("--bind", default="127.0.0.1", help="address to bind (default 127.0.0.1)")
    oob_p.add_argument("--port", type=int, default=9999, help="port to bind (default 9999)")
    oob_p.add_argument("--advertise-host", dest="advertise_host", default="", help="hostname shown in generated callback URLs")
    oob_p.add_argument("--once", action="store_true", help="exit after the first callback arrives")

    mine_p = sub.add_parser("mine", help="discover hidden parameters on one URL (Param Miner approach)")
    mine_p.add_argument("url")
    mine_p.add_argument("--workers", type=int, default=8)
    mine_p.add_argument("--timeout", type=float, default=10.0)
    mine_p.add_argument("--json", dest="json_path", help="write findings as JSON")

    auth = sub.add_parser("authorize", help="compare two roles per URL - broken access control (Autorize workflow)")
    auth.add_argument("urls", nargs="+", help="URLs to test (test each with both roles)")
    auth.add_argument("--role", dest="roles", action="append", required=True,
                      help="role spec 'name=Header: value', repeatable; first role = privileged baseline, e.g. --role 'admin=Cookie: session=abc'")
    auth.add_argument("--timeout", type=float, default=10.0)
    auth.add_argument("--json", dest="json_path", help="write findings as JSON")

    fuzz_p = sub.add_parser("fuzz", help="brute-force paths, or fuzz payload positions in a raw request")
    fuzz_p.add_argument("url", nargs="?", help="target URL for directory mode")
    fuzz_p.add_argument("-w", "--wordlist", help="wordlist file, one entry per line (directory mode)")
    fuzz_p.add_argument("-t", "--threads", type=int, default=10, help="concurrent requests (default 10)")
    fuzz_p.add_argument("-e", "--extensions", default="", help="comma separated, e.g. php,html,bak (directory mode)")
    fuzz_p.add_argument("--request", dest="request_file",
                        help="raw request file with §positions§ - Intruder-style payload fuzzing")
    fuzz_p.add_argument("--payloads", default=None, help="payload list, comma separated (sniper mode)")
    fuzz_p.add_argument("--payload-file", dest="payload_files", action="append", default=None,
                        help="payload file, one entry per line; repeat - pitchfork mode pairs files with positions in order")
    fuzz_p.add_argument("--mode", choices=["sniper", "pitchfork"], default="sniper",
                        help="sniper: one position at a time (default); pitchfork: position i gets payload file i")
    fuzz_p.add_argument("--encoder", choices=["none", "url", "b64"], default="none", help="payload encoder (default none)")
    fuzz_p.add_argument("--json", dest="json_path", help="write fuzz results (requests + divergences) as JSON")
    fuzz_p.add_argument("--rate", type=float, default=None, help="max requests per second")
    fuzz_p.add_argument("--timeout", type=float, default=10.0)

    proxy_p = sub.add_parser("proxy", help="run the local intercepting proxy")
    proxy_p.add_argument("--bind", default="127.0.0.1")
    proxy_p.add_argument("--port", type=int, default=8080)
    proxy_p.add_argument("--db", default="summit_sitemap.db", help="sqlite site map path")
    proxy_p.add_argument("--tls-intercept", dest="tls_intercept", action="store_true",
                         help="decrypt HTTPS CONNECT tunnels with a locally generated CA (needs: pip install 'summit-scanner[proxy]')")
    proxy_p.add_argument("--ca-dir", dest="ca_dir", default=None,
                         help="directory for the generated proxy CA (default ~/.summit/proxy-ca)")

    sched = sub.add_parser(
        "schedule",
        help="run a scan on an interval and diff every round (cron-friendly); "
             "extra scan flags go after --, e.g.: summit schedule URL --every 900 --fail-on high -- --rate 5",
    )
    sched.add_argument("url")
    sched.add_argument("--every", type=float, default=3600.0, help="seconds between rounds (default 3600)")
    sched.add_argument("--times", type=int, default=0, help="rounds to run; 0 = keep going until Ctrl+C")
    sched.add_argument("--out-dir", dest="out_dir", default="summit-history",
                       help="directory for the per-round JSON reports (default summit-history)")
    sched.add_argument("--fail-on", dest="fail_on", choices=list(SEVERITIES), default=None,
                       help="exit 1 when a round reports a new or regressed finding at or above this severity")

    rep = sub.add_parser("repeater", help="send a raw HTTP request from a file (Burp-style)")
    rep.add_argument("file")
    rep.add_argument("--timeout", type=float, default=10.0)

    rec = sub.add_parser("recon", help="chain subfinder -> httpx -> nmap on a target")
    rec.add_argument("target", help="domain or URL, e.g. testsite.local")
    rec.add_argument("--timeout", type=float, default=120.0, help="per-tool timeout in seconds")
    rec.add_argument("--json", dest="json_path", help="write the recon report as JSON")

    enc = sub.add_parser("encode", help="encode text (b64, url, hex)")
    enc.add_argument("value")
    enc.add_argument("-f", "--format", dest="encoding", default="b64", choices=["b64", "url", "hex"])

    dec = sub.add_parser("decode", help="decode text (b64, url, hex, jwt)")
    dec.add_argument("value")
    dec.add_argument("-f", "--format", dest="encoding", default="b64", choices=["b64", "url", "hex", "jwt"])

    tls_p = sub.add_parser("tls", help="audit a host's certificate and TLS versions")
    tls_p.add_argument("host", help="hostname or URL")
    tls_p.add_argument("--port", type=int, default=443)
    tls_p.add_argument("--timeout", type=float, default=10.0)
    tls_p.add_argument("--json", dest="json_path", help="write findings as JSON")

    race_p = sub.add_parser("race", help="detect race conditions via concurrent identical requests")
    race_p.add_argument("url", help="target URL that performs a state change")
    race_p.add_argument("-n", "--concurrency", type=int, default=10, help="number of concurrent requests (default 10)")
    race_p.add_argument("--method", default="GET", help="HTTP method (default GET)")
    race_p.add_argument("--data", default=None, help="request body (for POST)")
    race_p.add_argument("--cookie", default=None, help="Cookie header value")
    race_p.add_argument("--timeout", type=float, default=10.0)
    race_p.add_argument("--json", dest="json_path", help="write findings as JSON")

    map_p = sub.add_parser("map", help="crawl a target and map pages, forms, tech and parameters")
    map_p.add_argument("url")
    map_p.add_argument("--depth", type=int, default=3)
    map_p.add_argument("--max-pages", type=int, default=50)
    map_p.add_argument("--timeout", type=float, default=10.0)
    map_p.add_argument("--json", dest="json_path", help="write the surface map as JSON")
    map_p.add_argument("--html", dest="html_path", help="write the surface map as HTML")
    map_p.add_argument("--markdown", dest="markdown_path", help="write the surface map as Markdown")
    map_p.add_argument("--progress", action=argparse.BooleanOptionalAction, default=None,
                      help="show the live crawl progress (default: on in a terminal, off when piped)")

    return parser


# ---------------------------------------------------------------------------
# severity filters (shared by scan)
# ---------------------------------------------------------------------------


def _severity_filters(args: argparse.Namespace):
    """Parse --severity / --min-severity into (allowed set, floor name)."""
    allowed = None
    if getattr(args, "severity", None):
        allowed = {token.strip().lower() for token in args.severity.split(",") if token.strip()}
        unknown = allowed - set(SEVERITIES)
        if unknown:
            print(colors.fail(f"unknown severity value(s): {', '.join(sorted(unknown))} - valid: {', '.join(SEVERITIES)}"))
            raise SystemExit(1)
    return allowed, getattr(args, "min_severity", None)


def _apply_severity_filters(findings, args: argparse.Namespace):
    allowed, minimum = _severity_filters(args)
    if allowed:
        findings = filter_by_severities(findings, allowed)
    if minimum:
        findings = filter_by_min_severity(findings, minimum)
    return findings


def _gate_hits(candidates: list[dict], fail_on: str) -> list[dict]:
    floor = SEVERITY_RANK.get(fail_on, 0)
    return [item for item in candidates if SEVERITY_RANK.get(item.get("severity", "info"), 0) >= floor]


def _apply_ci_gate(findings, args: argparse.Namespace) -> int:
    """Return 0 for pass, 1 for a failed gate, 2 for an unusable baseline."""
    fail_on = getattr(args, "fail_on", None)
    baseline_path = getattr(args, "baseline_path", None)
    if not fail_on and not baseline_path:
        return 0
    if baseline_path and getattr(args, "json_path", None):
        try:
            same_file = Path(baseline_path).resolve() == Path(args.json_path).resolve()
        except OSError:
            same_file = False
        if same_file:
            print(colors.fail("--baseline and --json point at the same file; use a separate baseline path"))
            return 2

    current = [finding.as_dict() for finding in findings]
    candidates = current
    scope = "reported"
    if baseline_path:
        try:
            baseline = load_findings(baseline_path)
        except (OSError, ValueError) as exc:
            print(colors.fail(f"baseline unavailable: {baseline_path}: {exc}"))
            return 2
        diff = diff_finding_lists(baseline, current)
        candidates = diff.new + diff.regressed
        scope = "new or regressed"
        print(colors.header("Baseline comparison", 70))
        print(f"  new: {len(diff.new)}  regressed: {len(diff.regressed)}  "
              f"resolved: {len(diff.resolved)}  unchanged: {len(diff.unchanged)}")

    if not fail_on:
        return 0

    hits = _gate_hits(candidates, fail_on)
    if not hits:
        print(colors.ok(f"CI gate passed: no {scope} finding at or above {fail_on}"))
        return 0

    print(colors.fail(f"CI gate failed: {len(hits)} {scope} finding(s) at or above {fail_on}"))
    for hit in hits[:5]:
        print(f"  [{hit.get('severity', '?').upper()}] {hit.get('title', '?')} - {hit.get('url', '?')}")
    if len(hits) > 5:
        print(f"  ... and {len(hits) - 5} more")
    return 1


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _split_csv(value: str | None) -> set[str]:
    return {token.strip().lower() for token in (value or "").split(",") if token.strip()}


def _template_matches(template, tags: set[str], exclude_tags: set[str], severities: set[str]) -> bool:
    template_tags = {tag.lower() for tag in template.tags}
    if tags and not (template_tags & tags):
        return False
    if exclude_tags and (template_tags & exclude_tags):
        return False
    if severities and template.severity.lower() not in severities:
        return False
    return True


def _run_templates(
    args: argparse.Namespace,
    settings: Settings,
    engine: ScanEngine,
    client: HttpClient,
    result: dict,
    progress: ProgressReporter | None = None,
) -> None:
    """Run the built-in YAML templates, plus any custom ones the user points at."""
    if getattr(args, "no_templates", False):
        return
    # Templates send active probes; a passive-only scan must stay traffic-free.
    if getattr(args, "no_active", False):
        return
    include_tags = _split_csv(getattr(args, "template_tags", None))
    exclude_tags = _split_csv(getattr(args, "template_exclude_tags", None))
    severities = _split_csv(getattr(args, "template_severity", None))
    from .templates import TemplateError, load_template, run_template, validate_template

    builtin_dir = Path(__file__).resolve().parent / "templates" / "builtin"
    files = sorted(builtin_dir.glob("*.yaml"))

    templates_path = args.templates_path or settings.template_dir
    if templates_path:
        target = Path(templates_path).expanduser()
        if target.is_dir():
            custom_files = sorted(target.glob("*.yaml"))
            if not custom_files:
                print(colors.warn(f"no .yaml templates found in {target}"))
            files.extend(custom_files)
        elif target.is_file():
            files.append(target)
        else:
            print(colors.warn(f"templates path not found: {templates_path}"))
    # A file passed explicitly may live in the builtin directory - run it once.
    files = list(dict.fromkeys(files))

    base_url = args.url or next((response.request.url for response in result.get("pages", [])), "")
    if not base_url:
        print(colors.warn("no target URL available for template requests - skipping templates"))
        return

    selected = []
    for file in files:
        try:
            template = load_template(str(file))
        except TemplateError as exc:
            print(colors.warn(str(exc)))
            continue
        if not _template_matches(template, include_tags, exclude_tags, severities):
            continue
        errors = validate_template(str(file))
        if errors:
            for error in errors:
                print(colors.warn(error))
            continue
        selected.append(template)

    if progress is not None:
        progress.phase("TEMPLATES", len(selected))

    ran = 0
    executed = 0
    for template in selected:
        if progress is not None:
            progress.task(template.id, "RUN", base_url)
            before = len(engine.findings)

            def _on_template_request(method: str, url: str, template_id: str = template.id) -> None:
                progress.event(template_id, method, url)

            findings = run_template(template, client, base_url, on_request=_on_template_request)
        else:
            findings = run_template(template, client, base_url)
        for finding in findings:
            engine.add(finding)
            ran += 1
        executed += 1
        if progress is not None:
            produced = len(engine.findings) - before
            if produced > 0:
                progress.hit(produced)

    summary = f"ran {executed} template(s) - {ran} finding(s)"
    if progress is not None:
        progress.finish()
    _phase("TEMPLATES", summary)


def _cmd_scan(args: argparse.Namespace, settings: Settings) -> int:
    global _SILENT, _PROGRESS
    _SILENT = bool(getattr(args, "silent", False))
    if not args.url and not args.openapi_path:
        print(colors.fail("scan needs a target URL (or --openapi PATH)"))
        return 2
    _banner()

    progress_choice = getattr(args, "progress", None)
    progress_enabled = not _SILENT and (
        sys.stderr.isatty() if progress_choice is None else bool(progress_choice)
    )
    progress = ProgressReporter(enabled=progress_enabled)
    _PROGRESS = progress

    # --- merge flags with saved settings; deep mode raises crawl defaults ---
    deep = settings.deep if args.deep is None else args.deep
    workers = settings.workers if args.workers is None else args.workers
    depth = args.depth if args.depth is not None else (5 if deep else 3)
    max_pages = args.max_pages if args.max_pages is not None else (200 if deep else 50)
    retries = settings.retries if args.retries is None else args.retries
    timeout = settings.timeout if args.timeout is None else args.timeout
    delay = settings.delay if args.delay is None else args.delay
    rate = settings.rate if args.rate is None else args.rate
    if deep:
        workers = max(workers, 12)
        retries = max(retries, 2)

    user_agent = args.user_agent or settings.user_agent or None
    client = HttpClient(timeout=timeout, delay=delay, rate=rate, retries=retries, user_agent=user_agent)
    headers = settings.effective_headers()
    for item in args.header or []:
        if ":" not in item:
            print(colors.warn(f"ignoring malformed --header (expected 'Name: value'): {item}"))
            continue
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie
    if headers:
        client.session.headers.update(headers)

    scan_started = time.monotonic()

    if args.openapi_path:
        progress.phase("RECON")
        spec = load_spec(args.openapi_path)
        result = spec_pages(client, spec)
        progress.finish()
        _phase("RECON", f"openapi spec loaded: {len(result['pages'])} target(s), {len(result['errors'])} error(s)")
    else:
        progress.phase("RECON", max_pages)
        spider = Spider(
            client,
            max_depth=depth,
            max_pages=max_pages,
            delay=delay,
            on_page=lambda url: progress.event("crawl", "GET", url),
        )
        _phase("RECON", f"crawling {colors.bold(args.url)} (depth={depth}, max_pages={max_pages}) ...")
        result = spider.crawl(args.url)
        progress.finish()
        _phase("RECON", f"visited {len(result['visited'])} page(s), {len(result['forms'])} form(s), "
                        f"{len(result['external_links'])} outbound link(s), {len(result['errors'])} request error(s)")
    _phase("RECON", f"completed in {_fmt_duration(time.monotonic() - scan_started)}")
    for error in result.get("errors", [])[:5]:
        _log(colors.warn(str(error)))

    if args.render:
        from .crawl.render import RenderUnavailable, render_pages

        urls = [response.request.url for response in result.get("pages", [])]
        try:
            rendered = render_pages(urls)
            result.setdefault("pages", []).extend(rendered)
            _phase("RECON", f"headless render: {len(rendered)} page(s) materialized with JavaScript")
        except RenderUnavailable as exc:
            print(colors.warn(str(exc)))

    # --- out-of-band listener (blind SSRF gets a real confirmation channel) ---
    oob_server = None
    oob_check = None
    if args.oob_listen is not None:
        oob_server = OobServer(bind=args.oob_bind, port=args.oob_listen, advertise_host=args.oob_advertise)
        try:
            base = oob_server.start()
        except OSError as exc:
            progress.close()
            _PROGRESS = None
            print(colors.fail(f"could not start OOB listener on {args.oob_bind}:{args.oob_listen}: {exc}"))
            return 2
        _phase("INIT", f"OOB listener up on {colors.url_text(base)} - blind findings fire only on a real callback")
        oob_check = SsrfCheck(
            callback_base=base,
            hit_checker=lambda token: oob_server.wait_for(token, timeout=2.0) is not None,
        )
    elif args.oob_url or settings.oob_url:
        print(colors.warn("external OOB URL set: callbacks over it cannot be auto-verified, so the SSRF check stays off "
                          "(use --oob-listen for confirmed results)"))

    try:
        vuln_started = time.monotonic()
        engine = ScanEngine(
            client,
            active=not args.no_active,
            workers=workers,
            linkcheck_enabled=not args.skip_linkcheck,
            deep=deep,
            takeover=not args.no_takeover,
            oob_check=oob_check,
            oob_callback_base=oob_server.base_url if oob_server else "",
            oob_raw_base=oob_server.raw_base if oob_server else "",
            oob_hit_checker=(
                (lambda token: oob_server.wait_for(token, timeout=2.0) is not None)
                if oob_server else None
            ),
            progress=progress,
        )
        _phase("SCAN", f"running passive + active checks (workers={workers}{', deep mode' if deep else ''}) ...")
        engine.scan(result)
        _phase("SCAN", f"completed in {_fmt_duration(time.monotonic() - vuln_started)} - {len(engine.findings)} raw finding(s)")

        _run_templates(args, settings, engine, client, result, progress=progress)

        findings = _apply_severity_filters(engine.findings, args)
        total_elapsed = time.monotonic() - scan_started
        _phase("DONE", f"{client.request_count} request(s) in {_fmt_duration(total_elapsed)} "
                       f"(workers={workers}, rate={rate or 'unlimited'}, retries={retries})")
        _phase("DONE", f"smart order: {engine.high_signal} high-signal injection point(s) probed first")

        for error in engine.errors[:5]:
            print(colors.fail(f"check error: {error}"))
        target_label = args.url or args.openapi_path or "scan"
        print(write_console(findings, target_label))

        html_path = args.html_path
        auto_html = settings.auto_html if args.auto_html is None else args.auto_html
        if not html_path and auto_html:
            html_path = _auto_html_path(settings, args.url or "")

        if args.json_path:
            write_json(findings, args.json_path)
            _log("  " + colors.ok(f"JSON report written to {args.json_path}"))
        if html_path:
            write_html(findings, html_path, target_label)
            _log("  " + colors.ok(f"HTML report written to {html_path}"))
        if getattr(args, "sarif_path", None):
            from .report.sarif import write_sarif

            write_sarif(findings, args.sarif_path)
            _log("  " + colors.ok(f"SARIF report written to {args.sarif_path} (GitHub code scanning compatible)"))
        if getattr(args, "junit_path", None):
            from .report.sarif import write_junit

            write_junit(findings, args.junit_path)
            _log("  " + colors.ok(f"JUnit XML report written to {args.junit_path}"))
        if getattr(args, "markdown_path", None):
            write_markdown(findings, args.markdown_path, target_label)
            _log("  " + colors.ok(f"Markdown report written to {args.markdown_path}"))
        return _apply_ci_gate(findings, args)
    finally:
        if _PROGRESS is not None:
            _PROGRESS.close()
            _PROGRESS = None
        if oob_server is not None:
            oob_server.stop()


def _auto_html_path(settings: Settings, url: str) -> str:
    from datetime import datetime
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or "scan"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(settings.output_dir or "summit-reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    return str(out_dir / f"summit-{host}-{stamp}.html")


# ---------------------------------------------------------------------------
# setup wizard
# ---------------------------------------------------------------------------


def _ask(prompt: str, current: str) -> str:
    shown = current or "none"
    try:
        answer = input(f"  {colors.cyan('?')} {prompt} [{colors.gray(shown)}]: ").strip()
    except EOFError:
        return current
    if not answer:
        return current
    if answer.lower() == "none":
        return ""
    return answer


def _ask_int(prompt: str, current: int, minimum: int = 1) -> int:
    answer = _ask(prompt, str(current))
    try:
        return max(minimum, int(answer))
    except ValueError:
        print(colors.warn(f"not a number - keeping {current}"))
        return current


def _ask_float(prompt: str, current: float, minimum: float = 0.0) -> float:
    answer = _ask(prompt, str(current))
    try:
        return max(minimum, float(answer))
    except ValueError:
        print(colors.warn(f"not a number - keeping {current}"))
        return current


def _ask_optional_float(prompt: str, current: float | None) -> float | None:
    shown = "unlimited" if current is None else str(current)
    answer = _ask(prompt, shown)
    if answer.lower() in ("unlimited", "none", "-", "0", "0.0"):
        return None
    try:
        return float(answer)
    except ValueError:
        print(colors.warn(f"not a number - keeping {shown}"))
        return current


def _ask_bool(prompt: str, current: bool) -> bool:
    marker = "Y/n" if current else "y/N"
    try:
        answer = input(f"  {colors.cyan('?')} {prompt} [{colors.gray(marker)}]: ").strip().lower()
    except EOFError:
        return current
    if not answer:
        return current
    return answer in ("y", "yes", "true", "1")


def _cmd_setup(args: argparse.Namespace, settings: Settings) -> int:
    path = default_config_path()
    if args.show:
        _banner(compact=True)
        print(colors.header("summit settings", 70))
        print(colors.kv_table([
            ("output_dir", settings.output_dir),
            ("workers", str(settings.workers)),
            ("rate", "unlimited" if settings.rate is None else str(settings.rate)),
            ("timeout", f"{settings.timeout}s"),
            ("retries", str(settings.retries)),
            ("delay", f"{settings.delay}s"),
            ("auto_html", "on" if settings.auto_html else "off"),
            ("deep", "on" if settings.deep else "off"),
            ("oob_url", settings.oob_url or "-"),
            ("template_dir", settings.template_dir or "-"),
            ("user_agent", settings.user_agent or "-"),
            ("cookie", "set" if settings.cookie else "-"),
            ("headers", ", ".join(settings.headers) or "-"),
            ("no_color", "on" if settings.no_color else "off"),
        ]))
        print()
        print(f"  {colors.gray('config file:')} {path}")
        return 0
    if args.reset:
        try:
            path.unlink()
            print(colors.ok(f"config removed: {path}"))
        except FileNotFoundError:
            print(colors.warn(f"no config file to remove at {path}"))
        return 0

    _banner()
    if args.output_dir is not None:
        settings.output_dir = args.output_dir
    if args.workers is not None:
        settings.workers = max(1, args.workers)
    if args.rate is not None:
        settings.rate = args.rate
    if args.timeout is not None:
        settings.timeout = args.timeout
    if args.retries is not None:
        settings.retries = max(0, args.retries)
    if args.delay is not None:
        settings.delay = args.delay
    if args.auto_html is not None:
        settings.auto_html = args.auto_html
    if args.deep is not None:
        settings.deep = args.deep
    if args.oob_url is not None:
        settings.oob_url = args.oob_url
    if args.template_dir is not None:
        settings.template_dir = args.template_dir
    if args.user_agent is not None:
        settings.user_agent = args.user_agent
    if args.cookie is not None:
        settings.cookie = args.cookie
    if args.no_color:
        settings.no_color = True
    for item in args.header or []:
        if ":" not in item:
            print(colors.warn(f"ignoring malformed --header (expected 'Name: value'): {item}"))
            continue
        name, value = item.split(":", 1)
        settings.headers[name.strip()] = value.strip()

    if args.yes or not sys.stdin.isatty():
        if not args.yes:
            print(colors.warn("stdin is not a terminal - saving current values (use --yes in scripts)"))
    else:
        print(colors.header("setup wizard - press Enter to keep the value in brackets", 70))
        print()
        settings.output_dir = _ask("report directory", settings.output_dir)
        settings.workers = _ask_int("parallel workers", settings.workers)
        settings.rate = _ask_optional_float("rate limit, requests/second (write 'unlimited' for no ceiling)", settings.rate)
        settings.timeout = _ask_float("request timeout (seconds)", settings.timeout, minimum=0.5)
        settings.retries = _ask_int("retries per request", settings.retries, minimum=0)
        settings.delay = _ask_float("delay between requests (seconds)", settings.delay)
        settings.auto_html = _ask_bool("write an HTML report automatically after scans", settings.auto_html)
        settings.deep = _ask_bool("enable deep mode (extended payload sets) by default", settings.deep)
        settings.oob_url = _ask("external OOB base URL (blank = none)", settings.oob_url)
        settings.template_dir = _ask("YAML template directory (blank = built-ins only)", settings.template_dir)
        settings.no_color = _ask_bool("disable colours", settings.no_color)
        print()

    saved = save_settings(resolve_paths(settings))
    print(colors.ok(f"settings saved to {saved}"))
    print(f"  {colors.gray('every command reads this file; per-run flags still override it.')}")
    return 0


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def _cmd_diff(args: argparse.Namespace) -> int:
    _banner(compact=True)
    try:
        result = diff_reports(args.old, args.new)
    except (OSError, ValueError) as exc:
        print(colors.fail(f"could not read reports: {exc}"))
        return 1

    lines: list[str] = []
    if result.new:
        lines.append("")
        lines.append(f"  {colors.bold('NEW findings')} ({len(result.new)})")
        for finding in result.new:
            badge = colors.severity_badge(finding.get('severity', 'info'))
            title = finding.get('title', '?')
            url = colors.url_text(finding.get('url', '?'))
            lines.append(f"    {badge} {title} - {url}")
    if result.resolved:
        lines.append("")
        lines.append(f"  {colors.bold('RESOLVED findings')} ({len(result.resolved)})")
        for finding in result.resolved:
            lines.append("    " + colors.ok(f"{finding.get('title', '?')} - {finding.get('url', '?')}"))
    if result.regressed:
        lines.append("")
        lines.append(f"  {colors.bold('REGRESSED findings')} ({len(result.regressed)})")
        for finding in result.regressed:
            badge = colors.severity_badge(finding.get('severity', 'info'))
            title = finding.get('title', '?')
            url = colors.url_text(finding.get('url', '?'))
            lines.append(f"    {badge} {title} - {url}")
    if not (result.new or result.resolved or result.regressed):
        lines.append("")
        lines.append("  " + colors.ok("No changes between scans."))
    lines.append("")
    lines.append(colors.header("summary", 70))
    summary = (
        f"  {len(result.new)} new  ·  {len(result.resolved)} resolved  ·  "
        f"{len(result.regressed)} regressed  ·  {len(result.unchanged)} unchanged"
    )
    lines.append(summary)
    print("\n".join(lines))

    if args.json_path:
        payload = {
            "new": result.new,
            "resolved": result.resolved,
            "regressed": result.regressed,
            "unchanged_count": len(result.unchanged),
        }
        Path(args.json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print("  " + colors.ok(f"diff written to {args.json_path}"))

    failed = (
        (args.fail_on == "any" and (result.new or result.regressed))
        or (args.fail_on == "new" and result.new)
        or (args.fail_on == "regressed" and result.regressed)
    )
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------


def _cmd_templates(args: argparse.Namespace) -> int:
    from .templates import TemplateError, load_template, load_templates, validate_template

    target = Path(args.path).expanduser() if args.path else Path(__file__).resolve().parent / "templates" / "builtin"
    if not target.exists():
        print(colors.fail(f"path not found: {target}"))
        return 1

    if args.action == "validate":
        files = sorted(target.glob("*.yaml")) if target.is_dir() else [target]
        if not files:
            print(colors.warn(f"no .yaml templates found in {target}"))
            return 1
        failures = 0
        for file in files:
            errors = validate_template(str(file))
            if errors:
                failures += 1
                print(colors.fail(f"{file.name}"))
                for error in errors:
                    print(f"    {colors.gray(error)}")
            else:
                print(colors.ok(file.name))
        if failures:
            print(colors.fail(f"{failures} of {len(files)} template(s) failed validation"))
            return 1
        print(colors.ok(f"all {len(files)} template(s) valid"))
        return 0

    try:
        templates = load_templates(str(target)) if target.is_dir() else [load_template(str(target))]
    except TemplateError as exc:
        print(colors.fail(str(exc)))
        return 1
    if args.action == "list":
        tags = _split_csv(getattr(args, "tags", None))
        exclude_tags = _split_csv(getattr(args, "exclude_tags", None))
        severities = _split_csv(getattr(args, "severity", None))
        templates = [
            template for template in templates
            if _template_matches(template, tags, exclude_tags, severities)
        ]
    if getattr(args, "as_json", False):
        payload = [
            {
                "id": template.id,
                "name": template.name,
                "severity": template.severity,
                "confidence": template.confidence,
                "tags": template.tags,
                "cwe": template.cwe,
                "cve": template.cve,
                "path": template.path,
            }
            for template in templates
        ]
        print(json.dumps(payload, indent=2))
        return 0
    print(colors.header(f"templates ({len(templates)})", 70))
    if not templates:
        print(colors.warn("no templates matched the filters"))
        return 0
    for template in templates:
        print(f"  {colors.severity_badge(template.severity)} {colors.bold(template.name)}")
        print(f"    {colors.check_tag(template.id)}  ·  confidence: {colors.confidence_tag(template.confidence)}")
        print(f"    {colors.gray(Path(template.path).name)}")
    return 0


# ---------------------------------------------------------------------------
# oob listener
# ---------------------------------------------------------------------------


def _cmd_oob(args: argparse.Namespace) -> int:
    _banner()
    server = OobServer(bind=args.bind, port=args.port, advertise_host=args.advertise_host)
    try:
        base = server.start()
    except OSError as exc:
        print(colors.fail(f"could not bind {args.bind}:{args.port}: {exc}"))
        return 1

    print(colors.box("summit oob", [
        f"listening on {colors.bold(base)}",
        f"point payloads at {colors.url_text(base + '/<token>')}",
        f"JNDI/LDAP callbacks on {colors.bold(server.raw_base)} (Log4Shell)",
        colors.gray("Ctrl+C to stop" if not args.once else "will exit after the first callback"),
    ]))
    print()

    seen_count = 0
    try:
        while True:
            hits = server.hits
            if len(hits) > seen_count:
                for hit in hits[seen_count:]:
                    print("  " + colors.ok(hit.summary()))
                seen_count = len(hits)
                if args.once:
                    break
            time.sleep(0.25)
    except KeyboardInterrupt:
        print()
    finally:
        server.stop()
    print(colors.gray("listener stopped"))
    return 0


# ---------------------------------------------------------------------------
# versioning commands
# ---------------------------------------------------------------------------


def _cmd_check_update() -> int:
    _banner(compact=True)
    latest = fetch_latest_version()
    if latest is None:
        print(colors.fail("could not reach the GitHub release API (offline or rate-limited)"))
        return 1
    if is_outdated(__version__, latest):
        print(colors.warn(f"update available: {__version__} -> {latest}"))
        print(colors.gray("run: summit --auto-update"))
    else:
        print(colors.ok(f"summit {__version__} is up to date (latest release: {latest})"))
    return 0


def _cmd_auto_update() -> int:
    _banner(compact=True)
    ok, message = self_update()
    print(colors.ok(message) if ok else colors.fail(message))
    return 0 if ok else 1


def _cmd_install_tools() -> int:
    _banner(compact=True)
    install_tools()
    return 0


# ---------------------------------------------------------------------------
# scan-adjacent commands
# ---------------------------------------------------------------------------


def _cmd_mine(args: argparse.Namespace) -> int:
    global _SILENT
    _SILENT = getattr(args, "silent", False)
    _banner()
    client = HttpClient(timeout=args.timeout)
    started = time.monotonic()
    _phase("MINE", f"mining hidden parameters on {colors.bold(args.url)} (~120 candidates) ...")
    findings = mine(client, args.url, workers=args.workers)
    _log("  " + colors.ok(f"mining completed in {_fmt_duration(time.monotonic() - started)} - {len(findings)} discovery(ies)"))
    print(write_console(findings, args.url))
    if args.json_path:
        write_json(findings, args.json_path)
        _log("  " + colors.ok(f"JSON report written to {args.json_path}"))
    return 0


def _cmd_authorize(args: argparse.Namespace) -> int:
    _banner()
    client = HttpClient(timeout=args.timeout)
    try:
        roles = [parse_role(spec) for spec in args.roles]
    except ValueError as exc:
        print(colors.fail(str(exc)))
        return 1
    if len(roles) < 2:
        print(colors.fail("authorize needs at least two roles - first is the privileged baseline"))
        return 1
    privileged, other = roles[0], roles[1]
    started = time.monotonic()
    _phase("AUTHORIZE", f"testing {len(args.urls)} URL(s): '{privileged.name}' vs '{other.name}'")
    results = run_authorize(client, args.urls, privileged, other)
    _log("  " + colors.ok(f"completed in {_fmt_duration(time.monotonic() - started)}"))
    for result in results:
        if result.verdict == "broken":
            verdict = colors.red("BROKEN")
        elif result.verdict == "enforced":
            verdict = colors.green("ENFORCED")
        else:
            verdict = colors.yellow(result.verdict.upper())
        print(f"  [{verdict}] {result.url}")
        if result.verdict == "broken":
            print(colors.gray(f"      {other.name} sees exactly what {privileged.name} sees "
                              f"(HTTP {result.privileged.status}, {len(result.privileged.body)}B)"))
    findings = findings_from(results)
    print(write_console(findings, f"{len(args.urls)} URL(s), {privileged.name} vs {other.name}"))
    if args.json_path:
        write_json(findings, args.json_path)
        _log("  " + colors.ok(f"JSON report written to {args.json_path}"))
    return 0


def _cmd_recon(args: argparse.Namespace) -> int:
    _banner()
    started = time.monotonic()
    missing = missing_tools()
    if missing:
        print(colors.warn(f"tools not on PATH: {', '.join(missing)} - install them with: summit --install-tools"))
        print(colors.gray("continuing with the tools that ARE available ...\n"))
    try:
        report = run_recon(args.target, timeout=args.timeout)
    except Exception as exc:
        print(colors.fail(f"recon failed: {exc}"))
        return 1
    _log("  " + colors.ok(f"recon completed in {_fmt_duration(time.monotonic() - started)}"))
    print(render_report(report))
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print()
        print("  " + colors.ok(f"JSON report written to {args.json_path}"))
    return 0


def _cmd_tls(args: argparse.Namespace) -> int:
    _banner()
    started = time.monotonic()
    try:
        findings = tls_audit(args.host, port=args.port, timeout=args.timeout)
    except ConnectionError as exc:
        print(colors.fail(str(exc)))
        return 1
    _log("  " + colors.ok(f"TLS audit completed in {_fmt_duration(time.monotonic() - started)}"))
    print(write_console(findings, f"{args.host}:{args.port}"))
    if not findings:
        print(colors.ok("no TLS findings - certificate valid, no legacy protocol versions accepted"))
    if args.json_path:
        write_json(findings, args.json_path)
        print("  " + colors.ok(f"JSON report written to {args.json_path}"))
    return 0


def _cmd_race(args: argparse.Namespace) -> int:
    _banner()
    client = HttpClient(timeout=args.timeout)
    headers = {"Cookie": args.cookie} if args.cookie else {}
    started = time.monotonic()
    _phase("RACE", f"testing {colors.bold(args.url)} with {args.concurrency} concurrent {args.method} requests ...")
    result = run_race_test(
        client, args.url, concurrency=args.concurrency, method=args.method,
        body=args.data.encode() if args.data else None, headers=headers,
    )
    _log("  " + colors.ok(f"race test completed in {_fmt_duration(time.monotonic() - started)}"))
    print(f"  {colors.gray('baseline:')} HTTP {result.baseline.status}/{len(result.baseline.body)}B")
    print(f"  {colors.gray('concurrent:')} {len(result.concurrent)} responses, {result.unique_responses} unique")
    findings = race_findings_from([result])
    print(write_console(findings, args.url))
    if args.json_path:
        write_json(findings, args.json_path)
        print("  " + colors.ok(f"JSON report written to {args.json_path}"))
    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    global _SILENT
    _SILENT = getattr(args, "silent", False)
    _banner(compact=True)
    client = HttpClient(timeout=args.timeout, rate=args.rate)

    if args.request_file or args.payloads or args.payload_files:
        return _cmd_fuzz_intruder(args, client)

    if not args.url:
        print(colors.fail("fuzz needs a target URL (or --request FILE for payload fuzzing)"))
        return 2
    wordlist = None
    if args.wordlist:
        wordlist = [line.strip() for line in Path(args.wordlist).read_text(encoding="utf-8").splitlines() if line.strip()]
    extensions = [ext.strip().lstrip(".") for ext in args.extensions.split(",") if ext.strip()]
    started = time.monotonic()
    findings = fuzz(client, args.url, wordlist=wordlist, threads=args.threads, extensions=extensions)
    _log("  " + colors.ok(f"fuzz completed in {_fmt_duration(time.monotonic() - started)} - {len(findings)} path(s) found"))
    print(write_console(findings, args.url))
    return 0


def _load_payload_list(source: str) -> list[str]:
    """A CSV list or a file path - one payload per line if the file exists."""
    path = Path(source)
    if path.exists():
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [token for token in (item.strip() for item in source.split(",")) if token]


def _cmd_fuzz_intruder(args: argparse.Namespace, client: HttpClient) -> int:
    global _SILENT
    if not args.request_file:
        print(colors.fail("payload fuzzing needs a raw request file: --request FILE (mark spots with §positions§)"))
        return 2
    try:
        raw = Path(args.request_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(colors.fail(f"could not read request file: {exc}"))
        return 2

    try:
        if args.mode == "pitchfork":
            if not args.payload_files:
                print(colors.fail("pitchfork mode needs one --payload-file per position, in order"))
                return 2
            payload_sets = [_load_payload_list(source) for source in args.payload_files]
            result = run_intruder(
                client, raw, payload_sets=payload_sets, mode="pitchfork",
                encoder=args.encoder, threads=args.threads,
            )
        else:
            payloads = _load_payload_list(args.payloads or "")
            if not payloads and args.payload_files:
                payloads = _load_payload_list(args.payload_files[0])
            if not payloads:
                print(colors.fail("no payloads given - use --payloads 'a,b,c' or --payload-file FILE"))
                return 2
            result = run_intruder(
                client, raw, payloads=payloads, mode="sniper",
                encoder=args.encoder, threads=args.threads,
            )
    except (OSError, ValueError) as exc:
        print(colors.fail(str(exc)))
        return 2

    started_note = f"mode={args.mode}, encoder={args.encoder}, {len(result.hits)} request(s)"
    _log("  " + colors.ok(f"payload fuzz completed - {started_note}"))
    control = result.control
    if control is not None:
        print(f"  {colors.gray('control:')} HTTP {control.status} · {len(control.body)} bytes")
    else:
        print(colors.warn("  control request failed - every probe counts as divergent"))

    divergent = 0
    for hit in result.hits:
        if hit.response is None:
            marker = colors.fail("no response")
        elif hit.divergent:
            marker = colors.warn("DIVERGENT")
            divergent += 1
        else:
            marker = colors.ok("matches control")
        payload_text = ", ".join(hit.payloads) or "(empty)"
        if hit.response is not None:
            shape = f"HTTP {hit.response.status} · {len(hit.response.body)} bytes"
        else:
            shape = "unreachable"
        print(f"  [{payload_text}] {shape} - {marker}")
    print()
    print(f"  {len(result.hits)} request(s), {colors.bold(str(divergent))} divergent from the control")

    findings = intruder_findings_from(result)
    if findings:
        print(write_console(findings, args.request_file))
    if args.json_path:
        payload = {
            "control": None if control is None else {"status": control.status, "bytes": len(control.body)},
            "requests": [
                {
                    "payloads": list(hit.payloads),
                    "status": None if hit.response is None else hit.response.status,
                    "bytes": None if hit.response is None else len(hit.response.body),
                    "divergent": hit.divergent,
                    "url": hit.request.url,
                }
                for hit in result.hits
            ],
        }
        Path(args.json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _log("  " + colors.ok(f"fuzz results written to {args.json_path}"))
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    _banner()
    server = ProxyServer(host=args.bind, port=args.port, db_path=args.db,
                         tls_intercept=getattr(args, "tls_intercept", False),
                         ca_dir=getattr(args, "ca_dir", None))
    print(colors.gray(f"  starting proxy on {args.bind}:{args.port} (site map: {args.db}) - Ctrl+C to stop"))
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n" + colors.gray("shutting down"))
        server.stop()
        return 0
    except RuntimeError as exc:  # includes CaUnavailable from the optional dependency
        print(colors.fail(str(exc)))
        return 2
    return 0


def _cmd_schedule(args: argparse.Namespace) -> int:
    global _SILENT
    _SILENT = getattr(args, "silent", False)
    _banner(compact=True)
    scan_args = list(args.scan_args or [])
    if scan_args and scan_args[0] == "--":
        scan_args = scan_args[1:]
    _phase("SCHEDULE", f"monitoring {colors.bold(args.url)} - every {args.every:.0f}s"
                       f"{f', {args.times} round(s)' if args.times > 0 else ', until Ctrl+C'}"
                       + (f", gate on {args.fail_on}" if args.fail_on else ""))
    from .schedule import run_schedule

    return run_schedule(
        args.url,
        every=args.every,
        times=args.times,
        out_dir=args.out_dir,
        fail_on=args.fail_on,
        scan_args=scan_args,
    )


def _cmd_repeater(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_text(encoding="utf-8")
    request = HttpRequest.from_raw(raw)
    client = HttpClient(timeout=args.timeout)
    print(f"  {colors.cyan('▸')} sending {colors.bold(request.method)} {colors.url_text(request.url)}")
    response = client.send(request)
    print(colors.bold(f"HTTP {response.status}") + colors.gray(f" ({response.elapsed:.2f}s)"))
    for key, value in response.headers.items():
        print(f"{key}: {value}")
    print()
    print(response.text[:5000])
    return 0


def _cmd_map(args: argparse.Namespace) -> int:
    global _SILENT, _PROGRESS
    _SILENT = getattr(args, "silent", False)
    _banner(compact=True)
    from .map import map_target, write_map_html, write_map_json, write_map_markdown

    progress_choice = getattr(args, "progress", None)
    progress_enabled = not _SILENT and (
        sys.stderr.isatty() if progress_choice is None else bool(progress_choice)
    )
    progress = ProgressReporter(enabled=progress_enabled)
    _PROGRESS = progress

    client = HttpClient(timeout=args.timeout)
    started = time.monotonic()
    _phase("MAP", f"crawling {colors.bold(args.url)} (depth={args.depth}, max_pages={args.max_pages}) ...")
    try:
        surface = map_target(
            client,
            args.url,
            max_depth=args.depth,
            max_pages=args.max_pages,
            on_page=lambda url: progress.event("crawl", "GET", url),
        )
    except ValueError as exc:
        print(colors.fail(str(exc)))
        return 2
    finally:
        progress.finish()
        _PROGRESS = None

    summary = surface["summary"]
    _phase(
        "MAP",
        f"completed in {_fmt_duration(time.monotonic() - started)} - "
        f"{summary['pages']} page(s), {summary['forms']} form(s), "
        f"{summary['injection_points']} injection point(s), {summary['technologies']} tech item(s)",
    )
    for error in surface.get("errors", [])[:5]:
        _log(colors.warn(f"crawl error: {error}"))

    if args.json_path:
        write_map_json(surface, args.json_path)
        _log("  " + colors.ok(f"JSON surface map written to {args.json_path}"))
    if args.html_path:
        write_map_html(surface, args.html_path)
        _log("  " + colors.ok(f"HTML surface map written to {args.html_path}"))
    if args.markdown_path:
        write_map_markdown(surface, args.markdown_path)
        _log("  " + colors.ok(f"Markdown surface map written to {args.markdown_path}"))
    return 0


def _cmd_encode(args: argparse.Namespace) -> int:
    try:
        print(encode_text(args.value, args.encoding))
    except ValueError as exc:
        print(colors.fail(str(exc)))
        return 1
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    try:
        print(decode_text(args.value, args.encoding))
    except ValueError as exc:
        print(colors.fail(str(exc)))
        return 1
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    _reconfigure_stdio()
    if _has_flag(argv, "--no-color"):
        colors.set_enabled(False)
    parser = build_parser()
    raw = list(argv) if argv is not None else sys.argv[1:]
    # `schedule` passes everything after a bare -- straight to summit scan.
    # argparse cannot express that (a REMAINDER positional would swallow the
    # schedule flags too), so the split happens before parsing.
    passthrough: list[str] = []
    if "schedule" in raw and "--" in raw:
        split_at = raw.index("--")
        passthrough = raw[split_at + 1:]
        raw = raw[:split_at]
    args = parser.parse_args(raw)
    args.scan_args = passthrough
    global _SILENT
    _SILENT = getattr(args, "silent", False)
    settings = resolve_paths(load_settings())
    if getattr(args, "no_color", False) or settings.no_color:
        colors.set_enabled(False)
    try:
        if args.check_update:
            return _cmd_check_update()
        if args.auto_update:
            return _cmd_auto_update()
        if args.install_tools:
            return _cmd_install_tools()
        if args.command == "scan":
            return _cmd_scan(args, settings)
        if args.command == "setup":
            return _cmd_setup(args, settings)
        if args.command == "diff":
            return _cmd_diff(args)
        if args.command == "templates":
            return _cmd_templates(args)
        if args.command == "oob":
            return _cmd_oob(args)
        if args.command == "fuzz":
            return _cmd_fuzz(args)
        if args.command == "proxy":
            return _cmd_proxy(args)
        if args.command == "schedule":
            return _cmd_schedule(args)
        if args.command == "repeater":
            return _cmd_repeater(args)
        if args.command == "mine":
            return _cmd_mine(args)
        if args.command == "authorize":
            return _cmd_authorize(args)
        if args.command == "recon":
            return _cmd_recon(args)
        if args.command == "tls":
            return _cmd_tls(args)
        if args.command == "race":
            return _cmd_race(args)
        if args.command == "map":
            return _cmd_map(args)
        if args.command == "encode":
            return _cmd_encode(args)
        if args.command == "decode":
            return _cmd_decode(args)
    except KeyboardInterrupt:
        print("\n" + colors.warn("interrupted"))
        return 130
    print(render_banner(__version__))
    parser.print_help()
    return 0
