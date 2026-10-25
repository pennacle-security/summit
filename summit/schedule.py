"""Scan scheduling - run a scan on an interval, diff every round.

The last open roadmap item besides the TLS proxy. Monitoring is where
scanning turns into defense: a scheduled scan keeps a JSON history, diffs
each round against the previous one with the same dedup key as
`summit diff`, and can fail the run when a new or regressed finding
crosses a severity floor - so a cron job in CI becomes a regression gate.

Each iteration runs the real `summit scan` as a subprocess: fresh
process, its own rate limiter, reports on disk, nothing shared. That
isolation is deliberate - a scheduler that reuses one long-lived scan
session accumulates state in ways nobody debugs at 3am.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from .diff import diff_finding_lists, load_findings
from .scan.core import SEVERITY_RANK


def _gate_hits(candidates: list[dict], fail_on: str) -> list[dict]:
    """Same contract as the scan CI gate: rank-based severity floor."""
    floor = SEVERITY_RANK.get(fail_on, 0)
    return [item for item in candidates if SEVERITY_RANK.get(item.get("severity", "info"), 0) >= floor]


def run_schedule(
    url: str,
    every: float,
    times: int,
    out_dir: str,
    fail_on: str | None = None,
    scan_args: list[str] | None = None,
) -> int:
    """Run `times` scans of `url`, `every` seconds apart.

    Every round writes `scan-NNN.json` into out_dir and prints a
    new/resolved/regressed summary against the previous round. With
    fail_on, the run exits 1 if any round produced a new or regressed
    finding at or above that severity - the scheduled CI gate.
    """
    directory = Path(out_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    tripped = False
    previous_path: Path | None = None
    index = 0

    while True:
        index += 1
        if times > 0 and index > times:
            break
        json_path = directory / f"scan-{index:03d}.json"
        command = [
            sys.executable, "-m", "summit", "scan", url,
            "--json", str(json_path), "--silent",
            *(scan_args or []),
        ]
        started = time.monotonic()
        result = subprocess.run(command)
        elapsed = time.monotonic() - started
        if result.returncode == 2:
            print(f"[schedule] scan aborted (bad arguments), stopping after round {index}")
            return 2

        summary = f"[round {index}{'/' + str(times) if times > 0 else ''}] scan finished in {elapsed:.1f}s"
        if json_path.exists():
            try:
                current = load_findings(str(json_path))
                summary += f", {len(current)} finding(s)"
                if previous_path is not None:
                    diff = diff_finding_lists(load_findings(str(previous_path)), current)
                    summary += (
                        f" - new {len(diff.new)}, resolved {len(diff.resolved)}, "
                        f"regressed {len(diff.regressed)}"
                    )
                    if fail_on:
                        hits = _gate_hits(diff.new + diff.regressed, fail_on)
                        if hits:
                            tripped = True
                            summary += f" - GATE FAILED: {len(hits)} new/regressed at or above {fail_on}"
                            for hit in hits[:3]:
                                summary += f"\n    [{hit.get('severity', '?').upper()}] {hit.get('title', '?')} - {hit.get('url', '?')}"
                previous_path = json_path
            except (OSError, ValueError) as exc:
                summary += f" (unreadable report: {exc})"
        else:
            summary += " - no report written (scan failed)"
        print(summary)

        if times > 0 and index >= times:
            break
        time.sleep(max(0.0, every))

    if tripped:
        print(f"[schedule] finished: gate on '{fail_on}' tripped during the run")
        return 1
    print("[schedule] finished: all rounds clean against the gate" if fail_on else "[schedule] finished")
    return 0
