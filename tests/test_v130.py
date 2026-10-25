"""v1.3.0 regressions: CI gates, baseline diffing, and template selection."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from summit import __version__
from summit.cli import _apply_ci_gate, _cmd_templates, _gate_hits, _split_csv, _template_matches, build_parser
from summit.diff import diff_finding_lists, load_findings
from summit.templates import load_templates

BUILTIN = Path(__file__).resolve().parents[1] / "summit" / "templates" / "builtin"


class FakeFinding:
    def __init__(self, severity: str, title: str = "Test finding", url: str = "http://example.test/x"):
        self.severity = severity
        self.title = title
        self.url = url

    def as_dict(self) -> dict:
        return {
            "check_id": "test-check",
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "param": "",
        }


def _report(tmp_path: Path, findings: list[dict]) -> str:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(path)


def test_version_is_1_3_0():
    assert __version__ == "2.1.0"


def test_split_csv_is_tolerant():
    assert _split_csv(None) == set()
    assert _split_csv(" cve, RCE ,, ") == {"cve", "rce"}


def test_template_tag_and_severity_filters():
    templates = load_templates(str(BUILTIN))
    assert len(templates) == 37
    for template in templates:
        assert _template_matches(template, {"cve"}, set(), set()) == ("cve" in template.tags)
        assert _template_matches(template, set(), {"lfi"}, set()) == ("lfi" not in template.tags)
        assert _template_matches(template, set(), set(), {"critical"}) == (
            template.severity == "critical"
        )
    cve_critical = [t for t in templates if t.severity == "critical" and "cve" in t.tags]
    assert cve_critical
    assert all(_template_matches(t, {"cve"}, set(), {"critical"}) for t in cve_critical)


def test_templates_json_inventory_is_filtered(capsys):
    args = Namespace(
        action="list",
        path=None,
        tags="cve",
        exclude_tags=None,
        severity=None,
        as_json=True,
    )
    assert _cmd_templates(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload
    assert all("cve" in item["tags"] for item in payload)
    assert all({"id", "name", "severity", "tags", "path"} <= set(item) for item in payload)


def test_scan_gate_flags_parse():
    args = build_parser().parse_args([
        "scan", "http://127.0.0.1:1",
        "--fail-on", "high",
        "--baseline", "old.json",
        "--template-tags", "cve,rce",
        "--template-exclude-tags", "dos",
        "--template-severity", "critical,high",
    ])
    assert args.fail_on == "high"
    assert args.baseline_path == "old.json"
    assert args.template_tags == "cve,rce"
    assert args.template_exclude_tags == "dos"
    assert args.template_severity == "critical,high"


def test_templates_parser_flags():
    args = build_parser().parse_args(["templates", "--tags", "cve", "--exclude-tags", "lfi",
                                      "--severity", "critical", "--json"])
    assert args.tags == "cve"
    assert args.exclude_tags == "lfi"
    assert args.severity == "critical"
    assert args.as_json is True


def test_gate_hits_respects_threshold():
    candidates = [
        {"severity": "info"},
        {"severity": "medium"},
        {"severity": "critical"},
    ]
    assert _gate_hits(candidates, "high") == [{"severity": "critical"}]
    assert len(_gate_hits(candidates, "info")) == 3


def test_gate_fails_on_current_high_without_baseline(capsys):
    code = _apply_ci_gate([FakeFinding("high")], Namespace(fail_on="high", baseline_path=None))
    assert code == 1
    assert "CI gate failed" in capsys.readouterr().out


def test_gate_passes_below_threshold(capsys):
    code = _apply_ci_gate([FakeFinding("medium")], Namespace(fail_on="high", baseline_path=None))
    assert code == 0
    assert "CI gate passed" in capsys.readouterr().out


def test_baseline_gate_ignores_known_finding(capsys, tmp_path):
    known = FakeFinding("critical")
    baseline = _report(tmp_path, [known.as_dict()])
    code = _apply_ci_gate([known], Namespace(fail_on="high", baseline_path=baseline))
    assert code == 0
    output = capsys.readouterr().out
    assert "new: 0" in output
    assert "CI gate passed" in output


def test_baseline_gate_fails_on_new_finding(capsys, tmp_path):
    known = FakeFinding("high")
    baseline = _report(tmp_path, [known.as_dict()])
    new = FakeFinding("critical", title="New SQL injection", url="http://example.test/item?id=1")
    code = _apply_ci_gate([known, new], Namespace(fail_on="high", baseline_path=baseline))
    assert code == 1
    output = capsys.readouterr().out
    assert "new: 1" in output
    assert "CI gate failed" in output


def test_unusable_baseline_returns_2(capsys, tmp_path):
    missing = str(tmp_path / "missing.json")
    code = _apply_ci_gate([FakeFinding("low")], Namespace(fail_on="high", baseline_path=missing))
    assert code == 2
    assert "baseline unavailable" in capsys.readouterr().out


def test_baseline_same_as_json_path_returns_2(capsys, tmp_path):
    path = _report(tmp_path, [FakeFinding("low").as_dict()])
    args = Namespace(fail_on="high", baseline_path=path, json_path=path)
    code = _apply_ci_gate([FakeFinding("low")], args)
    assert code == 2
    assert "same file" in capsys.readouterr().out


def test_diff_finding_lists_classifies():
    old = [{"check_id": "x", "url": "http://example.test/a?b=2&a=1", "param": "q", "severity": "medium"}]
    same = {"check_id": "x", "url": "http://example.test/a?a=1&b=2", "param": "q", "severity": "medium"}
    regressed = {"check_id": "x", "url": "http://example.test/a?a=1&b=2", "param": "q", "severity": "high"}
    added = {"check_id": "y", "url": "http://example.test/b", "param": "", "severity": "low"}

    assert len(diff_finding_lists(old, [same]).unchanged) == 1
    result = diff_finding_lists(old, [regressed, added])
    assert [item["check_id"] for item in result.regressed] == ["x"]
    assert [item["check_id"] for item in result.new] == ["y"]
    assert diff_finding_lists(old, []).resolved == old


def test_load_findings_rejects_non_list(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"findings": "nope"}), encoding="utf-8")
    try:
        load_findings(str(path))
    except ValueError as exc:
        assert "findings" in str(exc)
    else:
        raise AssertionError("expected ValueError")
