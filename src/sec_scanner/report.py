"""Render a scan report. The JSON document is the record the other formats follow."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import cast

from sec_scanner.errors import SecScannerError

SCHEMA_VERSION = 1
_MAX_REPORT_BYTES = 32 * 1024 * 1024
_HOME_PATH = re.compile(r"/home/([^/]+)")
_ROOT_PATH = re.compile(r"/root/([^/]+)")


def dump_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def write_reports(report: dict[str, object], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(dump_json(report), encoding="utf-8")
    (output / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (output / "report.html").write_text(render_html(report), encoding="utf-8")


def render_text(report: dict[str, object]) -> str:
    tool = _dict(report.get("tool"))
    advisory = _dict(report.get("advisory"))
    lines = [
        f"{tool.get('name', 'sec-scanner')} {tool.get('version', '')}".strip(),
        (
            f"advisory {advisory.get('bundle_id', '')} "
            f"version {advisory.get('bundle_version', '')}, "
            f"reviewed {advisory.get('reviewed_on', '')}, age {advisory.get('age_days', '')} days"
        ),
    ]
    if advisory.get("stale") is True:
        lines.append("advisory bundle is stale; vendor verdicts are not current")
    scan = _dict(report.get("scan"))
    os_info = _dict(report.get("os"))
    lines.append(f"started {scan.get('started_at', '')}")
    lines.append(
        "os "
        f"{os_info.get('pretty_name') or os_info.get('id', '')} "
        f"{os_info.get('version_id', '')} {os_info.get('codename', '')}".strip()
    )
    lines.append(
        f"root {scan.get('root', '')}  completion {scan.get('completion', '')}  "
        f"time limit {scan.get('deadline_seconds', '')} seconds"
    )
    execution = _list(scan.get("execution"))
    if execution:
        lines.append("PHP version queries:")
        for item in execution:
            command = _dict(item).get("argv", [])
            lines.append(f"  {command}")
    else:
        lines.append("no PHP binary was executed")
    findings = _list(report.get("findings"))
    if not findings:
        lines.append("")
        lines.append("No PHP runtime was found in the locations this scan reads.")
        lines.append("That is not proof the machine has no PHP.")
    for finding in findings:
        item = _dict(finding)
        subject = _dict(item.get("subject"))
        label = subject.get("name") or subject.get("path") or item.get("rule_id")
        lines.append("")
        lines.append(f"{label}  {item.get('role', '')}  {item.get('rule_id', '')}")
        lines.append(f"  status {item.get('status', '')}")
        lines.append(f"  closure {item.get('closure', '')}")
        lines.append(f"  confidence {_one_line(str(item.get('confidence', '')))}")
        evidence = _list(item.get("evidence"))
        if evidence:
            first = _dict(evidence[0])
            lines.append(
                f"  evidence {first.get('source', '')}: {_one_line(str(first.get('detail', '')))}"
            )
        lines.append(f"  next {_one_line(str(item.get('next_action', '')))}")
    coverage = _dict(report.get("coverage"))
    lines.extend(["", "Searched locations:"])
    searched = _list(coverage.get("searched"))
    if not searched:
        lines.append("  none recorded")
    for item in searched:
        lines.append(f"  {item}")
    lines.append("Skipped:")
    skipped = _list(coverage.get("skipped"))
    if not skipped:
        lines.append("  none")
    for item in skipped:
        skipped_item = _dict(item)
        lines.append(f"  {skipped_item.get('path', '')}: {skipped_item.get('reason', '')}")
    lines.append("Limitations:")
    for item in _list(report.get("limitations")):
        lines.append(f"  {_one_line(str(item))}")
    lines.append("")
    return "\n".join(lines)


def render_markdown(report: dict[str, object]) -> str:
    tool = _dict(report.get("tool"))
    advisory = _dict(report.get("advisory"))
    scan = _dict(report.get("scan"))
    lines = [
        "# PHP patch and configuration report",
        "",
        _disclaimer(),
        "",
        f"- Tool: {tool.get('name', '')} {tool.get('version', '')}",
        f"- Started: {scan.get('started_at', '')}",
        f"- Root: `{scan.get('root', '')}`",
        f"- Completion: {scan.get('completion', '')}",
        (
            f"- Advisory: {advisory.get('bundle_id', '')} "
            f"version {advisory.get('bundle_version', '')}, "
            f"reviewed {advisory.get('reviewed_on', '')}, age {advisory.get('age_days', '')} days"
        ),
    ]
    if advisory.get("stale") is True:
        lines.append("- Advisory data is stale. Fixed and affected verdicts were withheld.")
    lines.extend(["", "## Limitations", ""])
    for item in _list(report.get("limitations")):
        lines.append(f"- {_one_line(str(item))}")
    lines.extend(["", "## Findings", ""])
    findings = _list(report.get("findings"))
    if not findings:
        lines.append("No PHP runtime was found in the locations this scan reads.")
    for finding in findings:
        lines.extend(_markdown_finding(_dict(finding)))
    coverage = _dict(report.get("coverage"))
    lines.extend(["", "## Searched locations", ""])
    searched = _list(coverage.get("searched"))
    if not searched:
        lines.append("No search locations were recorded.")
    for item in searched:
        lines.append(f"- `{item}`")
    lines.extend(["", "## Coverage", ""])
    for item in _list(coverage.get("notes")):
        lines.append(f"- {_one_line(str(item))}")
    for item in _list(coverage.get("skipped")):
        skipped = _dict(item)
        lines.append(f"- `{skipped.get('path', '')}`: {_one_line(str(skipped.get('reason', '')))}")
    lines.append("")
    return "\n".join(lines)


def render_html(report: dict[str, object]) -> str:
    body = render_markdown(report)
    paragraphs = "\n".join(f"<p>{html.escape(line)}</p>" for line in body.splitlines())
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        "<title>PHP patch and configuration report</title></head><body>\n"
        f"{paragraphs}\n</body></html>\n"
    )


def redact_report(report: dict[str, object], home: str) -> dict[str, object]:
    redacted = _redact_value(report, home)
    if not isinstance(redacted, dict):
        raise SecScannerError("report redaction failed")
    return cast(dict[str, object], redacted)


def load_report(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            data = handle.read(_MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise SecScannerError(f"could not read report {path}") from exc
    if len(data) > _MAX_REPORT_BYTES:
        raise SecScannerError(f"{path} is larger than the report read limit")
    try:
        raw = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SecScannerError(f"could not read report {path}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise SecScannerError(f"{path} is not a schema {SCHEMA_VERSION} report")
    if not isinstance(raw.get("findings"), list):
        raise SecScannerError(f"{path} has no findings list")
    return cast(dict[str, object], raw)


def _markdown_finding(finding: dict[str, object]) -> list[str]:
    subject = _dict(finding.get("subject"))
    title = str(subject.get("name") or subject.get("path") or finding.get("rule_id"))
    lines = [
        f"### {title}",
        "",
        f"- Rule: {finding.get('rule_id', '')}",
        f"- Status: {finding.get('status', '')}",
        f"- Closure: {finding.get('closure', '')}",
        f"- Role: {finding.get('role', '')}",
        f"- Confidence: {_one_line(str(finding.get('confidence', '')))}",
        f"- Observed: {finding.get('observed_at', '')}",
        f"- Next: {_one_line(str(finding.get('next_action', '')))}",
        "",
        finding.get("remediation", ""),
        "",
        "Evidence:",
        "",
    ]
    for item in _list(finding.get("evidence")):
        evidence = _dict(item)
        lines.append(
            f"- {evidence.get('source', '')}: {_one_line(str(evidence.get('detail', '')))}"
        )
    limitations = _list(finding.get("limitations"))
    if limitations:
        lines.extend(["", "Limits:", ""])
        for item in limitations:
            lines.append(f"- {_one_line(str(item))}")
    references = _list(finding.get("references"))
    if references:
        lines.extend(["", "References:", ""])
        for item in references:
            lines.append(f"- {item}")
    lines.append("")
    return [str(line) for line in lines]


def _disclaimer() -> str:
    return (
        "This is evidence for an operator. It is not a warranty, a certification, "
        "or a statement that the host was or was not compromised."
    )


def _redact_value(value: object, home: str) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if key == "identity":
                redacted[str(key)] = item
            else:
                redacted[str(key)] = _redact_value(item, home)
        return redacted
    if isinstance(value, list):
        return [_redact_value(item, home) for item in value]
    if isinstance(value, str):
        return _redact_text(value, home)
    return value


def _redact_text(text: str, home: str) -> str:
    if home and home != "/" and home in text:
        text = text.replace(home, "/home/REDACTED")
    text = _HOME_PATH.sub(_redact_segment, text)
    return _ROOT_PATH.sub(_redact_segment, text)


def _redact_segment(match: re.Match[str]) -> str:
    if match.group(1) == "REDACTED":
        return match.group(0)
    slash = match.group(0).rfind("/")
    return match.group(0)[: slash + 1] + "REDACTED"


def _dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    return {}


def _list(value: object) -> list[object]:
    if isinstance(value, list):
        return cast(list[object], value)
    return []


def _one_line(text: str) -> str:
    return " ".join(text.split())
