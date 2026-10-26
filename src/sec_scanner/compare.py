"""Compare a later scan with a saved baseline. A missing path is not closure."""

from __future__ import annotations

from sec_scanner.errors import SecScannerError

_RESOLVED = frozenset(
    {
        "vendor_fix_verified_for_serving_runtime",
        "upstream_fix_verified_for_serving_runtime",
    }
)
_MITIGATED = "mitigation_observed_patch_still_needed"
_UNKNOWN = frozenset({"unknown", "not_assessed"})


def compare_reports(
    baseline: dict[str, object],
    current: dict[str, object],
) -> dict[str, object]:
    base_findings = _findings(baseline, "baseline")
    current_findings = _findings(current, "current")
    base_ids = {str(item.get("identity")): item for item in base_findings}
    current_ids = {str(item.get("identity")): item for item in current_findings}
    resolved: list[dict[str, object]] = []
    mitigated: list[dict[str, object]] = []
    still_open: list[dict[str, object]] = []
    unknown: list[dict[str, object]] = []
    not_seen: list[dict[str, object]] = []
    new_findings: list[dict[str, object]] = []
    for identity, earlier in base_ids.items():
        later = current_ids.get(identity)
        if later is None:
            not_seen.append(
                _change(
                    identity,
                    earlier,
                    None,
                    (
                        "The earlier runtime was not observed on the rescan. "
                        "Disappearance is not closure."
                    ),
                )
            )
            continue
        bucket = _bucket(later)
        _store(
            bucket,
            resolved,
            mitigated,
            still_open,
            unknown,
            _change(identity, earlier, later, _reason(bucket, new=False)),
        )
    for identity, item in current_ids.items():
        if identity in base_ids:
            continue
        bucket = _bucket(item)
        if bucket == "still_open":
            new_findings.append(
                _change(identity, None, item, "This runtime was not in the baseline.")
            )
            continue
        _store(
            bucket,
            resolved,
            mitigated,
            still_open,
            unknown,
            _change(identity, None, item, _reason(bucket, new=True)),
        )
    return {
        "schema_version": 1,
        "baseline": _header(baseline),
        "current": _header(current),
        "resolved": resolved,
        "mitigated": mitigated,
        "still_open": still_open,
        "unknown": unknown,
        "not_seen": not_seen,
        "new": new_findings,
        "open_count": (
            len(mitigated) + len(still_open) + len(unknown) + len(not_seen) + len(new_findings)
        ),
    }


def _store(
    bucket: str,
    resolved: list[dict[str, object]],
    mitigated: list[dict[str, object]],
    still_open: list[dict[str, object]],
    unknown: list[dict[str, object]],
    item: dict[str, object],
) -> None:
    if bucket == "resolved":
        resolved.append(item)
    elif bucket == "mitigated":
        mitigated.append(item)
    elif bucket == "unknown":
        unknown.append(item)
    else:
        still_open.append(item)


def _bucket(finding: dict[str, object]) -> str:
    closure = str(finding.get("closure", ""))
    status = str(finding.get("status", ""))
    if closure in _RESOLVED:
        return "resolved"
    if closure == _MITIGATED:
        return "mitigated"
    if status in _UNKNOWN or closure in _UNKNOWN:
        return "unknown"
    return "still_open"


def _reason(bucket: str, *, new: bool) -> str:
    if bucket == "resolved" and new:
        return "This serving runtime was not in the baseline and is tied to a fixed build."
    if bucket == "resolved":
        return "The serving runtime is tied to a fixed build in the current report."
    if bucket == "mitigated" and new:
        return (
            "This runtime was not in the baseline. A temporary mitigation is recorded, "
            "and the patch finding stays open."
        )
    if bucket == "mitigated":
        return "A temporary mitigation is recorded. The patch finding stays open."
    if bucket == "unknown" and new:
        return (
            "This runtime was not in the baseline, and the current report "
            "has no package or version verdict."
        )
    if bucket == "unknown":
        return "The current report does not have a package or version verdict."
    return "The current report does not tie a serving runtime to a fixed build."


def _change(
    identity: str,
    earlier: dict[str, object] | None,
    later: dict[str, object] | None,
    reason: str,
) -> dict[str, object]:
    source = later if later is not None else earlier
    rule_id = "" if source is None else source.get("rule_id", "")
    return {
        "identity": identity,
        "rule_id": rule_id,
        "prior_status": "" if earlier is None else earlier.get("status", ""),
        "prior_closure": "" if earlier is None else earlier.get("closure", ""),
        "status": "" if later is None else later.get("status", ""),
        "closure": "" if later is None else later.get("closure", ""),
        "serving": "" if later is None else _serving(later),
        "reason": reason,
    }


def _serving(finding: dict[str, object]) -> str:
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        return ""
    parts: list[str] = []
    for item in evidence:
        if isinstance(item, dict) and item.get("source") == "process":
            parts.append(str(item.get("detail", "")))
    return "; ".join(parts)


def _header(report: dict[str, object]) -> dict[str, object]:
    scan = report.get("scan")
    advisory = report.get("advisory")
    coverage = report.get("coverage")
    scan_record = scan if isinstance(scan, dict) else {}
    advisory_record = advisory if isinstance(advisory, dict) else {}
    coverage_record = coverage if isinstance(coverage, dict) else {}
    skipped = coverage_record.get("skipped")
    return {
        "started_at": scan_record.get("started_at", ""),
        "completion": scan_record.get("completion", ""),
        "advisory_bundle": advisory_record.get("bundle_id", ""),
        "advisory_version": advisory_record.get("bundle_version", ""),
        "advisory_age_days": advisory_record.get("age_days", ""),
        "advisory_stale": advisory_record.get("stale", ""),
        "skipped": skipped if isinstance(skipped, list) else [],
    }


def _findings(report: dict[str, object], label: str) -> list[dict[str, object]]:
    raw = report.get("findings")
    if not isinstance(raw, list):
        raise SecScannerError(f"{label} report has no findings list")
    findings: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict) or not item.get("identity"):
            raise SecScannerError(f"{label} report has a finding without an identity")
        findings.append(item)
    return findings
