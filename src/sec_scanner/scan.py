"""Build a read-only report from local files. This module does not change the host."""

from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast

from sec_scanner import __version__
from sec_scanner.advisory import CONFIG_CVE, PATCH_CVES, Bundle, load_for_scan
from sec_scanner.assess import (
    classify_package,
    classify_upstream_banner,
    closure_for,
    links_are_verified,
    normalize_version_id,
)
from sec_scanner.config_review import (
    ApacheNotes,
    AppHit,
    SapiConfig,
    adjacent_ini,
    apache_has_risky_handler,
    apache_summary,
    branch_from_source,
    config_status,
    handler_is_risky,
    memory_limit_locked_off,
    read_apache,
    read_sapi,
    scan_app_dir,
    upload_progress_off,
)
from sec_scanner.discover import (
    collect,
    contained_file,
    file_workers_are_current,
    link_workers,
    packaged_paths,
    start_budget,
)
from sec_scanner.guidance import CONFIG_GUIDANCE, TEMPORARY_MEASURES, patch_next_action
from sec_scanner.models import BinaryObs, OsInfo, PackageObs, ProcessObs, SkipObs, WorkerLink
from sec_scanner.report import SCHEMA_VERSION

_RPM_FAMILIES = frozenset({"fedora", "rhel", "centos", "almalinux", "rocky", "ol", "amzn"})
_SAPI_BY_ROLE = {"fpm": "fpm", "cli": "cli", "cgi": "cgi", "mod_php": "apache2"}
_QUERY_TIMEOUT_SECONDS = 3.0
_QUERY_LIMIT = 16
_DEADLINE_SECONDS = 60.0


def scan(
    root: Path,
    *,
    app_dirs: tuple[Path, ...] = (),
    query_versions: tuple[Path, ...] = (),
    read_processes: bool = True,
    extra_search_dirs: tuple[Path, ...] = (),
    advisory_path: Path | None = None,
    today: date | None = None,
    now: datetime | None = None,
    progress: Callable[[str], None] | None = None,
    clock: Callable[[], float] | None = None,
    deadline_seconds: float = _DEADLINE_SECONDS,
) -> dict[str, object]:
    def note(stage: str) -> None:
        if progress is not None:
            progress(stage)

    scan_day = today or datetime.now(UTC).date()
    started = now or datetime.now(UTC)
    budget = start_budget(clock or time.monotonic, deadline_seconds)
    note("reading the signed advisory bundle")
    bundle, notes = load_for_scan(advisory_path, scan_day)
    note("reading OS, packages, binaries, and processes")
    discovery = collect(
        root,
        read_processes=read_processes,
        extra_dirs=extra_search_dirs,
        budget=budget,
    )
    skipped = list(discovery.skipped)
    coverage_notes = list(notes)
    if discovery.os_info.os_id in _RPM_FAMILIES:
        coverage_notes.append(
            "RPM package inventory is not implemented. "
            "No vendor verdict is produced from an RPM database."
        )
        skipped.append(SkipObs("rpm", "RPM inventory is not implemented in this build"))
    queries = _run_queries(root, query_versions, skipped)
    owned = packaged_paths(root, discovery.packages)
    for query in queries:
        owner = owned.get(str(query["path"]))
        if owner is not None:
            query["package_name"] = owner.name
    note("reading PHP and Apache configuration")
    configs, config_skips = _read_configs(root, discovery.packages)
    skipped.extend(config_skips)
    apache = read_apache(root, budget)
    skipped.extend(apache.skipped)
    app_hits: list[AppHit] = []
    app_skip_list: list[SkipObs] = []
    note("reading selected application directories")
    for app_dir in app_dirs:
        hits, app_skips = scan_app_dir(root, app_dir, budget)
        app_hits.extend(hits)
        app_skip_list.extend(app_skips)
        skipped.extend(app_skips)
    findings: list[dict[str, object]] = []
    for package in discovery.packages:
        links = link_workers(root, package, discovery.processes)
        findings.extend(
            _package_findings(bundle, discovery.os_info, package, links, configs, queries, apache)
        )
    findings.extend(
        _binary_findings(bundle, discovery.binaries, owned, queries, discovery.processes, root)
    )
    findings.extend(_config_findings(configs, bundle, apache))
    if app_dirs:
        findings.append(_app_finding(app_dirs, tuple(app_hits), tuple(app_skip_list), bundle))
    observed_at = started.replace(microsecond=0).isoformat()
    for finding in findings:
        finding["observed_at"] = observed_at
    limitations = [
        (
            "This report is evidence for an operator. It is not a warranty, a certification, "
            "or a statement that the host was or was not compromised."
        ),
        (
            "The scan does not send exploit traffic, install packages, edit configuration, "
            "or restart services."
        ),
        "A package on disk can be fixed while an older worker is still running.",
        "Containers, chroots, and PHP copies outside coverage.searched are not covered.",
        "The scan stops when scan.deadline_seconds is reached and reports what it read.",
        "No network requests are made during a scan.",
        (
            "PHP was executed only for the paths listed under scan.execution."
            if queries
            else "No PHP binary was executed."
        ),
    ]
    if bundle.stale:
        limitations.append(
            "The advisory bundle is outside its freshness window. "
            "Fixed and affected verdicts were withheld."
        )
    completion = "partial" if skipped or coverage_notes else "complete"
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "sec-scanner", "version": __version__},
        "scan": {
            "started_at": started.replace(microsecond=0).isoformat(),
            "root": str(root),
            "completion": completion,
            "execution": [{"argv": cast(list[str], item["argv"])} for item in queries],
            "deadline_seconds": deadline_seconds,
        },
        "advisory": {
            "bundle_id": bundle.bundle_id,
            "bundle_version": bundle.bundle_version,
            "reviewed_on": bundle.reviewed_on.isoformat(),
            "age_days": bundle.age_days,
            "freshness_window_days": bundle.freshness_window_days,
            "stale": bundle.stale,
        },
        "os": {
            "id": discovery.os_info.os_id,
            "version_id": discovery.os_info.version_id,
            "codename": discovery.os_info.codename,
            "pretty_name": discovery.os_info.pretty_name,
        },
        "coverage": {
            "searched": list(discovery.searched),
            "skipped": [{"path": item.path, "reason": item.reason} for item in skipped],
            "notes": coverage_notes,
        },
        "findings": findings,
        "limitations": limitations,
    }


def _package_findings(
    bundle: Bundle,
    os_info: OsInfo,
    package: PackageObs,
    links: tuple[WorkerLink, ...],
    configs: dict[tuple[str, str], SapiConfig],
    queries: list[dict[str, object]],
    apache: ApacheNotes,
) -> list[dict[str, object]]:
    os_id = os_info.os_id
    version_id = os_info.version_id
    codename = os_info.codename
    verified = links_are_verified(links)
    branch = branch_from_source(package.source)
    sapi = _SAPI_BY_ROLE.get(package.role)
    config = configs.get((branch or "", sapi or ""))
    findings: list[dict[str, object]] = []
    for cve in PATCH_CVES:
        status, detail = classify_package(
            bundle,
            os_id=os_id,
            version_id=version_id,
            codename=codename,
            source_package=package.source,
            installed_version=package.version,
            cve=cve,
        )
        mitigation = _mitigation(config, cve)
        closure = closure_for(
            status,
            package.role,
            serving_verified=verified,
            mitigation=mitigation,
        )
        rule = bundle.rule_for(
            os_id=os_id,
            version_id=normalize_version_id(os_id, version_id),
            codename=codename,
            source_package=package.source,
            cve=cve,
        )
        fixed = rule.fixed_version if rule is not None else ""
        evidence: list[dict[str, str]] = [{"source": "dpkg", "detail": detail}]
        evidence.extend({"source": "process", "detail": link.detail} for link in links)
        if config is not None and config.readable:
            evidence.append(
                {
                    "source": "php.ini",
                    "detail": _config_detail(config),
                }
            )
        for query in queries:
            if query.get("package_name") == package.name and query.get("banner"):
                evidence.append(
                    {
                        "source": "version-query",
                        "detail": (
                            f"argv {query['argv']}: {query['banner']}. "
                            "The package record is the verdict, not the banner."
                        ),
                    }
                )
        if package.role == "mod_php":
            apache_text = apache_summary(apache)
            if apache_text:
                evidence.append({"source": "apache", "detail": apache_text})
        limitations = _patch_limits(package.role, closure, mitigation)
        if package.role == "mod_php" and apache.directives:
            limitations.append(
                "Apache directives are text only. Directory and virtual-host "
                "context was not evaluated, so they are not a locked mitigation."
            )
        record = bundle.cves[cve]
        references = list(dict.fromkeys([*record.source_urls, *(rule.source_urls if rule else ())]))
        remediation = record.note
        if status in {"below_vendor_fix", "affected_upstream", "stale_recheck_vendor"}:
            remediation = f"{record.note} {TEMPORARY_MEASURES}"
        findings.append(
            _finding(
                identity=_identity(cve, package.source, package.name, package.arch, package.role),
                rule_id=cve,
                status=status,
                closure=closure,
                role=package.role,
                subject={
                    "kind": "package",
                    "name": package.name,
                    "version": package.version,
                    "arch": package.arch,
                    "source_package": package.source,
                    "path": package.files[0] if package.files else "",
                },
                evidence=evidence,
                remediation=remediation,
                limitations=limitations,
                next_action=patch_next_action(
                    status=status,
                    closure=closure,
                    name=package.name,
                    fixed_version=fixed,
                ),
                references=references,
                confidence=_confidence(status, "package"),
            )
        )
    return findings


def _binary_findings(
    bundle: Bundle,
    binaries: tuple[BinaryObs, ...],
    owned: dict[str, PackageObs],
    queries: list[dict[str, object]],
    processes: tuple[ProcessObs, ...],
    root: Path,
) -> list[dict[str, object]]:
    by_path = {str(item.get("path")): item for item in queries}
    findings: list[dict[str, object]] = []
    seen: set[str] = set()
    for binary in binaries:
        if binary.path in owned:
            continue
        seen.add(binary.path)
        findings.extend(
            _one_binary(bundle, binary.path, binary.role, by_path.get(binary.path), processes, root)
        )
    for path, query in by_path.items():
        if path in owned or path in seen:
            continue
        findings.extend(_one_binary(bundle, path, "unknown", query, processes, root))
    return findings


def _one_binary(
    bundle: Bundle,
    path: str,
    role: str,
    query: dict[str, object] | None,
    processes: tuple[ProcessObs, ...],
    root: Path,
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    banner = str(query.get("banner")) if query and query.get("banner") else ""
    verified = file_workers_are_current(path, processes)
    ini_detail = _adjacent_ini_detail(root, path)
    for cve in PATCH_CVES:
        if banner:
            status, detail = classify_upstream_banner(bundle, banner, cve)
            source = "version-query"
        else:
            status, detail = (
                "not_assessed",
                "No package identity and no authorized version query for this file.",
            )
            source = "path"
        closure = closure_for(status, role, serving_verified=verified, mitigation=False)
        record = bundle.cves[cve]
        evidence = [
            {"source": source, "detail": detail},
            {"source": "php.ini", "detail": ini_detail},
        ]
        findings.append(
            _finding(
                identity=_identity(cve, "unpacked", path, role),
                rule_id=cve,
                status=status,
                closure=closure,
                role=role,
                subject={
                    "kind": "binary",
                    "name": Path(path).name,
                    "version": banner,
                    "arch": "",
                    "source_package": "",
                    "path": path,
                },
                evidence=evidence,
                remediation=(
                    f"{record.note} {TEMPORARY_MEASURES}"
                    if status in {"affected_upstream", "below_vendor_fix", "stale_recheck_vendor"}
                    else record.note
                ),
                limitations=[
                    "An unpacked file has no vendor package identity. "
                    "A banner below the upstream fix can still be a backported "
                    "build this bundle does not know."
                ],
                next_action=patch_next_action(
                    status=status,
                    closure=closure,
                    name=Path(path).name,
                    fixed_version="",
                ),
                references=list(record.source_urls),
                confidence=_confidence(status, "binary"),
            )
        )
    return findings


def _config_findings(
    configs: dict[tuple[str, str], SapiConfig],
    bundle: Bundle,
    apache: ApacheNotes,
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    record = bundle.cves[CONFIG_CVE]
    for config in configs.values():
        status = config_status(config, ())
        closure = (
            "mitigation_observed_patch_still_needed" if upload_progress_off(config) else status
        )
        if not config.readable:
            status = "not_assessed"
            closure = "not_assessed"
        detail = (
            _config_detail(config) if config.readable else "Startup configuration was not readable."
        )
        if handler_is_risky(config):
            detail += " session.serialize_handler is set to a value named in the PHP notice."
        limitations = [
            "Static settings cannot show whether application code changes "
            "the serializer before session_start.",
            "This is not proof the condition is present or absent.",
        ]
        if config.sapi == "apache2":
            apache_text = apache_summary(apache)
            if apache_text:
                detail = f"{detail} {apache_text}"
                limitations.append(
                    "Apache directives are text only. Directory and virtual-host "
                    "context was not evaluated, so they are not a locked mitigation."
                )
            if apache_has_risky_handler(apache):
                detail += " Apache text names a session.serialize_handler from the PHP notice."
                if status in {"no_matching_static_evidence", "not_assessed"}:
                    status = "potential_configuration_to_review"
                if closure in {"no_matching_static_evidence", "not_assessed"}:
                    closure = "potential_configuration_to_review"
            elif status == "no_matching_static_evidence" and apache.skipped:
                status = "not_assessed"
                closure = "not_assessed"
        findings.append(
            _finding(
                identity=_identity(CONFIG_CVE, config.branch, config.sapi),
                rule_id=CONFIG_CVE,
                status=status,
                closure=closure,
                role=config.sapi,
                subject={
                    "kind": "config",
                    "name": f"php {config.branch} {config.sapi}",
                    "version": config.branch,
                    "arch": "",
                    "source_package": "",
                    "path": config.files[0] if config.files else "",
                },
                evidence=[{"source": "php.ini", "detail": detail}],
                remediation=CONFIG_GUIDANCE,
                limitations=limitations,
                next_action=CONFIG_GUIDANCE,
                references=list(record.source_urls),
                confidence=_confidence(status, "config"),
            )
        )
    return findings


def _app_finding(
    app_dirs: tuple[Path, ...],
    hits: tuple[AppHit, ...],
    app_skips: tuple[SkipObs, ...],
    bundle: Bundle,
) -> dict[str, object]:
    record = bundle.cves[CONFIG_CVE]
    if hits:
        status = "potential_configuration_to_review"
        detail = "; ".join(
            f"{hit.path}:{hit.line} sets session.serialize_handler to {hit.value}"
            + (
                f" and session_start is on line {hit.session_start_line}"
                if hit.session_start_line is not None
                else " and session_start was not seen in that file"
            )
            for hit in hits[:20]
        )
    elif app_skips:
        status = "not_assessed"
        detail = (
            "Some application files were skipped, so this is not a clean result. "
            f"{len(app_skips)} path(s) were not read."
        )
    else:
        status = "no_matching_static_evidence"
        detail = (
            "No session.serialize_handler assignment was found in the application files "
            "that were read."
        )
    limitations = [
        "A text match does not show that the code runs, or that it runs "
        "in that order, on the worker that serves requests.",
    ]
    if hits and app_skips:
        limitations.append(
            "Some application files were skipped. "
            "The matches above are only the files that were read."
        )
    return _finding(
        identity=_identity(CONFIG_CVE, "app", *(str(path) for path in app_dirs)),
        rule_id=CONFIG_CVE,
        status=status,
        closure=status,
        role="application",
        subject={
            "kind": "application",
            "name": "application source",
            "version": "",
            "arch": "",
            "source_package": "",
            "path": str(app_dirs[0]),
        },
        evidence=[{"source": "source text", "detail": detail}],
        remediation=CONFIG_GUIDANCE,
        limitations=limitations,
        next_action=CONFIG_GUIDANCE,
        references=list(record.source_urls),
        confidence=_confidence(status, "application"),
    )


def _read_configs(
    root: Path,
    packages: tuple[PackageObs, ...],
) -> tuple[dict[tuple[str, str], SapiConfig], list[SkipObs]]:
    configs: dict[tuple[str, str], SapiConfig] = {}
    skipped: list[SkipObs] = []
    for package in packages:
        branch = branch_from_source(package.source)
        sapi = _SAPI_BY_ROLE.get(package.role)
        if branch is None or sapi is None:
            continue
        key = (branch, sapi)
        if key in configs:
            continue
        config = read_sapi(root, branch, sapi)
        configs[key] = config
        skipped.extend(config.skipped)
    return configs, skipped


def _run_queries(
    root: Path,
    paths: tuple[Path, ...],
    skipped: list[SkipObs],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    if len(paths) > _QUERY_LIMIT:
        skipped.append(
            SkipObs("query-version", f"only the first {_QUERY_LIMIT} version queries are run")
        )
    for path in paths[:_QUERY_LIMIT]:
        resolved = _query_target(root, path)
        if resolved is None:
            skipped.append(
                SkipObs(str(path), "version query path is outside the root or not a regular file")
            )
            continue
        argv = [str(resolved), "-v"]
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                timeout=_QUERY_TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            skipped.append(SkipObs(str(resolved), f"version query failed: {exc}"))
            continue
        banner = (completed.stdout + b"\n" + completed.stderr)[:4096].decode("utf-8", "replace")
        first = banner.splitlines()[0] if banner.splitlines() else ""
        results.append({"path": str(resolved), "argv": argv, "banner": first, "package_name": ""})
    return results


def _query_target(root: Path, path: Path) -> Path | None:
    return contained_file(root, path)


def _mitigation(config: SapiConfig | None, cve: str) -> bool:
    if config is None or not config.readable:
        return False
    if cve == "CVE-2026-109619":
        return upload_progress_off(config)
    if cve == "CVE-2026-109618":
        return memory_limit_locked_off(config)
    return False


def _config_detail(config: SapiConfig) -> str:
    handler = config.startup.get("session.serialize_handler", "not set")
    upload = config.startup.get(
        "session.upload_progress.enabled", "not set; PHP's default is enabled"
    )
    memory = config.startup.get("memory_limit", "not set")
    post = config.startup.get("post_max_size", "not set")
    uploads = config.startup.get("upload_max_filesize", "not set")
    traces = config.startup.get("fatal_error_backtraces", "not set")
    locked = upload_progress_off(config)
    memory_locked = memory_limit_locked_off(config)
    detail = (
        f"serialize_handler={handler}; upload_progress={upload}; memory_limit={memory}; "
        f"post_max_size={post}; upload_max_filesize={uploads}; "
        f"fatal_error_backtraces={traces}; upload progress locked off={locked}; "
        f"memory_limit admin -1={memory_locked}; files={len(config.files)}"
    )
    if config.branch.startswith("8.5") and _off(traces):
        detail += (
            ". fatal_error_backtraces is off. That covers one PHP 8.5 path for "
            "CVE-2026-109619 and is not the session mitigation."
        )
    return detail


def _adjacent_ini_detail(root: Path, binary: str) -> str:
    found = adjacent_ini(root, Path(binary))
    if found is None:
        return "No php.ini was found beside this binary."
    ini_path, values = found
    upload = values.get("session.upload_progress.enabled", "not set")
    memory = values.get("memory_limit", "not set")
    return (
        f"candidate {ini_path}; upload_progress={upload}; memory_limit={memory}. "
        "This file sits beside the binary and was not confirmed as the ini PHP loads."
    )


def _off(value: str) -> bool:
    return value.strip().strip("\"'").lower() in {"0", "off", "false", "no"}


def _confidence(status: str, kind: str) -> str:
    if kind == "config":
        return "Static configuration only. This is not proof of runtime behavior."
    if kind == "application":
        return "Source text only. This is not proof the code runs."
    if status in {"vendor_fix_confirmed", "below_vendor_fix"}:
        return "Matched one signed advisory rule for this OS and source package."
    if status == "stale_recheck_vendor":
        return "A signed rule matched, and the bundle is outside its freshness window."
    if status in {"affected_upstream", "fixed_upstream"}:
        return "Upstream banner only. No vendor package is linked to this file."
    if status == "not_assessed":
        return "The file or package was found. Its patch level was not read."
    return "No signed rule matched. The version number was not used as a verdict."


def _patch_limits(role: str, closure: str, mitigation: bool) -> list[str]:
    limits = [
        "Version and package evidence do not show whether the host was "
        "compromised before it was patched."
    ]
    if role not in {"fpm", "cgi", "mod_php", "litespeed", "frankenphp"}:
        limits.append("This package is not a web-serving SAPI.")
    if closure == "patched_on_disk_live_runtime_not_verified":
        limits.append("The live worker was not tied to the file on disk.")
    if mitigation:
        limits.append("A temporary mitigation was observed. The patch finding stays open.")
    return limits


def _identity(*parts: str) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:24]


def _finding(
    *,
    identity: str,
    rule_id: str,
    status: str,
    closure: str,
    role: str,
    subject: dict[str, str],
    evidence: list[dict[str, str]],
    remediation: str,
    limitations: list[str],
    next_action: str,
    references: list[str],
    confidence: str,
) -> dict[str, object]:
    return {
        "identity": identity,
        "rule_id": rule_id,
        "status": status,
        "closure": closure,
        "role": role,
        "confidence": confidence,
        "subject": subject,
        "evidence": evidence,
        "remediation": remediation,
        "limitations": limitations,
        "next_action": next_action,
        "references": references,
    }
