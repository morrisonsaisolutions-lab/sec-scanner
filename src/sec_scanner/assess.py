"""Patch status from a signed bundle. Unknown stays unknown."""

from __future__ import annotations

import re

from sec_scanner.advisory import Bundle, VendorRule
from sec_scanner.debian_version import compare
from sec_scanner.models import WorkerLink

_DEB_TOKEN = re.compile(r"deb\d")
_DOTTED = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
_PHP_BANNER = re.compile(r"\bPHP (\d+)\.(\d+)\.(\d+)(?:([-_.]?)([A-Za-z][A-Za-z0-9.]*))?")

_SERVING_ROLES = frozenset({"fpm", "cgi", "mod_php", "litespeed", "frankenphp"})
_STALE_SUFFIX = (
    " The advisory bundle is outside its freshness window, so this is not a current verdict."
)


def normalize_version_id(os_id: str, version_id: str) -> str:
    if os_id == "ubuntu":
        match = re.fullmatch(r"(\d+\.\d+)(?:\.\d+)?", version_id)
        return match.group(1) if match else version_id
    if os_id == "debian" and re.fullmatch(r"\d+", version_id):
        return version_id
    return version_id


def classify_package(
    bundle: Bundle,
    *,
    os_id: str,
    version_id: str,
    codename: str,
    source_package: str,
    installed_version: str,
    cve: str,
) -> tuple[str, str]:
    """Return a status and the evidence sentence that justifies it."""
    rule = bundle.rule_for(
        os_id=os_id,
        version_id=normalize_version_id(os_id, version_id),
        codename=codename,
        source_package=source_package,
        cve=cve,
    )
    if rule is None:
        return (
            "unknown",
            "No advisory rule matches this OS release and source package. "
            "The version was not compared with another vendor's fix.",
        )
    if not version_matches_vendor(installed_version, rule):
        return (
            "unknown",
            f"Package version {installed_version} does not match the {rule.version_pattern} "
            f"version pattern for {rule.source_package}, so it was not treated as that "
            "vendor's package.",
        )
    ordered = compare(installed_version, rule.fixed_version)
    if ordered is None:
        return ("not_assessed", f"Package version {installed_version} could not be compared.")
    if ordered < 0:
        status = "below_vendor_fix"
        relation = "older than"
    else:
        status = "vendor_fix_confirmed"
        relation = "at or newer than"
    detail = (
        f"{rule.os_id} {rule.codename or rule.version_id} {source_package} "
        f"{installed_version} is {relation} the bundled fix {rule.fixed_version}."
    )
    if bundle.stale:
        return (
            "stale_recheck_vendor",
            detail + _STALE_SUFFIX,
        )
    return status, detail


def classify_upstream_banner(bundle: Bundle, banner: str, cve: str) -> tuple[str, str]:
    """Classify a PHP version banner only when no package rule applies."""
    match = _PHP_BANNER.search(banner)
    if match is None:
        return ("not_assessed", "The version query did not report a PHP version.")
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3))
    shown, suffix = _banner_shown(match)
    if suffix:
        return (
            "unknown",
            f"PHP {shown} is a pre-release. This bundle does not treat a pre-release as fixed.",
        )
    fixes = bundle.upstream_fixes(cve)
    fixed = fixes.get(f"{major}.{minor}")
    if fixed is None:
        return (
            "unknown",
            f"PHP {shown} has no upstream fixed release in this bundle. "
            "Check the vendor or move to a supported branch.",
        )
    fixed_text = ".".join(str(part) for part in fixed)
    if (major, minor, patch) < fixed:
        status = "affected_upstream"
        relation = "older than"
    else:
        status = "fixed_upstream"
        relation = "at or newer than"
    detail = (
        f"Unpacked PHP {shown} is {relation} upstream {fixed_text}. "
        "There is no package record for this file."
    )
    if bundle.stale:
        return (
            "stale_recheck_vendor",
            detail + _STALE_SUFFIX,
        )
    return status, detail


def version_matches_vendor(installed: str, rule: VendorRule) -> bool:
    """Reject a lookalike package that only sorts above the vendor's version.

    A third-party build can compare greater than a Debian security version
    while being a different supplier. Those strings stay unknown.
    """
    split = _split_installed(installed)
    if split is None:
        return False
    _upstream, revision = split
    if rule.version_pattern == "ubuntu":
        return "ubuntu" in installed
    if rule.version_pattern == "debian-release":
        return f"deb{rule.version_id}" in installed and _DEB_TOKEN.search(installed) is not None
    if rule.version_pattern == "debian-unstable":
        return _DOTTED.fullmatch(_upstream) is not None and (
            revision.isdigit() or _DEB_TOKEN.search(revision) is not None
        )
    return False


def closure_for(status: str, role: str, *, serving_verified: bool, mitigation: bool) -> str:
    if status == "stale_recheck_vendor":
        return "stale_recheck_vendor"
    if status in {"unknown", "not_assessed"}:
        return status
    if status in {"vendor_fix_confirmed", "fixed_upstream"}:
        if role not in _SERVING_ROLES:
            return "no_web_serving_runtime_observed"
        if serving_verified:
            if status == "vendor_fix_confirmed":
                return "vendor_fix_verified_for_serving_runtime"
            return "upstream_fix_verified_for_serving_runtime"
        return "patched_on_disk_live_runtime_not_verified"
    if status in {"below_vendor_fix", "affected_upstream"}:
        if mitigation:
            return "mitigation_observed_patch_still_needed"
        return "affected_evidence_found"
    return "unknown"


def links_are_verified(links: tuple[WorkerLink, ...]) -> bool:
    if not links:
        return False
    return all(link.tied and link.fresh is True for link in links)


def parse_banner_version(banner: str) -> str | None:
    match = _PHP_BANNER.search(banner)
    if match is None:
        return None
    shown, _suffix = _banner_shown(match)
    return shown


def _banner_shown(match: re.Match[str]) -> tuple[str, str]:
    """Return the version text and the pre-release suffix, keeping its separator."""
    suffix = match.group(5) or ""
    shown = f"{match.group(1)}.{match.group(2)}.{match.group(3)}{match.group(4) or ''}{suffix}"
    return shown, suffix


def _split_installed(version: str) -> tuple[str, str] | None:
    if not version or len(version) > 256:
        return None
    _epoch, separator, remainder = version.partition(":")
    body = remainder if separator else version
    upstream, hyphen, revision = body.rpartition("-")
    if hyphen == "":
        return body, ""
    if upstream == "":
        return None
    return upstream, revision
