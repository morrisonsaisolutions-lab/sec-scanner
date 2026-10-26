"""Operator text. The checker describes fixes. It does not apply them."""

from __future__ import annotations

TEMPORARY_MEASURES = (
    "Updating is the only complete fix PHP describes for CVE-2026-109618 and "
    "CVE-2026-109619. If an update is not available yet, the temporary measures "
    "below are incomplete. For CVE-2026-109618, memory_limit=-1 can be set where "
    "applications cannot override it, together with an external container or cgroup "
    "limit; do not use RLIMIT_AS or RLIMIT_DATA. For CVE-2026-109619, set "
    "session.upload_progress.enabled=0 in startup configuration and restart every "
    "worker. On PHP 8.5, fatal_error_backtraces=0 covers only the confirmed "
    "fatal-backtrace path. Disabling upload progress does not close CVE-2026-109618."
)

CONFIG_GUIDANCE = (
    "PHP had not published a fixed release for CVE-2026-115560 in this advisory "
    "bundle. The project recommends session.upload_progress.enabled=0 in startup "
    "configuration until the next regular bugfix release, then a restart of the "
    "serving workers. Check application impact before changing it. A static match "
    "is a reason to review the application, not proof the runtime condition occurs."
)


def patch_next_action(
    *,
    status: str,
    closure: str,
    name: str,
    fixed_version: str,
) -> str:
    if status == "stale_recheck_vendor":
        return (
            "The advisory bundle is outside its freshness window. Recheck the vendor "
            "or PHP advisory, install a current signed bundle, and scan again."
        )
    if status == "below_vendor_fix":
        fixed = f" {fixed_version} or newer" if fixed_version else ""
        return (
            f"Update {name} to the vendor package{fixed}, restart the workers that "
            "serve requests, and scan again. This checker will not install a package "
            "or restart a service."
        )
    if status == "affected_upstream":
        return (
            "Replace this unpacked PHP with a fixed upstream release, or with a vendor "
            "package this bundle can check. Restart the serving workers and scan again."
        )
    if closure == "patched_on_disk_live_runtime_not_verified":
        return (
            "The package on disk meets the bundled fix. A running worker was not tied "
            "to that file. Restart the serving service using the vendor's procedure "
            "and scan again while it is running."
        )
    if closure in {
        "vendor_fix_verified_for_serving_runtime",
        "upstream_fix_verified_for_serving_runtime",
    }:
        return (
            "The serving process was tied to the current file and started after that "
            "file's mtime. This is not a test that exploitation was attempted."
        )
    if status == "unknown":
        return "Check this runtime's supplier. This bundle has no fix record that matches it."
    if status == "not_assessed":
        return (
            "The version was not read. Use a readable package database, or pass "
            "--query-version for a binary you choose to execute."
        )
    if closure == "no_web_serving_runtime_observed":
        return (
            "No web-serving process was tied to this package. A CLI result does not "
            "close a different web runtime."
        )
    return "Review the evidence before treating this runtime as closed."
