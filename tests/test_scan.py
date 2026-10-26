from __future__ import annotations

import os
import shutil
import socket
import subprocess
from datetime import date
from pathlib import Path

import pytest

from sec_scanner.compare import compare_reports
from sec_scanner.discover import _names_match
from sec_scanner.errors import SecScannerError
from sec_scanner.models import ProcessObs
from sec_scanner.report import load_report, redact_report, render_text
from sec_scanner.scan import scan
from tests.support import write_ini, write_os, write_package, write_process

TODAY = date(2026, 10, 26)
BTIME = 1_700_000_000


def _finding(report: dict[str, object], rule: str, name: str) -> dict[str, object]:
    matches = [
        item
        for item in report["findings"]
        if isinstance(item, dict) and item.get("rule_id") == rule and _name(item) == name
    ]
    assert len(matches) == 1
    match = matches[0]
    assert isinstance(match, dict)
    return match


def _name(finding: dict[str, object]) -> str:
    subject = finding.get("subject")
    assert isinstance(subject, dict)
    return str(subject.get("name"))


def test_noble_backport_is_not_called_affected(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.13",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = On\n")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php8.3-fpm")
    assert finding["status"] == "vendor_fix_confirmed"
    assert finding["closure"] == "patched_on_disk_live_runtime_not_verified"
    text = str(finding["remediation"]) + str(finding["evidence"])
    assert "affected" not in str(finding["status"])
    assert "8.3.36" not in text or "package record" in text


def test_worker_started_after_the_fixed_binary_is_verified(tmp_path: Path) -> None:
    binary = _fixed_fpm(tmp_path)
    os.utime(binary, (BTIME + 50, BTIME + 50))
    write_process(tmp_path, 55, "php-fpm8.3", binary, start_ticks=10_000)
    report = scan(tmp_path, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php8.3-fpm")
    assert finding["closure"] == "vendor_fix_verified_for_serving_runtime"


def test_old_worker_and_deleted_exe_stay_unverified(tmp_path: Path) -> None:
    binary = _fixed_fpm(tmp_path)
    os.utime(binary, (BTIME + 500, BTIME + 500))
    write_process(tmp_path, 55, "php-fpm8.3", binary, start_ticks=10_000)
    report = scan(tmp_path, today=TODAY)
    assert _finding(report, "CVE-2026-109618", "php8.3-fpm")["closure"] == (
        "patched_on_disk_live_runtime_not_verified"
    )
    deleted = tmp_path / "deleted"
    write_os(deleted, "ubuntu", "24.04", "noble")
    write_package(
        deleted,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.13",
        files=("/usr/sbin/php-fpm8.3",),
    )
    target = deleted / "usr/sbin/php-fpm8.3"
    write_process(deleted, 55, "php-fpm8.3", target, start_ticks=20_000, deleted=True)
    again = scan(deleted, today=TODAY)
    assert _finding(again, "CVE-2026-109618", "php8.3-fpm")["closure"] == (
        "patched_on_disk_live_runtime_not_verified"
    )


def test_upload_progress_mitigation_does_not_close_the_oom_finding(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = 0\n")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    oom = _finding(report, "CVE-2026-109618", "php8.3-fpm")
    stale = _finding(report, "CVE-2026-109619", "php8.3-fpm")
    assert oom["status"] == "below_vendor_fix"
    assert oom["closure"] == "affected_evidence_found"
    assert stale["closure"] == "mitigation_observed_patch_still_needed"
    config = _finding(report, "CVE-2026-115560", "php 8.3 fpm")
    assert config["closure"] == "mitigation_observed_patch_still_needed"
    assert "not proof" in str(config["remediation"])


def test_risky_serializer_is_a_review_lead(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(tmp_path, "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", files=("/usr/bin/php8.3",))
    write_ini(
        tmp_path,
        "8.3",
        "cli",
        "session.serialize_handler = php_serialize\nsession.upload_progress.enabled = On\n",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-115560", "php 8.3 cli")
    assert finding["status"] == "potential_configuration_to_review"
    assert "not proof" in str(finding["limitations"])


def test_app_text_match_is_not_proof_and_symlinks_stay_inside(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.php").write_text(
        "<?php\nini_set('session.serialize_handler', 'php');\nsession_start();\n",
        encoding="utf-8",
    )
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-TOKEN", encoding="utf-8")
    os.symlink(secret, app / "leak.php")
    report = scan(tmp_path, app_dirs=(app,), read_processes=False, today=TODAY)
    dumped = str(report)
    assert "TOP-SECRET-TOKEN" not in dumped
    app_finding = _finding(report, "CVE-2026-115560", "application source")
    assert app_finding["status"] == "potential_configuration_to_review"
    assert "does not show that the code runs" in str(app_finding["limitations"])


def test_scan_does_not_write_or_connect_or_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    before = _snapshot(tmp_path)

    def refuse_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scan opened a socket")

    def refuse_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scan executed a command")

    monkeypatch.setattr(socket, "socket", refuse_socket)
    monkeypatch.setattr(socket, "create_connection", refuse_socket)
    monkeypatch.setattr(subprocess, "run", refuse_run)
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _snapshot(tmp_path) == before
    assert report["scan"]["execution"] == []  # type: ignore[index]


def test_symlink_outside_the_root_is_not_read(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    outside = tmp_path.parent / f"sec-scanner-secret-{tmp_path.name}"
    outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
    binary_dir = tmp_path / "usr" / "bin"
    binary_dir.mkdir(parents=True)
    os.symlink(outside, binary_dir / "php")
    try:
        report = scan(tmp_path, read_processes=False, today=TODAY)
    finally:
        outside.unlink(missing_ok=True)
    assert "OUTSIDE-SECRET" not in str(report)
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("outside" in str(item) for item in skipped)


def test_query_version_is_explicit_and_does_not_override_a_package(
    tmp_path: Path,
) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-cli",
        "8.3.6-0ubuntu0.24.04.13",
        files=("/usr/bin/php8.3",),
    )
    binary = tmp_path / "usr/bin/php8.3"
    binary.write_text("#!/bin/sh\necho 'PHP 8.3.6 (cli)'\n", encoding="utf-8")
    binary.chmod(0o755)
    report = scan(tmp_path, query_versions=(binary,), read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php8.3-cli")
    assert finding["status"] == "vendor_fix_confirmed"
    assert "package record is the verdict" in str(finding["evidence"])
    execution = report["scan"]["execution"]  # type: ignore[index]
    assert execution == [{"argv": [str(binary.resolve()), "-v"]}]


def test_unpacked_upstream_binary(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "usr/local/bin/php"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\necho 'PHP 8.2.34 (cli)'\n", encoding="utf-8")
    binary.chmod(0o755)
    quiet = scan(tmp_path, read_processes=False, today=TODAY)
    quiet_finding = _finding(quiet, "CVE-2026-109618", "php")
    assert quiet_finding["status"] == "not_assessed"
    asked = scan(tmp_path, query_versions=(binary,), read_processes=False, today=TODAY)
    asked_finding = _finding(asked, "CVE-2026-109618", "php")
    assert asked_finding["status"] == "affected_upstream"


def test_missing_runtime_is_not_closure(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    binary = _fixed_fpm(first_root)
    os.utime(binary, (BTIME + 50, BTIME + 50))
    write_process(first_root, 55, "php-fpm8.3", binary, start_ticks=10_000)
    baseline = scan(first_root, today=TODAY)
    write_os(second_root, "ubuntu", "24.04", "noble")
    current = scan(second_root, read_processes=False, today=TODAY)
    compared = compare_reports(baseline, current)
    assert compared["not_seen"]
    assert compared["resolved"] == []


def test_cli_fix_does_not_close_a_web_gap(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(tmp_path, "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", files=("/usr/bin/php8.3",))
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    cli = _finding(report, "CVE-2026-109618", "php8.3-cli")
    fpm = _finding(report, "CVE-2026-109618", "php8.3-fpm")
    assert cli["closure"] == "no_web_serving_runtime_observed"
    assert fpm["status"] == "below_vendor_fix"


def test_oversized_application_file_is_skipped(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    app = tmp_path / "app"
    app.mkdir()
    (app / "big.php").write_bytes(b"<?php\n" + b"A" * (1_048_576))
    report = scan(tmp_path, app_dirs=(app,), read_processes=False, today=TODAY)
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("larger than the read limit" in str(item) for item in skipped)
    assert "AAAA" not in str(_finding(report, "CVE-2026-115560", "application source")["evidence"])


def test_panel_binary_is_found_without_a_package(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "opt/plesk/php/8.3/bin/php"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    ini = tmp_path / "opt/plesk/php/8.3/etc/php.ini"
    ini.parent.mkdir(parents=True, exist_ok=True)
    ini.write_text("session.upload_progress.enabled = 0\n", encoding="utf-8")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php")
    assert finding["status"] == "not_assessed"
    assert finding["closure"] == "not_assessed"
    assert str(binary) == str(_subject(finding).get("path"))
    assert "not confirmed as the ini PHP loads" in str(finding["evidence"])


def test_systemd_execstart_is_inventory_not_a_host_path(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "opt/custom/sbin/php-fpm"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    unit = tmp_path / "etc/systemd/system/php-fpm.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("ExecStart=/opt/custom/sbin/php-fpm --nodaemonize\n", encoding="utf-8")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php-fpm")
    assert finding["status"] == "not_assessed"
    assert finding["role"] == "fpm"
    assert str(binary) == str(_subject(finding).get("path"))


def test_running_binary_outside_the_search_dirs_is_reported(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "opt/custom/bin/php"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    write_process(tmp_path, 77, "php", binary, start_ticks=10_000)
    report = scan(tmp_path, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php")
    assert finding["status"] == "not_assessed"
    assert str(binary) == str(_subject(finding).get("path"))


def test_apache_admin_text_is_not_a_locked_mitigation(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "libapache2-mod-php8.3",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/lib/apache2/modules/libphp8.3.so",),
    )
    write_ini(tmp_path, "8.3", "apache2", "session.upload_progress.enabled = On\n")
    config = tmp_path / "etc/apache2/mods-enabled/php8.3.conf"
    config.parent.mkdir(parents=True)
    config.write_text(
        "php_admin_flag session.upload_progress.enabled Off\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    oom = _finding(report, "CVE-2026-109618", "libapache2-mod-php8.3")
    stale = _finding(report, "CVE-2026-109619", "libapache2-mod-php8.3")
    assert oom["status"] == "below_vendor_fix"
    assert oom["closure"] == "affected_evidence_found"
    assert stale["closure"] == "affected_evidence_found"
    assert "context was not evaluated" in str(stale["evidence"])


def test_relative_fpm_include_can_lock_upload_progress(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = On\n")
    extra = tmp_path / "etc/php/8.3/fpm/extra"
    extra.mkdir(parents=True)
    (extra / "www.conf").write_text(
        "php_admin_flag[session.upload_progress.enabled] = Off\n",
        encoding="utf-8",
    )
    conf = tmp_path / "etc/php/8.3/fpm/php-fpm.conf"
    conf.write_text('include="extra/*.conf"\n', encoding="utf-8")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    stale = _finding(report, "CVE-2026-109619", "php8.3-fpm")
    assert stale["closure"] == "mitigation_observed_patch_still_needed"
    config = _finding(report, "CVE-2026-115560", "php 8.3 fpm")
    assert "upload progress locked off=True" in str(config["evidence"])


def test_fpm_include_outside_the_root_is_not_a_clean_config(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = Off\n")
    secret = tmp_path.parent / f"secret-fpm-{tmp_path.name}.conf"
    secret.write_text(
        "php_value[session.upload_progress.enabled] = On\n"
        "php_value[session.serialize_handler] = php_serialize\n",
        encoding="utf-8",
    )
    conf = tmp_path / "etc/php/8.3/fpm/php-fpm.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"include=../../../../../{secret.name}\n",
        encoding="utf-8",
    )
    try:
        report = scan(tmp_path, read_processes=False, today=TODAY)
    finally:
        secret.unlink()
    stale = _finding(report, "CVE-2026-109619", "php8.3-fpm")
    config = _finding(report, "CVE-2026-115560", "php 8.3 fpm")
    assert stale["closure"] == "affected_evidence_found"
    assert config["status"] == "not_assessed"
    assert "value named in the PHP notice" not in str(config["evidence"])
    assert secret.name not in str(report)
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("outside the scan root" in str(item) for item in skipped)


def test_nested_fpm_includes_stop_at_the_cap(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = Off\n")
    fpm = tmp_path / "etc/php/8.3/fpm"
    nested = fpm / "nested"
    nested.mkdir(parents=True)
    for index in range(64):
        (nested / f"{index:02d}.conf").write_text("listen = /run/php.sock\n", encoding="utf-8")
    (fpm / "first.conf").write_text("include=nested/*.conf\n", encoding="utf-8")
    rest = fpm / "rest"
    rest.mkdir()
    (rest / "risky.conf").write_text(
        "php_value[session.serialize_handler] = php_serialize\n",
        encoding="utf-8",
    )
    (fpm / "php-fpm.conf").write_text(
        "include=first.conf\ninclude=rest/*.conf\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    config = _finding(report, "CVE-2026-115560", "php 8.3 fpm")
    assert config["status"] == "not_assessed"
    assert "value named in the PHP notice" not in str(config["evidence"])
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("truncated" in str(item) for item in skipped)


def test_apache_include_names_a_risky_serializer(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "libapache2-mod-php8.3",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/lib/apache2/modules/libphp8.3.so",),
    )
    write_ini(tmp_path, "8.3", "apache2", "session.upload_progress.enabled = On\n")
    included = tmp_path / "srv/apache/php.conf"
    included.parent.mkdir(parents=True)
    included.write_text(
        "php_value session.serialize_handler php_serialize\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "etc/apache2/apache2.conf"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        'ServerRoot "/srv/apache"\nInclude php.conf\n',
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    config = _finding(report, "CVE-2026-115560", "php 8.3 apache2")
    assert config["status"] == "potential_configuration_to_review"
    assert "Apache text names a session.serialize_handler" in str(config["evidence"])
    assert "not a locked mitigation" in str(config["limitations"])
    stale = _finding(report, "CVE-2026-109619", "libapache2-mod-php8.3")
    assert stale["closure"] == "affected_evidence_found"


def test_apache_include_outside_the_root_is_not_clean(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "libapache2-mod-php8.3",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/lib/apache2/modules/libphp8.3.so",),
    )
    write_ini(tmp_path, "8.3", "apache2", "session.upload_progress.enabled = On\n")
    secret = tmp_path.parent / f"secret-apache-{tmp_path.name}.conf"
    secret.write_text(
        "php_value session.serialize_handler php_serialize\n"
        "php_value memory_limit LEAK-APACHE-9f3a\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "etc/apache2/apache2.conf"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        f"Include ../../../{secret.name}\n",
        encoding="utf-8",
    )
    try:
        report = scan(tmp_path, read_processes=False, today=TODAY)
    finally:
        secret.unlink()
    config = _finding(report, "CVE-2026-115560", "php 8.3 apache2")
    assert config["status"] == "not_assessed"
    assert "LEAK-APACHE-9f3a" not in str(report)
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("outside the scan root" in str(item) for item in skipped)


def test_missing_include_optional_is_not_a_skip(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "libapache2-mod-php8.3",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/lib/apache2/modules/libphp8.3.so",),
    )
    write_ini(tmp_path, "8.3", "apache2", "session.upload_progress.enabled = On\n")
    config_path = tmp_path / "etc/apache2/apache2.conf"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "IncludeOptional /etc/apache2/missing-optional/*.conf\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    config = _finding(report, "CVE-2026-115560", "php 8.3 apache2")
    assert config["status"] == "no_matching_static_evidence"
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert not any("apache include" in str(item) for item in skipped)


def test_missing_required_apache_include_is_not_clean(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "libapache2-mod-php8.3",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/lib/apache2/modules/libphp8.3.so",),
    )
    write_ini(tmp_path, "8.3", "apache2", "session.upload_progress.enabled = On\n")
    config_path = tmp_path / "etc/apache2/apache2.conf"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("Include /etc/apache2/missing-required.conf\n", encoding="utf-8")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    config = _finding(report, "CVE-2026-115560", "php 8.3 apache2")
    assert config["status"] == "not_assessed"
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("matched no file" in str(item) for item in skipped)


def test_unversioned_libphp_is_mod_php(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "usr/lib/apache2/modules/libphp.so"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "libphp.so")
    assert finding["role"] == "mod_php"


def test_memory_limit_lock_does_not_close_upload_progress(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = On\n")
    pool = tmp_path / "etc/php/8.3/fpm/pool.d/www.conf"
    pool.parent.mkdir(parents=True)
    pool.write_text("php_admin_value[memory_limit] = -1\n", encoding="utf-8")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    oom = _finding(report, "CVE-2026-109618", "php8.3-fpm")
    stale = _finding(report, "CVE-2026-109619", "php8.3-fpm")
    assert oom["closure"] == "mitigation_observed_patch_still_needed"
    assert stale["closure"] == "affected_evidence_found"
    assert "fatal_error_backtraces" in str(oom["evidence"])


def test_time_limit_stops_before_a_verdict(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    ticks = {"count": 0}

    def clock() -> float:
        ticks["count"] += 1
        return 0.0 if ticks["count"] == 1 else 100.0

    report = scan(tmp_path, today=TODAY, clock=clock, deadline_seconds=60)
    assert report["findings"] == []
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("time limit" in str(item) for item in skipped)
    scan_record = report["scan"]
    assert isinstance(scan_record, dict)
    assert scan_record["completion"] == "partial"


def test_summary_lists_the_searched_locations(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    text = render_text(report)
    assert "Searched locations:" in text
    assert "usr/bin" in text
    assert "No PHP runtime was found" in text
    assert "not proof" in text


def test_mitigation_remains_open_when_reports_are_compared(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = 0\n")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    compared = compare_reports(report, report)
    mitigated = compared["mitigated"]
    assert isinstance(mitigated, list)
    assert any(
        isinstance(item, dict) and item.get("closure") == "mitigation_observed_patch_still_needed"
        for item in mitigated
    )
    assert compared["resolved"] == []
    assert compared["open_count"] != 0
    current = compared["current"]
    assert isinstance(current, dict)
    assert current["advisory_age_days"] == 0
    assert current["advisory_bundle"] == "php2shell-2026-10-26"


def test_ini_symlink_outside_the_root_is_not_a_mitigation(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    outside = tmp_path.parent / f"secret-ini-{tmp_path.name}"
    outside.write_text(
        "session.upload_progress.enabled = 0\nTOP-SECRET-INI\n",
        encoding="utf-8",
    )
    ini = tmp_path / "etc/php/8.3/fpm/php.ini"
    ini.parent.mkdir(parents=True)
    os.symlink(outside, ini)
    try:
        report = scan(tmp_path, read_processes=False, today=TODAY)
    finally:
        outside.unlink(missing_ok=True)
    assert "TOP-SECRET-INI" not in str(report)
    finding = _finding(report, "CVE-2026-109619", "php8.3-fpm")
    assert finding["closure"] == "affected_evidence_found"


def test_unreadable_pool_blocks_a_mitigation_claim(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = 0\n")
    outside = tmp_path.parent / f"secret-pool-{tmp_path.name}"
    outside.write_text("php_admin_value[memory_limit] = 32M\nPOOL-SECRET\n", encoding="utf-8")
    pool = tmp_path / "etc/php/8.3/fpm/pool.d/www.conf"
    pool.parent.mkdir(parents=True)
    os.symlink(outside, pool)
    try:
        report = scan(tmp_path, read_processes=False, today=TODAY)
    finally:
        outside.unlink(missing_ok=True)
    assert "POOL-SECRET" not in str(report)
    assert _finding(report, "CVE-2026-109619", "php8.3-fpm")["closure"] == (
        "affected_evidence_found"
    )


def test_cgi_bin_and_in_root_directory_symlink_are_found(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    cgi = tmp_path / "usr/lib/cgi-bin/php-cgi"
    cgi.parent.mkdir(parents=True)
    cgi.write_bytes(b"")
    real = tmp_path / "opt/real/bin"
    real.mkdir(parents=True)
    (real / "php").write_bytes(b"")
    link = tmp_path / "opt/plesk/php/8.3/bin"
    link.parent.mkdir(parents=True)
    link.symlink_to(real, target_is_directory=True)
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-109618", "php-cgi")["role"] == "cgi"
    assert str(real / "php") == str(
        _subject(_finding(report, "CVE-2026-109618", "php")).get("path")
    )


def test_user_ini_and_htaccess_are_review_leads(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    app = tmp_path / "app"
    app.mkdir()
    (app / ".user.ini").write_text(
        "session.serialize_handler = php_serialize\n",
        encoding="utf-8",
    )
    (app / ".htaccess").write_text(
        "php_value session.serialize_handler php_binary\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, app_dirs=(app,), read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-115560", "application source")
    assert finding["status"] == "potential_configuration_to_review"
    evidence = str(finding["evidence"])
    assert "php_serialize" in evidence
    assert "php_binary" in evidence


def test_pool_chroot_is_reported_and_not_entered(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = On\n")
    jail = tmp_path / "srv/jail/secret.ini"
    jail.parent.mkdir(parents=True)
    jail.write_text("JAIL-SECRET\n", encoding="utf-8")
    pool = tmp_path / "etc/php/8.3/fpm/pool.d/www.conf"
    pool.parent.mkdir(parents=True)
    pool.write_text(
        "chroot = /srv/jail\nphp_admin_value[memory_limit] = -1\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert "JAIL-SECRET" not in str(report)
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("chroot=/srv/jail" in str(item) for item in skipped)
    assert _finding(report, "CVE-2026-109618", "php8.3-fpm")["closure"] == (
        "mitigation_observed_patch_still_needed"
    )


def test_parent_directory_symlink_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"secret-etc-{tmp_path.name}"
    outside.mkdir()
    (outside / "os-release").write_text(
        'ID=evil\nVERSION_ID=1\nVERSION_CODENAME=nope\nPRETTY_NAME="TREE-SECRET"\n',
        encoding="utf-8",
    )
    os.symlink(outside, tmp_path / "etc")
    try:
        report = scan(tmp_path, read_processes=False, today=TODAY)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
    assert "TREE-SECRET" not in str(report)
    os_info = report["os"]
    assert isinstance(os_info, dict)
    assert os_info["id"] == ""
    assert os_info["pretty_name"] == ""


def test_clock_file_outside_the_root_does_not_make_a_worker_fresh(tmp_path: Path) -> None:
    binary = _fixed_fpm(tmp_path)
    os.utime(binary, (BTIME + 500, BTIME + 500))
    write_process(tmp_path, 55, "php-fpm8.3", binary, start_ticks=10_000)
    outside = tmp_path.parent / f"secret-ticks-{tmp_path.name}"
    outside.write_text("1\n", encoding="utf-8")
    ticks = tmp_path / "proc" / "clk_tck"
    ticks.unlink()
    os.symlink(outside, ticks)
    try:
        report = scan(tmp_path, today=TODAY)
    finally:
        outside.unlink(missing_ok=True)
    assert _finding(report, "CVE-2026-109618", "php8.3-fpm")["closure"] == (
        "patched_on_disk_live_runtime_not_verified"
    )


def test_proc_directory_outside_the_root_is_not_walked(tmp_path: Path) -> None:
    binary = _fixed_fpm(tmp_path)
    os.utime(binary, (BTIME + 50, BTIME + 50))
    outside = tmp_path.parent / f"secret-proc-{tmp_path.name}"
    write_process(outside, 55, "php-fpm8.3", binary, start_ticks=10_000)
    os.symlink(outside / "proc", tmp_path / "proc")
    try:
        report = scan(tmp_path, today=TODAY)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
    assert _finding(report, "CVE-2026-109618", "php8.3-fpm")["closure"] == (
        "patched_on_disk_live_runtime_not_verified"
    )
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert any("outside" in str(item) for item in skipped)


def test_php_in_cgi_bin_is_cgi(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "usr/lib/cgi-bin/php"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-109618", "php")["role"] == "cgi"


def test_pool_php_value_on_is_not_upload_mitigation(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = 0\n")
    pool = tmp_path / "etc/php/8.3/fpm/pool.d/www.conf"
    pool.parent.mkdir(parents=True)
    pool.write_text(
        "php_value[session.upload_progress.enabled] = On\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-109619", "php8.3-fpm")["closure"] == (
        "affected_evidence_found"
    )


def test_pool_admin_off_beats_php_value_on(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = On\n")
    pool = tmp_path / "etc/php/8.3/fpm/pool.d/www.conf"
    pool.parent.mkdir(parents=True)
    pool.write_text(
        "php_value[session.upload_progress.enabled] = On\n"
        "php_admin_value[session.upload_progress.enabled] = Off\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-109619", "php8.3-fpm")["closure"] == (
        "mitigation_observed_patch_still_needed"
    )


def test_pool_php_value_serializer_is_a_review_lead(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path, "php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", files=("/usr/sbin/php-fpm8.3",)
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = On\n")
    pool = tmp_path / "etc/php/8.3/fpm/pool.d/www.conf"
    pool.parent.mkdir(parents=True)
    pool.write_text(
        "php_value[session.serialize_handler] = php_serialize\n",
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-115560", "php 8.3 fpm")["status"] == (
        "potential_configuration_to_review"
    )


def test_bom_does_not_hide_the_first_ini_setting(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "\ufeffsession.upload_progress.enabled = 0\n")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-109619", "php8.3-fpm")["closure"] == (
        "mitigation_observed_patch_still_needed"
    )


def test_broken_conf_d_symlink_blocks_a_mitigation_claim(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    write_package(
        tmp_path,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.12",
        files=("/usr/sbin/php-fpm8.3",),
    )
    write_ini(tmp_path, "8.3", "fpm", "session.upload_progress.enabled = 0\n")
    conf = tmp_path / "etc/php/8.3/fpm/conf.d"
    conf.mkdir(parents=True)
    os.symlink(conf / "missing.ini", conf / "99-missing.ini")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    assert _finding(report, "CVE-2026-109619", "php8.3-fpm")["closure"] == (
        "affected_evidence_found"
    )


def test_user_unit_env_execstart_is_found(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "opt/custom/sbin/php-fpm"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    unit = tmp_path / "etc/systemd/user/php-worker.service"
    unit.parent.mkdir(parents=True)
    unit.write_text(
        'ExecStart=/usr/bin/env "/opt/custom/sbin/php-fpm" --nodaemonize\n',
        encoding="utf-8",
    )
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "php-fpm")
    assert finding["role"] == "fpm"
    assert str(binary) == str(_subject(finding).get("path"))


def test_bare_execstart_name_is_resolved_inside_the_root(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    binary = tmp_path / "usr/sbin/lsphp8.1"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    unit = tmp_path / "lib/systemd/system/lsphp.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("ExecStart=/usr/bin/env lsphp8.1\n", encoding="utf-8")
    report = scan(tmp_path, read_processes=False, today=TODAY)
    finding = _finding(report, "CVE-2026-109618", "lsphp8.1")
    assert finding["role"] == "litespeed"
    assert str(binary) == str(_subject(finding).get("path"))
    skipped = report["coverage"]["skipped"]  # type: ignore[index]
    assert isinstance(skipped, list)
    assert not any("not found" in str(item) for item in skipped)


def test_skipped_application_file_is_not_a_clean_result(tmp_path: Path) -> None:
    write_os(tmp_path, "ubuntu", "24.04", "noble")
    app = tmp_path / "app"
    app.mkdir()
    (app / "ok.php").write_text("<?php echo 1;\n", encoding="utf-8")
    outside = tmp_path.parent / f"secret-app-{tmp_path.name}"
    outside.write_text(
        "<?php ini_set('session.serialize_handler', 'php_serialize');\nAPP-SECRET\n",
        encoding="utf-8",
    )
    os.symlink(outside, app / "leak.php")
    try:
        report = scan(tmp_path, app_dirs=(app,), read_processes=False, today=TODAY)
    finally:
        outside.unlink(missing_ok=True)
    assert "APP-SECRET" not in str(report)
    assert _finding(report, "CVE-2026-115560", "application source")["status"] == "not_assessed"


def test_redact_hides_root_and_home_paths() -> None:
    report = {
        "schema_version": 1,
        "identity": "keep",
        "note": "see /root/secret and /home/patrick/code",
        "nested": {"identity": "also-keep", "path": "/root/secret/key"},
    }
    redacted = redact_report(report, "/home/patrick")
    dumped = str(redacted)
    assert "/root/secret" not in dumped
    assert "/home/patrick" not in dumped
    assert redacted["identity"] == "keep"
    nested = redacted["nested"]
    assert isinstance(nested, dict)
    assert nested["identity"] == "also-keep"


def test_oversized_report_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"schema_version": 1, "findings": []}\n', encoding="utf-8")
    monkeypatch.setattr("sec_scanner.report._MAX_REPORT_BYTES", 8)
    with pytest.raises(SecScannerError, match="read limit"):
        load_report(path)


def test_unreadable_exe_name_match_is_a_whole_token() -> None:
    process = ProcessObs(
        1,
        "php-fpm8.3",
        "php-fpm8.3: pool www",
        None,
        False,
        None,
        (),
        "denied",
    )
    assert _names_match(process, {"php"}) is False
    assert _names_match(process, {"php-fpm8.3"}) is True
    renamed = ProcessObs(
        2,
        "php-fpm8.",
        "/usr/sbin/php-fpm8.3: pool www",
        None,
        False,
        None,
        (),
        "denied",
    )
    assert _names_match(renamed, {"php"}) is False
    assert _names_match(renamed, {"php-fpm8.3"}) is True


def _subject(finding: dict[str, object]) -> dict[str, object]:
    subject = finding.get("subject")
    assert isinstance(subject, dict)
    return subject


def _fixed_fpm(root: Path) -> Path:
    write_os(root, "ubuntu", "24.04", "noble")
    write_package(
        root,
        "php8.3-fpm",
        "8.3.6-0ubuntu0.24.04.13",
        files=("/usr/sbin/php-fpm8.3",),
    )
    return root / "usr/sbin/php-fpm8.3"


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
