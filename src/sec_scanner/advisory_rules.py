"""Authoring source for the signed advisory bundle.

Verdicts are loaded from the signed JSON, not from this module. Change a rule
here, then run ``scripts/build_bundle.py`` so the signed bundle changes with it.
"""

from __future__ import annotations

BUNDLE_ID = "php2shell-2026-10-26"
BUNDLE_VERSION = 1
REVIEWED_ON = "2026-10-26"
FRESHNESS_WINDOW_DAYS = 14

_UPSTREAM_FIXED: list[dict[str, str]] = [
    {"branch": "8.2", "version": "8.2.35"},
    {"branch": "8.3", "version": "8.3.36"},
    {"branch": "8.4", "version": "8.4.27"},
    {"branch": "8.5", "version": "8.5.12"},
]

_PHP_URL = "https://www.php.net/archive/2026.php"
_GHSA_618 = "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"
_GHSA_619 = "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"

_UBUNTU_URLS = [
    "https://ubuntu.com/security/notices/USN-8948-1",
    "https://ubuntu.com/security/CVE-2026-109618",
    "https://ubuntu.com/security/CVE-2026-109619",
    "https://ubuntu.com/blog/php2shell-vulnerability-fixes-available",
]
_DEBIAN_618 = "https://security-tracker.debian.org/tracker/CVE-2026-109618"
_DEBIAN_619 = "https://security-tracker.debian.org/tracker/CVE-2026-109619"
_DLA = "https://security-tracker.debian.org/tracker/DLA-4848-1"
_DSA = "https://security-tracker.debian.org/tracker/DSA-6574-1"

# Fixed versions checked on 2026-10-26 against the Ubuntu CVE pages, USN-8948-1,
# and the Debian security tracker. Both CVEs use the same package versions there.
_UBUNTU: list[tuple[str, str, str, str]] = [
    ("14.04", "trusty", "php5", "5.5.9+dfsg-1ubuntu4.29+esm18"),
    ("16.04", "xenial", "php7.0", "7.0.33-0ubuntu0.16.04.16+esm22"),
    ("18.04", "bionic", "php7.2", "7.2.24-0ubuntu0.18.04.17+esm14"),
    ("20.04", "focal", "php7.4", "7.4.3-4ubuntu2.29+esm5"),
    ("22.04", "jammy", "php8.1", "8.1.2-1ubuntu2.28"),
    ("24.04", "noble", "php8.3", "8.3.6-0ubuntu0.24.04.13"),
    ("26.04", "resolute", "php8.5", "8.5.4-0ubuntu1.5"),
    ("26.10", "stonking", "php8.5", "8.5.9-0ubuntu2.1"),
]
_DEBIAN: list[tuple[str, str, str, str, str]] = [
    ("12", "bookworm", "php8.2", "8.2.35-1~deb12u1", "debian-release"),
    ("13", "trixie", "php8.4", "8.4.27-1~deb13u1", "debian-release"),
    ("", "forky", "php8.4", "8.4.27-1", "debian-unstable"),
    ("", "sid", "php8.4", "8.4.27-1", "debian-unstable"),
]


def document() -> dict[str, object]:
    return {
        "bundle_id": BUNDLE_ID,
        "bundle_version": BUNDLE_VERSION,
        "reviewed_on": REVIEWED_ON,
        "freshness_window_days": FRESHNESS_WINDOW_DAYS,
        "cves": {
            "CVE-2026-109618": _runtime_cve(
                "Out-of-memory request-state corruption in PHP request handling.",
                [_PHP_URL, _GHSA_618],
            ),
            "CVE-2026-109619": _runtime_cve(
                "Stale worker-global state can be consumed by a later request.",
                [_PHP_URL, _GHSA_619],
            ),
            "CVE-2026-115560": {
                "title": ("Unusual session serializer switch while upload progress stays enabled."),
                "source_urls": [_PHP_URL],
                "source_published": "2026-10-23",
                "reviewed_on": REVIEWED_ON,
                "upstream_fixed": [],
                "note": (
                    "As of 2026-10-26 PHP had not published a fixed release or a full "
                    "advisory. The 23 October and 26 October notices recommend "
                    "session.upload_progress.enabled=0 until the next regular bugfix "
                    "release. The 8.2.35, 8.3.36, 8.4.27, and 8.5.12 releases are not "
                    "treated as a fix for this CVE."
                ),
            },
        },
        "vendor_rules": _vendor_rules(),
    }


def _runtime_cve(title: str, urls: list[str]) -> dict[str, object]:
    return {
        "title": title,
        "source_urls": urls,
        "source_published": "2026-10-21",
        "reviewed_on": REVIEWED_ON,
        "upstream_fixed": [dict(item) for item in _UPSTREAM_FIXED],
        "note": (
            "PHP 8.1 and older have no fixed upstream release in this bundle. "
            "A matching vendor rule can still confirm a backport. PHP 8.6 has no "
            "stable release in this bundle; php.net said 8.6.0RC4 contains these "
            "fixes and is not for production. Pre-releases stay unknown."
        ),
    }


def _vendor_rules() -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    for version_id, codename, source, fixed in _UBUNTU:
        rules.append(
            {
                "os_id": "ubuntu",
                "version_id": version_id,
                "codename": codename,
                "source_package": source,
                "fixed_version": fixed,
                "version_pattern": "ubuntu",
                "cves": ["CVE-2026-109618", "CVE-2026-109619"],
                "source_urls": list(_UBUNTU_URLS),
                "source_published": "2026-10-21",
                "reviewed_on": REVIEWED_ON,
                "note": "USN-8948-1 and the Ubuntu CVE pages list this package version.",
            }
        )
    for version_id, codename, source, fixed, pattern in _DEBIAN:
        origin = _DLA if codename == "bookworm" else _DSA if codename == "trixie" else _DEBIAN_618
        rules.append(
            {
                "os_id": "debian",
                "version_id": version_id,
                "codename": codename,
                "source_package": source,
                "fixed_version": fixed,
                "version_pattern": pattern,
                "cves": ["CVE-2026-109618", "CVE-2026-109619"],
                "source_urls": [_DEBIAN_618, _DEBIAN_619, origin],
                "source_published": "2026-10-21",
                "reviewed_on": REVIEWED_ON,
                "note": ("Debian security tracker lists the same fixed version for both CVEs."),
            }
        )
    return rules
