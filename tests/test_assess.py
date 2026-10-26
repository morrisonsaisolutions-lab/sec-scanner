from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from sec_scanner.advisory import DATA_DIR, AdvisoryError, load_for_scan, load_path
from sec_scanner.advisory_rules import document
from sec_scanner.assess import classify_package, classify_upstream_banner

TODAY = date(2026, 10, 26)
CVE = "CVE-2026-109618"


@pytest.fixture(scope="module")
def bundle():  # type: ignore[no-untyped-def]
    loaded, notes = load_for_scan(None, TODAY)
    assert notes == ()
    return loaded


def test_signed_bundle_matches_the_authoring_source(bundle) -> None:  # type: ignore[no-untyped-def]
    assert json.loads((DATA_DIR / "bundle.json").read_text(encoding="utf-8")) == document()
    assert bundle.stale is False
    assert bundle.age_days == 0


def test_ubuntu_backport_is_a_vendor_fix_not_an_upstream_miss(bundle) -> None:  # type: ignore[no-untyped-def]
    status, detail = classify_package(
        bundle,
        os_id="ubuntu",
        version_id="24.04.1",
        codename="noble",
        source_package="php8.3",
        installed_version="8.3.6-0ubuntu0.24.04.13",
        cve=CVE,
    )
    assert status == "vendor_fix_confirmed"
    assert "8.3.6-0ubuntu0.24.04.13" in detail


def test_ubuntu_package_below_the_vendor_fix(bundle) -> None:  # type: ignore[no-untyped-def]
    status, _detail = classify_package(
        bundle,
        os_id="ubuntu",
        version_id="24.04",
        codename="noble",
        source_package="php8.3",
        installed_version="8.3.6-0ubuntu0.24.04.12",
        cve=CVE,
    )
    assert status == "below_vendor_fix"


def test_debian_bookworm_fix_and_sury_lookalike(bundle) -> None:  # type: ignore[no-untyped-def]
    fixed, _detail = classify_package(
        bundle,
        os_id="debian",
        version_id="12",
        codename="bookworm",
        source_package="php8.2",
        installed_version="8.2.35-1~deb12u1",
        cve="CVE-2026-109619",
    )
    lookalike, detail = classify_package(
        bundle,
        os_id="debian",
        version_id="12",
        codename="bookworm",
        source_package="php8.2",
        installed_version="8.2.35-1+0~20261021.94+debian12~1.gbp8bff78",
        cve=CVE,
    )
    assert fixed == "vendor_fix_confirmed"
    assert lookalike == "unknown"
    assert "version pattern" in detail


def test_sid_simple_version_is_fixed_and_sury_style_is_not(bundle) -> None:  # type: ignore[no-untyped-def]
    fixed, _detail = classify_package(
        bundle,
        os_id="debian",
        version_id="",
        codename="sid",
        source_package="php8.4",
        installed_version="8.4.27-1",
        cve=CVE,
    )
    other, _other = classify_package(
        bundle,
        os_id="debian",
        version_id="",
        codename="sid",
        source_package="php8.4",
        installed_version="8.4.27-1+0~20261021.57+debian13~1.gbp7636b9",
        cve=CVE,
    )
    assert fixed == "vendor_fix_confirmed"
    assert other == "unknown"


def test_eol_and_unmapped_packages_stay_unknown(bundle) -> None:  # type: ignore[no-untyped-def]
    eol, _detail = classify_package(
        bundle,
        os_id="debian",
        version_id="11",
        codename="bullseye",
        source_package="php7.4",
        installed_version="7.4.33-1+deb11u5",
        cve=CVE,
    )
    mismatched, _other = classify_package(
        bundle,
        os_id="ubuntu",
        version_id="22.04",
        codename="noble",
        source_package="php8.1",
        installed_version="8.1.2-1ubuntu2.28",
        cve=CVE,
    )
    assert eol == "unknown"
    assert mismatched == "unknown"


def test_upstream_banner_without_a_package(bundle) -> None:  # type: ignore[no-untyped-def]
    old, _old = classify_upstream_banner(bundle, "PHP 8.3.35 (cli)", CVE)
    fixed, _fixed = classify_upstream_banner(bundle, "PHP 8.3.36 (cli)", CVE)
    preview, _preview = classify_upstream_banner(bundle, "PHP 8.6.0RC4 (cli)", CVE)
    development, dev_detail = classify_upstream_banner(bundle, "PHP 8.3.36-dev (cli)", CVE)
    candidate, rc_detail = classify_upstream_banner(bundle, "PHP 8.3.36-RC1 (cli)", CVE)
    ancient, _ancient = classify_upstream_banner(bundle, "PHP 8.1.2 (cli)", CVE)
    assert old == "affected_upstream"
    assert fixed == "fixed_upstream"
    assert preview == "unknown"
    assert development == "unknown"
    assert candidate == "unknown"
    assert "8.3.36-dev" in dev_detail
    assert "8.3.36-RC1" in rc_detail
    assert "pre-release" in rc_detail
    assert ancient == "unknown"


def test_stale_bundle_cannot_say_fixed(bundle) -> None:  # type: ignore[no-untyped-def]
    stale = load_path(
        DATA_DIR / "bundle.json", DATA_DIR / "public_key.pem", date(2026, 12, 1), min_version=None
    )
    assert stale.stale is True
    status, detail = classify_package(
        stale,
        os_id="ubuntu",
        version_id="26.04.1",
        codename="resolute",
        source_package="php8.5",
        installed_version="8.5.4-0ubuntu1.5",
        cve=CVE,
    )
    assert status == "stale_recheck_vendor"
    assert "not a current verdict" in detail


def test_tampered_bundle_is_rejected(tmp_path: Path) -> None:
    payload = (DATA_DIR / "bundle.json").read_bytes()
    damaged = tmp_path / "bundle.json"
    damaged.write_bytes(payload[:-2] + b"xx")
    (tmp_path / "bundle.sig").write_bytes((DATA_DIR / "bundle.sig").read_bytes())
    with pytest.raises(AdvisoryError, match="signature"):
        load_path(damaged, DATA_DIR / "public_key.pem", TODAY, min_version=None)


def test_older_signed_bundle_is_rejected(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from sec_scanner.advisory import canonical_bytes

    private = Ed25519PrivateKey.generate()
    public = tmp_path / "public_key.pem"
    public.write_bytes(
        private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    body = document()
    body["bundle_version"] = 1
    payload = canonical_bytes(body)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(payload)
    (tmp_path / "bundle.sig").write_text(private.sign(payload).hex() + "\n", encoding="utf-8")
    with pytest.raises(AdvisoryError, match="older"):
        load_path(bundle, public, TODAY, min_version=2)


def test_future_review_date_is_rejected(tmp_path: Path, bundle) -> None:  # type: ignore[no-untyped-def]
    del bundle
    with pytest.raises(AdvisoryError, match="future"):
        load_path(
            DATA_DIR / "bundle.json",
            DATA_DIR / "public_key.pem",
            date(2026, 10, 25),
            min_version=None,
        )
