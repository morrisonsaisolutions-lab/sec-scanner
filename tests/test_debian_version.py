from __future__ import annotations

import shutil
import subprocess

import pytest

from sec_scanner.debian_version import compare

PAIRS = [
    ("1.0", "1.0-0", 0),
    ("1.0", "1.0-1", -1),
    ("8.1.2-1ubuntu2.9", "8.1.2-1ubuntu2.28", -1),
    ("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1),
    ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", 0),
    ("8.2.32-1~deb12u1", "8.2.35-1~deb12u1", -1),
    ("8.4.27-1~deb13u1", "8.4.27-1", -1),
    ("8.5.4-0ubuntu1.4", "8.5.4-0ubuntu1.5", -1),
    ("1:8.1.2-1", "8.1.2-1", 1),
    ("1.0~rc1", "1.0", -1),
    ("1.0a", "1.0", 1),
    ("5.5.9+dfsg-1ubuntu4.29+esm17", "5.5.9+dfsg-1ubuntu4.29+esm18", -1),
    ("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29+esm5", 0),
]


@pytest.mark.parametrize(("left", "right", "expected"), PAIRS)
def test_compare_matches_the_table(left: str, right: str, expected: int) -> None:
    assert compare(left, right) == expected


def test_compare_rejects_empty_and_huge_versions() -> None:
    assert compare("", "1.0") is None
    assert compare("1" * 300, "1.0") is None


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg is not installed")
def test_compare_matches_dpkg() -> None:
    samples = [left for left, _right, _expected in PAIRS]
    samples.extend(right for _left, right, _expected in PAIRS)
    unique = list(dict.fromkeys(samples))
    for left in unique:
        for right in unique:
            ours = compare(left, right)
            assert ours is not None
            assert ours == _dpkg(left, right)


def _dpkg(left: str, right: str) -> int:
    if _dpkg_true(left, "eq", right):
        return 0
    if _dpkg_true(left, "lt", right):
        return -1
    return 1


def _dpkg_true(left: str, operator: str, right: str) -> bool:
    completed = subprocess.run(
        ["dpkg", "--compare-versions", left, operator, right],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0
