from __future__ import annotations

from pathlib import Path

import pytest

from sec_scanner.advisory import AdvisoryError, assert_tree_matches, package_file_map


def test_manifest_check_rejects_a_changed_file(tmp_path: Path) -> None:
    package = tmp_path / "sec_scanner"
    package.mkdir()
    source = package / "cli.py"
    source.write_text("print(1)\n", encoding="utf-8")
    listed = package_file_map(package)
    assert_tree_matches(package, listed)
    source.write_text("print(2)\n", encoding="utf-8")
    with pytest.raises(AdvisoryError, match="hash mismatch"):
        assert_tree_matches(package, listed)


def test_manifest_check_rejects_an_extra_file(tmp_path: Path) -> None:
    package = tmp_path / "sec_scanner"
    package.mkdir()
    (package / "cli.py").write_text("print(1)\n", encoding="utf-8")
    listed = package_file_map(package)
    (package / "extra.py").write_text("print(3)\n", encoding="utf-8")
    with pytest.raises(AdvisoryError, match="missing"):
        assert_tree_matches(package, listed)
