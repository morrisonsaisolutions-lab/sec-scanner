"""Debian package version comparison.

The order matches ``dpkg --compare-versions``, including the case where a
missing revision compares equal to revision ``0`` and ``~`` sorts before
the end of a part. Callers must not use string ordering for package fixes.
"""

from __future__ import annotations

_MAX_LENGTH = 256


def compare(left: str, right: str) -> int | None:
    """Return -1, 0, or 1, or None when either version is not comparable."""
    parsed_left = _split(left)
    parsed_right = _split(right)
    if parsed_left is None or parsed_right is None:
        return None
    left_epoch, left_upstream, left_revision = parsed_left
    right_epoch, right_upstream, right_revision = parsed_right
    if left_epoch != right_epoch:
        return _sign(left_epoch - right_epoch)
    upstream = _compare_part(left_upstream, right_upstream)
    if upstream != 0:
        return upstream
    return _compare_part(left_revision, right_revision)


def _split(version: str) -> tuple[int, str, str] | None:
    if not version or len(version) > _MAX_LENGTH:
        return None
    if any(ord(char) < 33 or ord(char) > 126 for char in version):
        return None
    epoch_text, separator, remainder = version.partition(":")
    if separator == "":
        epoch = 0
        remainder = epoch_text
    else:
        if not epoch_text.isdigit():
            return None
        epoch = int(epoch_text)
    upstream, hyphen, revision = remainder.rpartition("-")
    if hyphen == "":
        upstream = revision
        revision = ""
    if upstream == "":
        return None
    return epoch, upstream, revision


def _compare_part(left: str, right: str) -> int:
    left_index = 0
    right_index = 0
    while left_index < len(left) or right_index < len(right):
        left_text, left_index = _take_nondigits(left, left_index)
        right_text, right_index = _take_nondigits(right, right_index)
        ordered = _compare_nondigits(left_text, right_text)
        if ordered != 0:
            return ordered
        left_digits, left_index = _take_digits(left, left_index)
        right_digits, right_index = _take_digits(right, right_index)
        ordered = _compare_digits(left_digits, right_digits)
        if ordered != 0:
            return ordered
    return 0


def _take_nondigits(text: str, index: int) -> tuple[str, int]:
    start = index
    while index < len(text) and not text[index].isdigit():
        index += 1
    return text[start:index], index


def _take_digits(text: str, index: int) -> tuple[str, int]:
    start = index
    while index < len(text) and text[index].isdigit():
        index += 1
    return text[start:index], index


def _compare_digits(left: str, right: str) -> int:
    left_value = int(left) if left else 0
    right_value = int(right) if right else 0
    return _sign(left_value - right_value)


def _compare_nondigits(left: str, right: str) -> int:
    length = max(len(left), len(right))
    for index in range(length):
        left_rank = _rank(left[index] if index < len(left) else "")
        right_rank = _rank(right[index] if index < len(right) else "")
        if left_rank != right_rank:
            return _sign(left_rank - right_rank)
    return 0


def _rank(char: str) -> int:
    if char == "":
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _sign(value: int) -> int:
    if value < 0:
        return -1
    if value > 0:
        return 1
    return 0
