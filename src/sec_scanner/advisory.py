"""Load a signed advisory bundle and refuse anything that does not verify."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from sec_scanner.errors import AdvisoryError

DATA_DIR = Path(__file__).resolve().parent / "data"
PATCH_CVES = ("CVE-2026-109618", "CVE-2026-109619")
CONFIG_CVE = "CVE-2026-115560"


@dataclass(frozen=True, slots=True)
class UpstreamFix:
    branch: str
    version: str
    major: int
    minor: int
    patch: int


@dataclass(frozen=True, slots=True)
class VendorRule:
    os_id: str
    version_id: str
    codename: str
    source_package: str
    fixed_version: str
    version_pattern: str
    cves: tuple[str, ...]
    source_urls: tuple[str, ...]
    source_published: str
    reviewed_on: str
    note: str


@dataclass(frozen=True, slots=True)
class CveRecord:
    cve: str
    title: str
    source_urls: tuple[str, ...]
    source_published: str
    reviewed_on: str
    upstream_fixed: tuple[UpstreamFix, ...]
    note: str


@dataclass(frozen=True, slots=True)
class Bundle:
    bundle_id: str
    bundle_version: int
    reviewed_on: date
    freshness_window_days: int
    age_days: int
    stale: bool
    cves: dict[str, CveRecord]
    rules: tuple[VendorRule, ...]

    def upstream_fixes(self, cve: str) -> dict[str, tuple[int, int, int]]:
        record = self.cves.get(cve)
        if record is None:
            return {}
        return {item.branch: (item.major, item.minor, item.patch) for item in record.upstream_fixed}

    def rule_for(
        self,
        *,
        os_id: str,
        version_id: str,
        codename: str,
        source_package: str,
        cve: str,
    ) -> VendorRule | None:
        found = [
            rule
            for rule in self.rules
            if _rule_matches(rule, os_id, version_id, codename, source_package, cve)
        ]
        if len(found) != 1:
            return None
        return found[0]


def load_for_scan(
    override: Path | None,
    today: date,
) -> tuple[Bundle, tuple[str, ...]]:
    """Load the embedded bundle, or a newer signed override that verifies."""
    verify_application()
    embedded = load_path(_bundle_path(), _key_path(), today, min_version=None)
    if override is None:
        return embedded, ()
    try:
        external = load_path(override, _key_path(), today, min_version=embedded.bundle_version)
    except AdvisoryError as exc:
        note = f"advisory override rejected: {exc}; using the bundled data"
        return embedded, (note,)
    return external, ()


def load_path(
    bundle_path: Path,
    key_path: Path,
    today: date,
    *,
    min_version: int | None,
) -> Bundle:
    payload = _read_limited(bundle_path, 1_048_576)
    signature = bytes.fromhex(_read_signature(bundle_path.with_suffix(".sig")))
    public_key = _load_public_key(_read_limited(key_path, 16_384))
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise AdvisoryError(f"signature verification failed for {bundle_path.name}") from exc
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdvisoryError("advisory bundle is not UTF-8 JSON") from exc
    bundle = _parse_bundle(raw, today)
    if min_version is not None and bundle.bundle_version < min_version:
        raise AdvisoryError(
            f"advisory bundle version {bundle.bundle_version} is older than {min_version}"
        )
    return bundle


def verify_application() -> None:
    """Refuse to load rules when the installed program does not match its signature."""
    manifest_path = DATA_DIR / "manifest.json"
    payload = _read_limited(manifest_path, 1_048_576)
    signature = bytes.fromhex(_read_signature(DATA_DIR / "manifest.sig"))
    public_key = _load_public_key(_read_limited(_key_path(), 16_384))
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise AdvisoryError("application manifest signature verification failed") from exc
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdvisoryError("application manifest is not UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise AdvisoryError("application manifest is not an object")
    listed = raw.get("files")
    if not isinstance(listed, dict):
        raise AdvisoryError("application manifest has no file list")
    files: dict[str, str] = {}
    for key, value in listed.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise AdvisoryError("application manifest file list is malformed")
        files[key] = value
    assert_tree_matches(DATA_DIR.parent, files)


def package_file_map(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        if relative in {"data/manifest.json", "data/manifest.sig"}:
            continue
        if path.name != "py.typed" and path.suffix not in {".py", ".pem", ".json", ".sig"}:
            continue
        found[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def assert_tree_matches(root: Path, listed: dict[str, str]) -> None:
    actual = package_file_map(root)
    if set(actual) != set(listed):
        missing = sorted(set(actual) - set(listed))
        extra = sorted(set(listed) - set(actual))
        detail = "application manifest file list does not match the package"
        if missing:
            detail += f"; missing {missing[0]}"
        if extra:
            detail += f"; unexpected {extra[0]}"
        raise AdvisoryError(detail)
    for name, digest in listed.items():
        if actual[name] != digest:
            raise AdvisoryError(f"application file hash mismatch: {name}")


def canonical_bytes(document: dict[str, object]) -> bytes:
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    return text.encode("utf-8")


def _bundle_path() -> Path:
    return DATA_DIR / "bundle.json"


def _key_path() -> Path:
    return DATA_DIR / "public_key.pem"


def _read_limited(path: Path, limit: int) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AdvisoryError(f"cannot read {path.name}") from exc
    if len(data) > limit or not data:
        raise AdvisoryError(f"{path.name} is empty or larger than {limit} bytes")
    return data


def _read_signature(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AdvisoryError("advisory signature is missing") from exc
    if len(text) != 128 or any(char not in "0123456789abcdef" for char in text):
        raise AdvisoryError("advisory signature is not a 64-byte hex digest")
    return text


def _load_public_key(pem: bytes) -> Ed25519PublicKey:
    try:
        key = load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise AdvisoryError("advisory public key could not be read") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AdvisoryError("advisory public key is not Ed25519")
    return key


def _parse_bundle(raw: object, today: date) -> Bundle:
    if not isinstance(raw, dict):
        raise AdvisoryError("advisory bundle is not an object")
    bundle_id = _string(raw, "bundle_id")
    version = raw.get("bundle_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise AdvisoryError("advisory bundle_version is not a positive integer")
    reviewed = _date(_string(raw, "reviewed_on"))
    window = raw.get("freshness_window_days")
    if not isinstance(window, int) or isinstance(window, bool) or window < 1 or window > 365:
        raise AdvisoryError("freshness_window_days is not usable")
    if reviewed > today:
        raise AdvisoryError("advisory reviewed_on is in the future")
    age = (today - reviewed).days
    cves = _parse_cves(raw.get("cves"))
    rules = _parse_rules(raw.get("vendor_rules"))
    for cve in (*PATCH_CVES, CONFIG_CVE):
        if cve not in cves:
            raise AdvisoryError(f"advisory bundle is missing {cve}")
    return Bundle(
        bundle_id=bundle_id,
        bundle_version=version,
        reviewed_on=reviewed,
        freshness_window_days=window,
        age_days=age,
        stale=age > window,
        cves=cves,
        rules=rules,
    )


def _parse_cves(raw: object) -> dict[str, CveRecord]:
    if not isinstance(raw, dict):
        raise AdvisoryError("advisory cves field is missing")
    parsed: dict[str, CveRecord] = {}
    for cve, value in raw.items():
        if not isinstance(cve, str) or not isinstance(value, dict):
            raise AdvisoryError("advisory cve record is malformed")
        fixes: list[UpstreamFix] = []
        upstream = value.get("upstream_fixed")
        if not isinstance(upstream, list):
            raise AdvisoryError(f"{cve} is missing upstream_fixed")
        for item in upstream:
            if not isinstance(item, dict):
                raise AdvisoryError(f"{cve} upstream fix is malformed")
            version_text = _string(item, "version")
            parts = _php_version(version_text)
            if parts is None:
                raise AdvisoryError(f"{cve} has an unreadable upstream version")
            major, minor, patch = parts
            branch = _string(item, "branch")
            if branch != f"{major}.{minor}":
                raise AdvisoryError(f"{cve} branch does not match {version_text}")
            fixes.append(UpstreamFix(branch, version_text, major, minor, patch))
        parsed[cve] = CveRecord(
            cve=cve,
            title=_string(value, "title"),
            source_urls=_string_tuple(value, "source_urls"),
            source_published=_string(value, "source_published"),
            reviewed_on=_string(value, "reviewed_on"),
            upstream_fixed=tuple(fixes),
            note=_string(value, "note"),
        )
    return parsed


def _parse_rules(raw: object) -> tuple[VendorRule, ...]:
    if not isinstance(raw, list) or not raw:
        raise AdvisoryError("advisory vendor_rules are missing")
    rules: list[VendorRule] = []
    for item in raw:
        if not isinstance(item, dict):
            raise AdvisoryError("a vendor rule is malformed")
        pattern = _string(item, "version_pattern")
        if pattern not in {"ubuntu", "debian-release", "debian-unstable"}:
            raise AdvisoryError(f"unsupported version pattern {pattern}")
        version_id = _string(item, "version_id", allow_empty=True)
        codename = _string(item, "codename", allow_empty=True)
        if not version_id and not codename:
            raise AdvisoryError("a vendor rule has no release identity")
        rules.append(
            VendorRule(
                os_id=_string(item, "os_id"),
                version_id=version_id,
                codename=codename,
                source_package=_string(item, "source_package"),
                fixed_version=_string(item, "fixed_version"),
                version_pattern=pattern,
                cves=_string_tuple(item, "cves"),
                source_urls=_string_tuple(item, "source_urls"),
                source_published=_string(item, "source_published"),
                reviewed_on=_string(item, "reviewed_on"),
                note=_string(item, "note"),
            )
        )
    return tuple(rules)


def _rule_matches(
    rule: VendorRule,
    os_id: str,
    version_id: str,
    codename: str,
    source_package: str,
    cve: str,
) -> bool:
    if rule.os_id != os_id or rule.source_package != source_package or cve not in rule.cves:
        return False
    if rule.version_id and rule.version_id != version_id:
        return False
    if rule.codename and (not codename or rule.codename != codename):
        return False
    return bool(rule.version_id or rule.codename)


def _php_version(value: str) -> tuple[int, int, int] | None:
    pieces = value.split(".")
    if len(pieces) != 3 or any(not piece.isdigit() for piece in pieces):
        return None
    return int(pieces[0]), int(pieces[1]), int(pieces[2])


def _date(value: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise AdvisoryError("advisory date is not YYYY-MM-DD") from exc


def _string(raw: dict[str, object], key: str, *, allow_empty: bool = False) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or (not value and not allow_empty):
        raise AdvisoryError(f"advisory field {key} is missing")
    return value


def _string_tuple(raw: dict[str, object], key: str) -> tuple[str, ...]:
    value = raw.get(key)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise AdvisoryError(f"advisory field {key} is missing")
    return tuple(value)
