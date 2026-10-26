"""Read PHP startup settings and optional application text. Nothing is executed."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from sec_scanner.discover import Budget
from sec_scanner.models import SkipObs

_MAX_INI = 1_048_576
_MAX_APP_FILE = 1_048_576
_MAX_APP_FILES = 2_000
_MAX_APP_BYTES = 32_000_000
_MAX_DEPTH = 8
_KEYS = frozenset(
    {
        "session.serialize_handler",
        "session.upload_progress.enabled",
        "memory_limit",
        "post_max_size",
        "upload_max_filesize",
        "fatal_error_backtraces",
    }
)
_INI_LINE = re.compile(r"^([A-Za-z0-9_.]+)\s*=\s*(.*)$")
_POOL_LINE = re.compile(
    r"^(php_admin_value|php_admin_flag|php_value|php_flag)\[([A-Za-z0-9_.]+)\]\s*=\s*(.*)$"
)
_INI_SET = re.compile(
    r"""ini_set\s*\(\s*(['"])session\.serialize_handler\1\s*,\s*(['"])(php|php_binary|php_serialize)\2""",
    re.IGNORECASE,
)
_SESSION_START = re.compile(r"\bsession_start\s*\(")
_APP_SUFFIXES = {".php", ".inc", ".phtml"}
_RISKY_HANDLERS = frozenset({"php_binary", "php_serialize"})
_APACHE_PATTERNS = (
    "etc/apache2/apache2.conf",
    "etc/httpd/conf/httpd.conf",
    "etc/apache2/mods-enabled/*.conf",
    "etc/apache2/conf-enabled/*.conf",
    "etc/apache2/sites-enabled/*.conf",
    "etc/httpd/conf.d/*.conf",
    "etc/httpd/conf.modules.d/*.conf",
)
_APACHE_DIRECTIVE = re.compile(
    r"^(php_admin_flag|php_admin_value|php_flag|php_value)\s+"
    r"\[?([A-Za-z0-9_.]+)\]?\s*=?\s*(.*?)\s*$"
)
_MAX_APACHE_FILES = 200
_MAX_INCLUDES = 64
_CHROOT = re.compile(r"^chroot\s*=\s*(\S+)\s*$")
_INCLUDE = re.compile(
    r"""^include\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))\s*$""",
    re.IGNORECASE,
)
_APACHE_INCLUDE = re.compile(
    r"""^(?:includeoptional|include)\s+(?:"([^"]*)"|'([^']*)'|(\S+))\s*$""",
    re.IGNORECASE,
)
_SERVER_ROOT = re.compile(
    r"""^serverroot\s+(?:"([^"]*)"|'([^']*)'|(\S+))\s*$""",
    re.IGNORECASE,
)
_STATIC_NAMES = {".user.ini", ".htaccess"}


@dataclass(frozen=True, slots=True)
class PoolView:
    name: str
    path: str
    locked: dict[str, str]
    overridable: dict[str, str]


@dataclass(frozen=True, slots=True)
class SapiConfig:
    branch: str
    sapi: str
    readable: bool
    startup: dict[str, str]
    pools: tuple[PoolView, ...]
    files: tuple[str, ...]
    skipped: tuple[SkipObs, ...]
    incomplete: bool


@dataclass(frozen=True, slots=True)
class AppHit:
    path: str
    line: int
    value: str
    session_start_line: int | None


@dataclass(frozen=True, slots=True)
class ApacheDirective:
    path: str
    kind: str
    key: str
    value: str


@dataclass(frozen=True, slots=True)
class ApacheNotes:
    files: tuple[str, ...]
    directives: tuple[ApacheDirective, ...]
    skipped: tuple[SkipObs, ...]


def branch_from_source(source: str) -> str | None:
    match = re.fullmatch(r"php(\d+(?:\.\d+)?)", source)
    if match is None:
        return None
    return match.group(1)


def read_sapi(root: Path, branch: str, sapi: str) -> SapiConfig:
    skipped: list[SkipObs] = []
    base = _sapi_dir(root, branch, sapi)
    if base is None:
        return SapiConfig(
            branch,
            sapi,
            False,
            {},
            (),
            (),
            (SkipObs(f"etc/php/{branch}/{sapi}", "configuration directory was not present"),),
            False,
        )
    incomplete = False
    files: list[Path] = []
    main = base / "php.ini"
    if main.is_symlink() or main.is_file():
        files.append(main)
    conf_dir = _contained_dir(root, base / "conf.d", skipped)
    if conf_dir is None and (base / "conf.d").is_symlink():
        incomplete = True
    elif conf_dir is not None:
        try:
            entries = list(conf_dir.iterdir())
        except OSError as exc:
            skipped.append(
                SkipObs(
                    str(base / "conf.d"), exc.strerror or "configuration directory was not readable"
                )
            )
            incomplete = True
        else:
            files.extend(
                sorted(
                    path
                    for path in entries
                    if path.suffix == ".ini" and (path.is_symlink() or path.is_file())
                )
            )
    startup: dict[str, str] = {}
    read_files: list[str] = []
    for path in files:
        resolved = _contained_file(root, path, skipped)
        if resolved is None:
            incomplete = True
            continue
        parsed = _read_ini(resolved, skipped)
        if parsed is None:
            incomplete = True
            continue
        startup.update(parsed)
        read_files.append(str(resolved))
    pools: list[PoolView] = []
    seen_pools: set[str] = set()
    pool_paths, pools_incomplete = _pool_paths(root, base, skipped)
    incomplete = incomplete or pools_incomplete
    for path in pool_paths:
        resolved = _contained_file(root, path, skipped)
        if resolved is None:
            incomplete = True
            continue
        key = str(resolved)
        if key in seen_pools:
            continue
        seen_pools.add(key)
        locked, overridable = _read_pool(resolved, skipped)
        if locked is None or overridable is None:
            incomplete = True
            continue
        pools.append(PoolView(resolved.stem, key, locked, overridable))
        read_files.append(key)
    return SapiConfig(
        branch,
        sapi,
        bool(read_files),
        startup,
        tuple(pools),
        tuple(read_files),
        tuple(skipped),
        incomplete,
    )


def read_apache(root: Path, budget: Budget | None = None) -> ApacheNotes:
    """Read PHP admin directives. Context inside Apache is not evaluated."""
    skipped: list[SkipObs] = []
    files: list[str] = []
    directives: list[ApacheDirective] = []
    seen: set[str] = set()
    pending: list[Path] = []
    server_root: Path | None = None
    for pattern in _APACHE_PATTERNS:
        if budget is not None and budget.expired():
            skipped.append(SkipObs("apache", "stopped at the time limit"))
            break
        pending.extend(_apache_paths(root, pattern, skipped))
    while pending:
        if budget is not None and budget.expired():
            skipped.append(SkipObs("apache", "stopped at the time limit"))
            break
        path = pending.pop()
        if len(files) >= _MAX_APACHE_FILES:
            skipped.append(SkipObs(str(path), "apache config list was truncated"))
            break
        resolved = _resolve_inside(root, path)
        if resolved is None or not resolved.is_file():
            skipped.append(SkipObs(str(path), "apache config is outside the scan root"))
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        text = _read_limited(resolved, _MAX_INI, skipped)
        if text is None:
            continue
        files.append(key)
        directives.extend(_apache_directives(key, text))
        extra, server_root = _apache_includes(root, resolved.parent, server_root, text, skipped)
        pending.extend(extra)
    return ApacheNotes(tuple(files), tuple(directives), tuple(skipped))


def adjacent_ini(root: Path, binary: Path) -> tuple[str, dict[str, str]] | None:
    """Read an ini next to an unpacked binary. It may not be the one PHP loads."""
    prefix = binary.parent.parent
    candidates = (
        prefix / "etc" / "php.ini",
        prefix / "etc" / "php" / "php.ini",
        prefix / "lib" / "php.ini",
    )
    for candidate in candidates:
        resolved = _resolve_inside(root, candidate)
        if resolved is None or not resolved.is_file():
            continue
        parsed = _read_ini(resolved, [])
        if parsed is None:
            continue
        return str(resolved), parsed
    return None


def apache_has_risky_handler(notes: ApacheNotes) -> bool:
    """True when Apache text names a serializer from the PHP notice.

    The directory and virtual-host context is still not evaluated.
    """
    return any(
        item.key == "session.serialize_handler" and item.value.strip().lower() in _RISKY_HANDLERS
        for item in notes.directives
    )


def apache_summary(notes: ApacheNotes) -> str:
    if not notes.directives:
        return ""
    shown = [
        f"{item.kind} {item.key}={item.value} in {item.path}" for item in notes.directives[:20]
    ]
    return (
        "; ".join(shown) + ". Apache directory and virtual-host context was not evaluated, "
        "so these lines are evidence and are not a locked mitigation."
    )


def scan_app_dir(
    root: Path,
    app_dir: Path,
    budget: Budget | None = None,
) -> tuple[tuple[AppHit, ...], tuple[SkipObs, ...]]:
    resolved_root = root.resolve()
    resolved_app = _resolve_inside(resolved_root, app_dir)
    if resolved_app is None or not resolved_app.is_dir():
        return (), (SkipObs(str(app_dir), "application directory is outside the scan root"),)
    hits: list[AppHit] = []
    skipped: list[SkipObs] = []
    total = 0
    count = 0
    pending = [resolved_app]
    seen_dirs: set[str] = set()
    while pending:
        start = pending.pop()
        try:
            start_key = str(start.resolve())
        except OSError:
            skipped.append(SkipObs(str(start), "directory was not readable"))
            continue
        if start_key in seen_dirs:
            continue
        seen_dirs.add(start_key)

        def note_walk_error(error: OSError, directory: Path = start) -> None:
            skipped.append(
                SkipObs(
                    str(error.filename or directory),
                    error.strerror or "directory was not readable",
                )
            )

        for current, dirnames, filenames in os.walk(
            start, followlinks=False, onerror=note_walk_error
        ):
            current_path = Path(current)
            try:
                depth = len(current_path.relative_to(resolved_app).parts)
            except ValueError:
                dirnames.clear()
                skipped.append(
                    SkipObs(str(current_path), "directory is outside the application directory")
                )
                continue
            if depth > _MAX_DEPTH:
                dirnames.clear()
                skipped.append(SkipObs(str(current_path), "directory depth limit reached"))
                continue
            kept: list[str] = []
            for name in dirnames:
                child = current_path / name
                if child.is_symlink():
                    target = _resolve_inside(resolved_app, child)
                    if target is None or not target.is_dir():
                        skipped.append(
                            SkipObs(
                                str(child),
                                "directory symlink is outside the application directory",
                            )
                        )
                    else:
                        pending.append(target)
                    continue
                if _resolve_inside(resolved_app, child) is None:
                    skipped.append(
                        SkipObs(str(child), "directory is outside the application directory")
                    )
                    continue
                kept.append(name)
            dirnames[:] = kept
            for name in filenames:
                if budget is not None and budget.expired():
                    skipped.append(SkipObs(str(current_path), "stopped at the time limit"))
                    return tuple(hits), tuple(skipped)
                if count >= _MAX_APP_FILES or total >= _MAX_APP_BYTES:
                    skipped.append(
                        SkipObs(str(current_path), "application scan stopped at its file limit")
                    )
                    return tuple(hits), tuple(skipped)
                path = current_path / name
                if path.suffix.lower() not in _APP_SUFFIXES and name not in _STATIC_NAMES:
                    continue
                resolved = _resolve_inside(resolved_app, path)
                if resolved is None or not resolved.is_file():
                    if path.is_symlink():
                        skipped.append(
                            SkipObs(str(path), "file symlink is outside the application directory")
                        )
                    continue
                try:
                    size = resolved.stat().st_size
                except OSError as exc:
                    skipped.append(SkipObs(str(path), exc.strerror or "not readable"))
                    continue
                if size > _MAX_APP_FILE:
                    skipped.append(SkipObs(str(path), "file is larger than the read limit"))
                    continue
                try:
                    with resolved.open("rb") as handle:
                        data = handle.read(_MAX_APP_FILE + 1)
                except OSError as exc:
                    skipped.append(SkipObs(str(path), exc.strerror or "not readable"))
                    continue
                if len(data) > _MAX_APP_FILE:
                    skipped.append(SkipObs(str(path), "file is larger than the read limit"))
                    continue
                text = data.decode("utf-8", "replace")
                if text.startswith("\ufeff"):
                    text = text[1:]
                count += 1
                total += size
                if name == ".user.ini":
                    hit = _config_text_hit(str(resolved), text, apache=False)
                elif name == ".htaccess":
                    hit = _config_text_hit(str(resolved), text, apache=True)
                else:
                    hit = _app_hit(str(resolved), text)
                if hit is not None:
                    hits.append(hit)
    return tuple(hits), tuple(skipped)


def upload_progress_off(config: SapiConfig) -> bool:
    """True only when upload progress stays off for every pool.

    A pool php_value that turns it on wins unless php_admin_value forces it off.
    """
    if not config.readable or config.incomplete:
        return False
    base = _boolish(config.startup.get("session.upload_progress.enabled"))
    if not config.pools:
        return base is False
    for pool in config.pools:
        locked = _boolish(pool.locked.get("session.upload_progress.enabled"))
        overridable = _boolish(pool.overridable.get("session.upload_progress.enabled"))
        if overridable is True and locked is not False:
            return False
        effective = locked if locked is not None else base
        if effective is not False:
            return False
    return True


def memory_limit_locked_off(config: SapiConfig) -> bool:
    """True when every pool's admin value removes the PHP memory ceiling."""
    if config.incomplete or not config.pools:
        return False
    return all(pool.locked.get("memory_limit", "").strip() == "-1" for pool in config.pools)


def handler_is_risky(config: SapiConfig) -> bool:
    values = [config.startup.get("session.serialize_handler", "").strip().lower()]
    for pool in config.pools:
        for source in (pool.locked, pool.overridable):
            raw = source.get("session.serialize_handler")
            if raw is not None:
                values.append(raw.strip().lower())
    return any(value in _RISKY_HANDLERS for value in values)


def config_status(config: SapiConfig, hits: tuple[AppHit, ...]) -> str:
    if config.incomplete and not handler_is_risky(config) and not hits:
        return "not_assessed"
    if not config.readable and not hits:
        return "not_assessed"
    if handler_is_risky(config) or hits:
        return "potential_configuration_to_review"
    return "no_matching_static_evidence"


def _apache_paths(root: Path, pattern: str, skipped: list[SkipObs]) -> tuple[Path, ...]:
    if not any(char in pattern for char in "*?["):
        kept = _queue_apache_file(root, root / pattern, skipped)
        return (kept,) if kept is not None else ()
    try:
        matches = list(root.glob(pattern))
    except (OSError, ValueError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) else "apache config was not readable"
        skipped.append(SkipObs(pattern, reason or "apache config was not readable"))
        return ()
    found: list[Path] = []
    for path in matches:
        kept = _queue_apache_file(root, path, skipped)
        if kept is not None:
            found.append(kept)
    return tuple(found)


def _queue_apache_file(root: Path, path: Path, skipped: list[SkipObs]) -> Path | None:
    """Return a regular file inside the root. Do not stat a link that leaves it."""
    if path.is_symlink():
        resolved = _resolve_inside(root, path)
        if resolved is not None and resolved.is_file():
            return resolved
        skipped.append(SkipObs(str(path), "apache config is outside the scan root"))
        return None
    if not path.is_file():
        return None
    resolved = _resolve_inside(root, path)
    if resolved is None or not resolved.is_file():
        skipped.append(SkipObs(str(path), "apache config is outside the scan root"))
        return None
    return resolved


def _apache_directives(path: str, text: str) -> tuple[ApacheDirective, ...]:
    found: list[ApacheDirective] = []
    for raw_line in text.splitlines():
        line = _strip_hash(_strip_comment(raw_line)).strip()
        match = _APACHE_DIRECTIVE.match(line)
        if match is None:
            continue
        key = match.group(2)
        if key not in _KEYS:
            continue
        found.append(ApacheDirective(path, match.group(1), key, _clean_value(match.group(3))))
        if len(found) >= 64:
            break
    return tuple(found)


def _strip_hash(line: str) -> str:
    quote = ""
    for index, char in enumerate(line):
        if char in {'"', "'"}:
            if quote == char:
                quote = ""
            elif quote == "":
                quote = char
        elif char == "#" and quote == "":
            return line[:index]
    return line


def _sapi_dir(root: Path, branch: str, sapi: str) -> Path | None:
    candidates = [root / "etc/php" / branch / sapi]
    if branch == "5":
        candidates.append(root / "etc/php5" / sapi)
    for candidate in candidates:
        if not candidate.is_symlink() and not candidate.is_dir():
            continue
        resolved = _resolve_inside(root, candidate)
        if resolved is not None and resolved.is_dir():
            return resolved
    return None


def _contained_dir(root: Path, path: Path, skipped: list[SkipObs]) -> Path | None:
    if not path.is_symlink() and not path.is_dir():
        return None
    resolved = _resolve_inside(root, path)
    if resolved is None or not resolved.is_dir():
        if path.is_symlink():
            skipped.append(SkipObs(str(path), "symlink target is outside the scan root"))
        return None
    return resolved


def _contained_file(root: Path, path: Path, skipped: list[SkipObs]) -> Path | None:
    if not path.is_symlink() and not path.is_file():
        return None
    resolved = _resolve_inside(root, path)
    if resolved is None or not resolved.is_file():
        skipped.append(SkipObs(str(path), "symlink target is outside the scan root"))
        return None
    return resolved


def _pool_paths(
    root: Path,
    base: Path,
    skipped: list[SkipObs],
) -> tuple[list[Path], bool]:
    incomplete = False
    found: list[Path] = []
    pool_dir = base / "pool.d"
    opened = _contained_dir(root, pool_dir, skipped)
    if pool_dir.is_symlink() and opened is None:
        incomplete = True
    elif opened is not None:
        try:
            entries = list(opened.iterdir())
        except OSError as exc:
            skipped.append(
                SkipObs(str(pool_dir), exc.strerror or "pool directory was not readable")
            )
            incomplete = True
        else:
            found.extend(
                path
                for path in sorted(entries)
                if path.suffix == ".conf" and (path.is_symlink() or path.is_file())
            )
    conf = base / "php-fpm.conf"
    resolved = _contained_file(root, conf, skipped)
    if conf.is_symlink() and resolved is None:
        return found, True
    if resolved is None:
        return found, incomplete
    text = _read_limited(resolved, _MAX_INI, skipped)
    if text is None:
        return found, True
    extra, missed = _include_files(root, text, skipped, resolved)
    return found + extra, incomplete or missed


def _include_files(
    root: Path,
    text: str,
    skipped: list[SkipObs],
    origin: Path,
) -> tuple[list[Path], bool]:
    found: list[Path] = []
    seen: set[str] = set()
    # One mutable budget so a nested include cannot restart the cap.
    remaining = [_MAX_INCLUDES]
    missed = _collect_includes(root, text, skipped, origin, found, seen, remaining)
    return found, missed


def _collect_includes(
    root: Path,
    text: str,
    skipped: list[SkipObs],
    origin: Path,
    found: list[Path],
    seen: set[str],
    remaining: list[int],
) -> bool:
    missed = False
    for raw in text.splitlines():
        match = _INCLUDE.match(_strip_comment(raw).strip())
        if match is None:
            continue
        pattern = _quoted_group(match)
        paths, problem = _expand_pattern(root, origin.parent, pattern, ".conf", limit=remaining[0])
        if problem is not None:
            skipped.append(SkipObs(str(origin), _INCLUDE_PROBLEMS[problem]))
            missed = True
        for path in paths:
            key = str(path)
            if key in seen:
                continue
            if remaining[0] <= 0:
                skipped.append(SkipObs(pattern, _INCLUDE_PROBLEMS["truncated"]))
                return True
            seen.add(key)
            remaining[0] -= 1
            nested = _read_limited(path, _MAX_INI, skipped)
            if nested is None:
                missed = True
                continue
            found.append(path)
            if _collect_includes(root, nested, skipped, path, found, seen, remaining):
                missed = True
    return missed


_INCLUDE_PROBLEMS = {
    "outside": "php-fpm include is outside the scan root",
    "truncated": "php-fpm include list was truncated",
    "unreadable": "php-fpm include was not readable",
}


def _quoted_group(match: re.Match[str]) -> str:
    for group in match.groups():
        if group is not None:
            return group
    return ""


def _apache_includes(
    root: Path,
    origin_dir: Path,
    server_root: Path | None,
    text: str,
    skipped: list[SkipObs],
) -> tuple[list[Path], Path | None]:
    """Follow Include lines that stay inside the scan root.

    Absolute paths are paths in the scanned image. A missing IncludeOptional
    is not a skip. A directory include is not treated as fully read.
    """
    extra: list[Path] = []
    current = server_root
    for raw in text.splitlines():
        line = _strip_hash(_strip_comment(raw)).strip()
        if not line:
            continue
        server_match = _SERVER_ROOT.match(line)
        if server_match is not None:
            updated = _apache_server_root(root, origin_dir, _quoted_group(server_match), skipped)
            if updated is not None:
                current = updated
            continue
        include_match = _APACHE_INCLUDE.match(line)
        if include_match is None:
            continue
        optional = line.lower().startswith("includeoptional")
        pattern = _quoted_group(include_match)
        base = current if current is not None else origin_dir
        paths, problem = _expand_pattern(root, base, pattern, None, limit=_MAX_APACHE_FILES)
        if problem is not None:
            skipped.append(SkipObs(pattern, _APACHE_PROBLEMS[problem]))
        if len(paths) == 1 and paths[0].is_dir():
            skipped.append(SkipObs(pattern, "apache include names a directory"))
            paths = []
        files = [path for path in paths if path.is_file()]
        if problem is None and not files and not optional:
            skipped.append(SkipObs(pattern, "apache include matched no file"))
        extra.extend(files)
    return extra, current


def _apache_server_root(
    root: Path,
    origin_dir: Path,
    pattern: str,
    skipped: list[SkipObs],
) -> Path | None:
    paths, problem = _expand_pattern(root, origin_dir, pattern, None, limit=1)
    if problem is not None or len(paths) != 1 or not paths[0].is_dir():
        skipped.append(SkipObs(pattern, "apache ServerRoot is outside the scan root"))
        return None
    return paths[0]


_APACHE_PROBLEMS = {
    "outside": "apache include is outside the scan root",
    "truncated": "apache include list was truncated",
    "unreadable": "apache include was not readable",
}


def _expand_pattern(
    root: Path,
    origin_dir: Path,
    pattern: str,
    suffix: str | None,
    *,
    limit: int,
) -> tuple[list[Path], str | None]:
    """Expand one include pattern.

    An absolute path is joined onto the scan root. It is not a host path.
    The result stays empty of anything whose resolved path leaves that root.
    """
    parsed = _include_parts(pattern)
    if parsed is None:
        return [], "outside"
    absolute, parts = parsed
    base = root if absolute else origin_dir
    wild = _wild_at(parts)
    if wild is None:
        target = _lexical_target(root, _join(base, parts))
        if target is None:
            return [], "outside"
        if limit <= 0:
            return [], "truncated"
        return [target], None
    if any(part == ".." for part in parts[wild:]):
        return [], "outside"
    head = _lexical_target(root, _join(base, parts[:wild]))
    if head is None:
        return [], "outside"
    if not head.is_dir():
        return [], None
    stop_after = limit + 1 if limit > 0 else 1
    matches, problem = _glob_inside(root, head, parts[wild:], suffix, stop_after)
    if limit <= 0:
        if problem == "outside":
            return [], "outside"
        if matches:
            return [], "truncated"
        return [], problem
    if len(matches) > limit:
        return matches[:limit], "outside" if problem == "outside" else "truncated"
    return matches, problem


def _include_parts(pattern: str) -> tuple[bool, list[str]] | None:
    if not pattern or len(pattern) > 4096 or "\x00" in pattern or "\\" in pattern:
        return None
    parts = [part for part in pattern.split("/") if part not in {"", "."}]
    if len(parts) > 64:
        return None
    return pattern.startswith("/"), parts


def _wild_at(parts: list[str]) -> int | None:
    for index, part in enumerate(parts):
        if any(char in part for char in "*?["):
            return index
    return None


def _join(base: Path, parts: list[str]) -> Path:
    if not parts:
        return base
    return base.joinpath(*parts)


def _lexical_target(root: Path, candidate: Path) -> Path | None:
    """Resolve a path that is lexically inside the root. Do not stat one that is not."""
    try:
        anchors = [root.resolve(), Path(os.path.normpath(root))]
    except OSError:
        return None
    lexical = Path(os.path.normpath(candidate))
    if not any(_is_under(lexical, anchor) for anchor in anchors):
        return None
    return _resolve_inside(root, lexical)


def _is_under(path: Path, anchor: Path) -> bool:
    try:
        return path.is_relative_to(anchor)
    except ValueError:
        return False


def _glob_inside(
    root: Path,
    head: Path,
    tail: list[str],
    suffix: str | None,
    stop_after: int,
) -> tuple[list[Path], str | None]:
    try:
        relative = head.relative_to(root.resolve())
    except (OSError, ValueError):
        return [], "outside"
    pattern = "/".join((*relative.parts, *tail))
    try:
        matches = root.glob(pattern)
    except (OSError, ValueError):
        return [], "unreadable"
    kept: list[Path] = []
    problem: str | None = None
    for match in matches:
        if suffix is not None and not match.name.endswith(suffix):
            continue
        # lstat first so a link to the outside is not followed by is_file.
        if not match.is_symlink() and not match.is_file():
            continue
        resolved = _resolve_inside(root, match)
        if resolved is None or not resolved.is_file():
            problem = "outside"
            continue
        kept.append(resolved)
        if len(kept) >= stop_after:
            break
    return kept, problem


def _config_text_hit(path: str, text: str, *, apache: bool) -> AppHit | None:
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw).strip()
        if apache:
            line = _strip_hash(line).strip()
            match = _APACHE_DIRECTIVE.match(line)
            if match is None or match.group(2) != "session.serialize_handler":
                continue
            value = _clean_value(match.group(3)).lower()
        else:
            match = _INI_LINE.match(line)
            if match is None or match.group(1) != "session.serialize_handler":
                continue
            value = _clean_value(match.group(2)).lower()
        if value in _RISKY_HANDLERS:
            return AppHit(path, number, value, None)
    return None


def _read_ini(path: Path, skipped: list[SkipObs]) -> dict[str, str] | None:
    text = _read_limited(path, _MAX_INI, skipped)
    if text is None:
        return None
    found: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        if not line or line.startswith("["):
            continue
        match = _INI_LINE.match(line)
        if match is None:
            continue
        key = match.group(1)
        if key in _KEYS:
            found[key] = _clean_value(match.group(2))
    return found


def _read_pool(
    path: Path,
    skipped: list[SkipObs],
) -> tuple[dict[str, str], dict[str, str]] | tuple[None, None]:
    text = _read_limited(path, _MAX_INI, skipped)
    if text is None:
        return None, None
    locked: dict[str, str] = {}
    overridable: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        chroot = _CHROOT.match(line)
        if chroot is not None:
            value = chroot.group(1).strip("\"'")
            if value not in {"", "/"}:
                skipped.append(
                    SkipObs(
                        str(path),
                        f"pool sets chroot={value}; files inside that chroot were not read",
                    )
                )
            continue
        match = _POOL_LINE.match(line)
        if match is None:
            continue
        kind, key, value = match.group(1), match.group(2), _clean_value(match.group(3))
        if key not in _KEYS:
            continue
        if kind in {"php_admin_value", "php_admin_flag"}:
            locked[key] = value
        else:
            overridable[key] = value
    return locked, overridable


def _app_hit(path: str, text: str) -> AppHit | None:
    ini_line = None
    ini_value = None
    start_line = None
    for number, line in enumerate(text.splitlines(), start=1):
        if ini_line is None:
            match = _INI_SET.search(line)
            if match is not None:
                ini_line = number
                ini_value = match.group(3).lower()
        if start_line is None and _SESSION_START.search(line):
            start_line = number
        if ini_line is not None and start_line is not None:
            break
    if ini_line is None or ini_value is None:
        return None
    return AppHit(path, ini_line, ini_value, start_line)


def _boolish(value: str | None) -> bool | None:
    if value is None:
        return None
    token = value.strip().strip("\"'").lower()
    if token in {"1", "on", "true", "yes"}:
        return True
    if token in {"0", "off", "false", "no"}:
        return False
    return None


def _clean_value(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1]
    return text[:64]


def _strip_comment(line: str) -> str:
    quote = ""
    for index, char in enumerate(line):
        if char in {'"', "'"}:
            if quote == char:
                quote = ""
            elif quote == "":
                quote = char
        elif char == ";" and quote == "":
            return line[:index]
    return line


def _read_limited(path: Path, limit: int, skipped: list[SkipObs]) -> str | None:
    try:
        if path.stat().st_size > limit:
            skipped.append(SkipObs(str(path), "file is larger than the read limit"))
            return None
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        skipped.append(SkipObs(str(path), exc.strerror or "not readable"))
        return None
    if len(data) > limit:
        skipped.append(SkipObs(str(path), "file is larger than the read limit"))
        return None
    text = data.decode("utf-8", "replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def _resolve_inside(root: Path, path: Path) -> Path | None:
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    # resolve() follows links. A target outside the allowed root is not read.
    if not resolved.is_relative_to(root_resolved):
        return None
    return resolved
