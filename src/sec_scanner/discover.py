"""Read-only discovery of PHP packages, binaries, and processes under one root."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sec_scanner.models import (
    BinaryObs,
    Discovery,
    OsInfo,
    PackageObs,
    ProcessObs,
    SkipObs,
    WorkerLink,
)

_MAX_STATUS = 32 * 1024 * 1024
_MAX_PACKAGES = 256
_MAX_LIST = 1_048_576
_MAX_PROC_DIRS = 10_000
_MAX_PROCESSES = 200
_MAX_CMDLINE = 4_096
_MAX_MAPS = 2 * 1024 * 1024
_MAX_BINARIES = 200
_MAX_SYMLINK_HOPS = 8
_FRESH_TOLERANCE_SECONDS = 1.0

_SEARCH_DIRS = (
    "usr/bin",
    "usr/sbin",
    "usr/local/bin",
    "usr/local/sbin",
    "usr/lib/apache2/modules",
    "usr/lib/cgi-bin",
    "usr/lib/httpd/modules",
    "usr/lib64/httpd/modules",
    "snap/bin",
)
_WALK_GLOBS = (
    "opt/plesk/php/*/bin",
    "opt/plesk/php/*/sbin",
    "opt/cpanel/ea-php*/root/usr/bin",
    "opt/cpanel/ea-php*/root/usr/sbin",
    "opt/alt/php*/usr/bin",
    "opt/alt/php*/usr/sbin",
    "opt/remi/php*/root/usr/bin",
    "opt/remi/php*/root/usr/sbin",
    "usr/local/php*/bin",
    "usr/local/php*/sbin",
    "usr/local/lsws/lsphp*/bin",
)
_UNIT_DIRS = (
    "etc/systemd/system",
    "etc/systemd/user",
    "lib/systemd/system",
    "usr/lib/systemd/system",
    "run/systemd/system",
)
_UNIT_GLOBS = (
    "etc/systemd/system/*php*.service",
    "etc/systemd/system/*lsphp*.service",
    "etc/systemd/system/*frankenphp*.service",
    "lib/systemd/system/*php*.service",
    "lib/systemd/system/*lsphp*.service",
    "lib/systemd/system/*frankenphp*.service",
    "usr/lib/systemd/system/*php*.service",
    "usr/lib/systemd/system/*lsphp*.service",
    "usr/lib/systemd/system/*frankenphp*.service",
    "etc/systemd/system/*php*.service.d/*.conf",
    "etc/systemd/system/*lsphp*.service.d/*.conf",
    "etc/systemd/system/*frankenphp*.service.d/*.conf",
    "lib/systemd/system/*php*.service.d/*.conf",
    "usr/lib/systemd/system/*php*.service.d/*.conf",
    "etc/systemd/user/*php*.service",
    "etc/systemd/user/*php*.service.d/*.conf",
    "run/systemd/system/*php*.service",
    "run/systemd/system/*php*.service.d/*.conf",
)
_MAX_UNIT_FILES = 100
_MAX_UNIT_BYTES = 262_144
_MAX_GLOB_DIRS = 100
_BIN_NAME = re.compile(
    r"^(?:php(?:[0-9.]+)?|php-cgi(?:[0-9.]+)?|php-fpm(?:[0-9.]+)?|lsphp(?:[0-9.]+)?|frankenphp)$"
)
_MOD_NAME = re.compile(r"^libphp(?:[0-9.]+)?\.so$")
_SOURCE_NAME = re.compile(r"^(php[0-9.]+|php5)")
_PACKAGE_NAME = re.compile(
    r"^(?:php[0-9.]+(?:-(?:cli|fpm|cgi|common))?|php5(?:-(?:cli|fpm|cgi|common))?|"
    r"libapache2-mod-php[0-9.]+)$"
)
_INTERESTING = re.compile(
    r"(?:^|[\s/])(?:php(?:-fpm|-cgi)?[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)(?:$|[\s:])"
)
_MOD_SOURCE = re.compile(r"^lib(?:apache2-mod-)?(php[0-9.]+|php5)$")


@dataclass(frozen=True, slots=True)
class Budget:
    clock: Callable[[], float]
    deadline: float

    def expired(self) -> bool:
        return self.clock() >= self.deadline


def start_budget(clock: Callable[[], float], seconds: float) -> Budget:
    return Budget(clock, clock() + seconds)


def collect(
    root: Path,
    *,
    read_processes: bool,
    extra_dirs: tuple[Path, ...],
    budget: Budget | None = None,
) -> Discovery:
    skipped: list[SkipObs] = []
    searched = _search_scope(root)
    if _expired(budget, skipped):
        return Discovery(OsInfo("", "", "", ""), (), (), (), tuple(skipped), searched)
    os_info = _read_os(root, skipped)
    packages = () if _expired(budget, skipped) else _read_packages(root, skipped)
    if read_processes:
        processes = () if _expired(budget, skipped) else _read_processes(root, skipped, budget)
    else:
        processes = ()
        skipped.append(SkipObs("proc", "process inspection disabled"))
    if _expired(budget, skipped):
        binaries: tuple[BinaryObs, ...] = ()
    else:
        binaries = _merge_binaries(
            _binaries_from_processes(root, processes, skipped),
            _binaries_from_units(root, skipped, budget),
            _read_binaries(root, extra_dirs, skipped, budget),
            skipped,
        )
    return Discovery(os_info, packages, processes, binaries, tuple(skipped), searched)


def file_workers_are_current(path: str, processes: tuple[ProcessObs, ...]) -> bool:
    matched = [process for process in processes if process.exe == path]
    if not matched:
        return False
    try:
        mtime = Path(path).stat().st_mtime
    except OSError:
        return False
    for process in matched:
        if process.exe_deleted or process.start_epoch is None:
            return False
        if mtime > process.start_epoch + _FRESH_TOLERANCE_SECONDS:
            return False
    return True


def packaged_paths(root: Path, packages: tuple[PackageObs, ...]) -> dict[str, PackageObs]:
    found: dict[str, PackageObs] = {}
    for package in packages:
        for listed in package.files:
            path = _image_path(root, listed)
            if path is not None:
                found[str(path)] = package
    return found


def contained_file(root: Path, path: Path) -> Path | None:
    resolved = _resolve_inside(root, path)
    if resolved is None or not resolved.is_file():
        return None
    return resolved


def link_workers(
    root: Path, package: PackageObs, processes: tuple[ProcessObs, ...]
) -> tuple[WorkerLink, ...]:
    files = {path for listed in package.files if (path := _image_path(root, listed)) is not None}
    names = {path.rsplit("/", 1)[-1] for path in package.files}
    links: list[WorkerLink] = []
    for process in processes:
        link = _link_one(root, files, names, process)
        if link is not None:
            links.append(link)
    return tuple(links)


def _search_scope(root: Path) -> tuple[str, ...]:
    locations = [str(root / relative) for relative in _SEARCH_DIRS]
    locations.extend(str(root / pattern) for pattern in _WALK_GLOBS)
    locations.extend(str(root / relative) for relative in _UNIT_DIRS)
    return tuple(locations)


def _expired(budget: Budget | None, skipped: list[SkipObs]) -> bool:
    if budget is None or not budget.expired():
        return False
    if not any(item.reason == "stopped at the time limit" for item in skipped):
        skipped.append(SkipObs("scan", "stopped at the time limit"))
    return True


def _glob_dirs(root: Path, skipped: list[SkipObs], budget: Budget | None) -> list[Path]:
    found: list[Path] = []
    for pattern in _WALK_GLOBS:
        if _expired(budget, skipped) or len(found) >= _MAX_GLOB_DIRS:
            break
        try:
            matches = list(root.glob(pattern))
        except OSError as exc:
            skipped.append(SkipObs(pattern, exc.strerror or "search pattern was not readable"))
            continue
        for match in matches:
            if len(found) >= _MAX_GLOB_DIRS:
                skipped.append(SkipObs(pattern, "panel path search stopped at its directory limit"))
                break
            opened = _open_dir(root, match, skipped)
            if opened is None:
                continue
            found.append(opened)
    return found


def _binaries_from_units(
    root: Path,
    skipped: list[SkipObs],
    budget: Budget | None,
) -> tuple[BinaryObs, ...]:
    found: list[BinaryObs] = []
    seen: set[str] = set()
    read = 0
    for pattern in _UNIT_GLOBS:
        if _expired(budget, skipped) or read >= _MAX_UNIT_FILES:
            break
        try:
            matches = list(root.glob(pattern))
        except OSError as exc:
            skipped.append(SkipObs(pattern, exc.strerror or "unit search was not readable"))
            continue
        for path in matches:
            if _expired(budget, skipped) or read >= _MAX_UNIT_FILES:
                skipped.append(SkipObs(pattern, "systemd unit search stopped at its file limit"))
                break
            read += 1
            text = _read_text(root, path, _MAX_UNIT_BYTES, skipped, proc=False)
            if text is None:
                continue
            for listed in _exec_paths(text):
                resolved = _resolve_exec(root, listed)
                if resolved is None:
                    skipped.append(SkipObs(listed, "executable was not found inside the scan root"))
                    continue
                _remember(resolved, found, seen, skipped, listed)
    return tuple(found)


def _binaries_from_processes(
    root: Path,
    processes: tuple[ProcessObs, ...],
    skipped: list[SkipObs],
) -> tuple[BinaryObs, ...]:
    found: list[BinaryObs] = []
    seen: set[str] = set()
    for process in processes:
        if process.exe is not None and not process.exe_deleted:
            _remember(_resolve_inside(root, Path(process.exe)), found, seen, skipped, process.exe)
        for mapped in process.map_paths:
            cleaned, deleted = _strip_deleted(mapped)
            if deleted:
                continue
            base = cleaned.rsplit("/", 1)[-1]
            if _BIN_NAME.fullmatch(base) or _MOD_NAME.fullmatch(base):
                _remember(_resolve_inside(root, Path(cleaned)), found, seen, skipped, cleaned)
    return tuple(found)


def _remember(
    resolved: Path | None,
    found: list[BinaryObs],
    seen: set[str],
    skipped: list[SkipObs],
    label: str,
) -> None:
    if len(found) >= _MAX_BINARIES:
        return
    if resolved is None:
        skipped.append(SkipObs(label, "binary path is outside the scan root"))
        return
    base = resolved.name
    if not (_BIN_NAME.fullmatch(base) or _MOD_NAME.fullmatch(base)):
        return
    try:
        info = resolved.stat()
    except OSError as exc:
        skipped.append(SkipObs(label, exc.strerror or "binary was not readable"))
        return
    if not stat.S_ISREG(info.st_mode):
        return
    key = str(resolved)
    if key in seen:
        return
    seen.add(key)
    found.append(BinaryObs(key, _binary_role(base, Path(label).parent.name)))


def _merge_binaries(
    from_processes: tuple[BinaryObs, ...],
    from_units: tuple[BinaryObs, ...],
    from_dirs: tuple[BinaryObs, ...],
    skipped: list[SkipObs],
) -> tuple[BinaryObs, ...]:
    found: list[BinaryObs] = []
    seen: set[str] = set()
    for group in (from_processes, from_units, from_dirs):
        for item in group:
            if item.path in seen:
                continue
            if len(found) >= _MAX_BINARIES:
                skipped.append(SkipObs("binaries", "binary list stopped at its file limit"))
                return tuple(found)
            seen.add(item.path)
            found.append(item)
    return tuple(found)


def _exec_paths(text: str) -> tuple[str, ...]:
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or not line.startswith("ExecStart"):
            continue
        _key, separator, rest = line.partition("=")
        if separator == "" or not rest.strip():
            continue
        command = rest.strip().lstrip("-").lstrip()
        absolute_php: str | None = None
        bare_php: str | None = None
        first_absolute: str | None = None
        for token in command.split():
            token = token.strip("\"'").lstrip("-@+!")
            if not token or ("=" in token and not token.startswith("/")):
                continue
            base = token.rsplit("/", 1)[-1]
            if _BIN_NAME.fullmatch(base) or _MOD_NAME.fullmatch(base):
                if token.startswith("/"):
                    absolute_php = token
                else:
                    bare_php = base
                break
            if token.startswith("/") and first_absolute is None:
                first_absolute = token
        chosen = absolute_php or bare_php or first_absolute
        if chosen is not None:
            found.append(chosen)
    return tuple(found)


def _resolve_exec(root: Path, listed: str) -> Path | None:
    if listed.startswith("/"):
        return _image_path(root, listed)
    for relative in ("usr/local/sbin", "usr/sbin", "usr/local/bin", "usr/bin", "usr/lib/cgi-bin"):
        candidate = _resolve_inside(root, root / relative / listed)
        if candidate is not None and candidate.is_file():
            return candidate
    return None


def _read_os(root: Path, skipped: list[SkipObs]) -> OsInfo:
    for relative in ("etc/os-release", "usr/lib/os-release"):
        text = _read_text(root, root / relative, 1_048_576, skipped, proc=False)
        if text is None:
            continue
        values = _parse_os_release(text)
        return OsInfo(
            os_id=values.get("ID", ""),
            version_id=values.get("VERSION_ID", ""),
            codename=values.get("VERSION_CODENAME", ""),
            pretty_name=values.get("PRETTY_NAME", ""),
        )
    skipped.append(SkipObs("etc/os-release", "OS release file was not readable"))
    return OsInfo("", "", "", "")


def _read_packages(root: Path, skipped: list[SkipObs]) -> tuple[PackageObs, ...]:
    listed = root / "var/lib/dpkg/status"
    if not listed.is_symlink() and not listed.is_file():
        skipped.append(SkipObs(str(listed), "dpkg status was not present"))
        return ()
    resolved_status = _resolve_inside(root, listed)
    if resolved_status is None or not resolved_status.is_file():
        skipped.append(SkipObs(str(listed), "symlink target is outside the scan root"))
        return ()
    status_path = resolved_status
    try:
        size = status_path.stat().st_size
    except OSError as exc:
        skipped.append(SkipObs(str(status_path), f"dpkg status was not readable: {exc.strerror}"))
        return ()
    if size > _MAX_STATUS:
        skipped.append(SkipObs(str(status_path), "dpkg status is larger than the read limit"))
        return ()
    try:
        with status_path.open("rb") as handle:
            data = handle.read(_MAX_STATUS + 1)
    except OSError as exc:
        skipped.append(SkipObs(str(status_path), f"dpkg status was not readable: {exc.strerror}"))
        return ()
    if len(data) > _MAX_STATUS:
        skipped.append(SkipObs(str(status_path), "dpkg status is larger than the read limit"))
        return ()
    text = data.decode("utf-8", "replace")
    found: list[PackageObs] = []
    for paragraph in _paragraphs(text):
        if len(found) >= _MAX_PACKAGES:
            skipped.append(SkipObs(str(status_path), "PHP package list was truncated"))
            break
        package = _package_from_paragraph(root, paragraph, skipped)
        if package is not None:
            found.append(package)
    return tuple(found)


def _package_from_paragraph(
    root: Path,
    paragraph: dict[str, str],
    skipped: list[SkipObs],
) -> PackageObs | None:
    parts = paragraph.get("status", "").split()
    if len(parts) < 3 or parts[0] != "install" or parts[2] != "installed":
        return None
    name = paragraph.get("package", "")
    if not _PACKAGE_NAME.fullmatch(name):
        return None
    version = paragraph.get("version", "")
    if not version or len(version) > 256:
        skipped.append(SkipObs(name, "package version was missing or too long"))
        return None
    source = _source_name(paragraph.get("source", ""), name)
    arch = paragraph.get("architecture", "")
    files = _package_files(root, name, arch, skipped)
    return PackageObs(name, source, version, arch, _role(name, binary=False), files)


def _source_name(source_field: str, package_name: str) -> str:
    raw = source_field.split(" ", 1)[0] if source_field else ""
    if raw:
        return raw
    match = _SOURCE_NAME.match(package_name)
    if match:
        return match.group(1)
    bundled = _MOD_SOURCE.fullmatch(package_name)
    if bundled:
        return bundled.group(1)
    return package_name


def _role(name: str, *, binary: bool) -> str:
    if name.startswith("libapache2-mod-php") or name.startswith("libphp"):
        return "mod_php"
    if "fpm" in name:
        return "fpm"
    if "cgi" in name:
        return "cgi"
    if "lsphp" in name:
        return "litespeed"
    if "frankenphp" in name:
        return "frankenphp"
    if name.endswith("-common"):
        return "common"
    if name.endswith("-cli") or name == "php" or (binary and re.fullmatch(r"php[0-9.]+", name)):
        return "cli"
    if _SOURCE_NAME.fullmatch(name):
        return "metapackage"
    return "unknown"


def _binary_role(name: str, directory: str) -> str:
    """A copy named php inside cgi-bin is the CGI SAPI, not the CLI."""
    if directory == "cgi-bin":
        return "cgi"
    return _role(name, binary=True)


def _package_files(root: Path, name: str, arch: str, skipped: list[SkipObs]) -> tuple[str, ...]:
    info = root / "var/lib/dpkg/info"
    candidates = [info / f"{name}.list"]
    if arch:
        candidates.append(info / f"{name}:{arch}.list")
    for path in candidates:
        target = path
        if path.is_symlink():
            resolved = _resolve_inside(root, path)
            if resolved is None:
                skipped.append(SkipObs(str(path), "symlink target is outside the scan root"))
                continue
            target = resolved
        text = _read_text(root, target, _MAX_LIST, [], proc=False)
        if text is None:
            continue
        kept: list[str] = []
        for line in text.splitlines():
            if not line.startswith("/"):
                continue
            base = line.rsplit("/", 1)[-1]
            if _BIN_NAME.fullmatch(base) or _MOD_NAME.fullmatch(base):
                kept.append(line)
            if len(kept) >= 64:
                break
        return tuple(kept)
    skipped.append(SkipObs(name, "package file list was not readable"))
    return ()


def _read_binaries(
    root: Path,
    extra_dirs: tuple[Path, ...],
    skipped: list[SkipObs],
    budget: Budget | None,
) -> tuple[BinaryObs, ...]:
    found: list[BinaryObs] = []
    directories = [root / relative for relative in _SEARCH_DIRS]
    directories.extend(_glob_dirs(root, skipped, budget))
    for extra in extra_dirs:
        resolved = _resolve_inside(root, extra)
        if resolved is None or not resolved.is_dir():
            skipped.append(
                SkipObs(str(extra), "search directory is outside the root or not a directory")
            )
            continue
        directories.append(resolved)
    seen: set[str] = set()
    for directory in directories:
        if _expired(budget, skipped):
            break
        if len(found) >= _MAX_BINARIES:
            skipped.append(SkipObs(str(directory), "binary search stopped at the file limit"))
            break
        opened = _open_dir(root, directory, skipped)
        if opened is None:
            continue
        try:
            entries = list(opened.iterdir())
        except OSError as exc:
            skipped.append(SkipObs(str(directory), f"directory was not readable: {exc.strerror}"))
            continue
        for entry in entries:
            if len(found) >= _MAX_BINARIES:
                break
            base = entry.name
            if not (_BIN_NAME.fullmatch(base) or _MOD_NAME.fullmatch(base)):
                continue
            resolved = _resolve_inside(root, entry)
            if resolved is None:
                skipped.append(SkipObs(str(entry), "symlink target is outside the scan root"))
                continue
            try:
                info = resolved.stat()
            except OSError as exc:
                skipped.append(SkipObs(str(entry), f"binary was not readable: {exc.strerror}"))
                continue
            if not stat.S_ISREG(info.st_mode):
                skipped.append(SkipObs(str(entry), "not a regular file"))
                continue
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            found.append(BinaryObs(key, _binary_role(base, directory.name)))
    return tuple(found)


def _read_processes(
    root: Path,
    skipped: list[SkipObs],
    budget: Budget | None,
) -> tuple[ProcessObs, ...]:
    proc = root / "proc"
    if not proc.is_symlink() and not proc.is_dir():
        skipped.append(SkipObs(str(proc), "process table was not present under the scan root"))
        return ()
    resolved_proc = _resolve_inside(root, proc)
    if resolved_proc is None or not resolved_proc.is_dir():
        skipped.append(SkipObs(str(proc), "symlink target is outside the scan root"))
        return ()
    ticks = _clock_ticks(root, resolved_proc)
    btime = _btime(root, resolved_proc)
    found: list[ProcessObs] = []
    seen = 0
    try:
        entries = list(resolved_proc.iterdir())
    except OSError as exc:
        skipped.append(SkipObs(str(proc), f"process table was not readable: {exc.strerror}"))
        return ()
    for entry in entries:
        if _expired(budget, skipped):
            break
        if seen >= _MAX_PROC_DIRS:
            skipped.append(SkipObs(str(proc), "process table walk was truncated"))
            break
        if not entry.name.isdigit():
            continue
        seen += 1
        if len(found) >= _MAX_PROCESSES:
            skipped.append(SkipObs(str(proc), "matching process list was truncated"))
            break
        process = _read_process(root, entry, ticks, btime, skipped)
        if process is not None:
            found.append(process)
    return tuple(found)


def _read_process(
    root: Path,
    entry: Path,
    ticks: int,
    btime: int | None,
    skipped: list[SkipObs],
) -> ProcessObs | None:
    comm = (_read_text(root, entry / "comm", 256, skipped, proc=True) or "").strip()
    cmdline_raw = _read_text(root, entry / "cmdline", _MAX_CMDLINE, skipped, proc=True) or ""
    cmdline = " ".join(part for part in cmdline_raw.split("\x00") if part)[:_MAX_CMDLINE]
    if not _process_is_interesting(comm, cmdline):
        return None
    exe_path, deleted, exe_error = _read_exe(root, entry / "exe")
    maps_text = _read_text(root, entry / "maps", _MAX_MAPS, skipped, proc=True)
    map_paths = _map_paths(maps_text) if maps_text is not None else ()
    stat_text = _read_text(root, entry / "stat", 8192, skipped, proc=True)
    start = _start_epoch(stat_text, ticks, btime)
    error = exe_error
    try:
        pid = int(entry.name)
    except ValueError:
        return None
    return ProcessObs(pid, comm, cmdline, exe_path, deleted, start, map_paths, error)


def _process_is_interesting(comm: str, cmdline: str) -> bool:
    first = cmdline.split(" ", 1)[0].rsplit("/", 1)[-1]
    return _INTERESTING.search(f" {comm} {first} ") is not None


def _read_exe(root: Path, path: Path) -> tuple[str | None, bool, str | None]:
    try:
        target = os.readlink(path)
    except OSError as exc:
        return None, False, exc.strerror or "executable link was not readable"
    deleted = target.endswith(" (deleted)")
    cleaned = target[: -len(" (deleted)")] if deleted else target
    candidate = Path(cleaned)
    if not candidate.is_absolute():
        candidate = path.parent / candidate
    resolved = _resolve_inside(root, candidate)
    if resolved is None:
        return None, deleted, "executable link is outside the scan root"
    return str(resolved), deleted, None


def _link_one(
    root: Path,
    files: set[Path],
    names: set[str],
    process: ProcessObs,
) -> WorkerLink | None:
    matched: Path | None = None
    deleted = process.exe_deleted
    if process.exe is not None:
        exe = Path(process.exe)
        if exe in files:
            matched = exe
    if matched is None:
        for mapped in process.map_paths:
            cleaned, map_deleted = _strip_deleted(mapped)
            candidate = _resolve_inside(root, Path(cleaned))
            if candidate is not None and candidate in files:
                matched = candidate
                deleted = deleted or map_deleted
                break
    if matched is None:
        if process.exe is None and process.error and _names_match(process, names):
            return WorkerLink(
                process.pid,
                False,
                False,
                None,
                f"pid {process.pid} looks like this package but its executable was not readable",
            )
        return None
    if deleted:
        return WorkerLink(
            process.pid,
            False,
            True,
            False,
            f"pid {process.pid} still has a deleted executable mapped",
        )
    fresh = _file_is_older_than_process(matched, process.start_epoch)
    detail = f"pid {process.pid} is linked to {matched.name}"
    if fresh is None:
        detail += "; its start time was not available"
    elif fresh:
        detail += "; it started after that file's mtime"
    else:
        detail += "; that file is newer than the process"
    return WorkerLink(process.pid, True, False, fresh, detail)


def _names_match(process: ProcessObs, names: set[str]) -> bool:
    tokens = {_command_name(process.comm)}
    for part in process.cmdline.split():
        tokens.add(_command_name(part.rsplit("/", 1)[-1]))
    return any(name in tokens for name in names if name)


def _command_name(token: str) -> str:
    """php-fpm rewrites argv[0] to 'php-fpm8.3: pool www'. The colon is not part of the name."""
    return token.split(":", 1)[0]


def _file_is_older_than_process(path: Path, start_epoch: float | None) -> bool | None:
    if start_epoch is None:
        return None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    return mtime <= start_epoch + _FRESH_TOLERANCE_SECONDS


def _image_path(root: Path, listed: str) -> Path | None:
    relative = listed[1:] if listed.startswith("/") else listed
    return _resolve_inside(root, root / relative)


def _strip_deleted(path: str) -> tuple[str, bool]:
    if path.endswith(" (deleted)"):
        return path[: -len(" (deleted)")], True
    return path, False


def _map_paths(text: str) -> tuple[str, ...]:
    found: list[str] = []
    for line in text.splitlines():
        if "php" not in line.lower():
            continue
        parts = line.split()
        if not parts or not parts[-1].startswith("/"):
            continue
        found.append(parts[-1])
        if len(found) >= 32:
            break
    return tuple(dict.fromkeys(found))


def _start_epoch(stat_text: str | None, ticks: int, btime: int | None) -> float | None:
    if stat_text is None or btime is None or ticks <= 0:
        return None
    end = stat_text.rfind(")")
    if end < 0:
        return None
    fields = stat_text[end + 1 :].split()
    if len(fields) < 20:
        return None
    try:
        start_ticks = int(fields[19])
    except ValueError:
        return None
    return btime + (start_ticks / ticks)


def _clock_ticks(root: Path, proc: Path) -> int:
    override = proc / "clk_tck"
    # is_symlink is first so a link is not stat'd through to a target outside the root.
    if not override.is_symlink() and not override.is_file():
        return os.sysconf("SC_CLK_TCK")
    text = _read_text(root, override, 64, [], proc=False)
    if text is None:
        return 100
    try:
        return int(text.strip())
    except ValueError:
        return 100


def _btime(root: Path, proc: Path) -> int | None:
    text = _read_text(root, proc / "stat", 1_048_576, [], proc=True)
    if text is None:
        return None
    for line in text.splitlines():
        if line.startswith("btime "):
            pieces = line.split()
            if len(pieces) == 2 and pieces[1].isdigit():
                return int(pieces[1])
    return None


def _paragraphs(text: str) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                paragraphs.append(current)
                current = {}
            continue
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip().lower()] = value.strip()
    if current:
        paragraphs.append(current)
    return paragraphs


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _open_dir(root: Path, directory: Path, skipped: list[SkipObs]) -> Path | None:
    if directory.is_symlink():
        resolved = _resolve_inside(root, directory)
        if resolved is None or not resolved.is_dir():
            skipped.append(SkipObs(str(directory), "symlink target is outside the scan root"))
            return None
        return resolved
    if not directory.is_dir():
        return None
    return directory


def _read_text(
    root: Path,
    path: Path,
    limit: int,
    skipped: list[SkipObs],
    *,
    proc: bool,
) -> str | None:
    if proc:
        # The last component of a proc file can be magic. Do not follow it.
        # A parent directory that leaves the scan root is not opened either.
        if path.is_symlink():
            return None
        parent = _resolve_inside(root, path.parent)
        if parent is None:
            return None
        target = parent / path.name
        if target.is_symlink():
            return None
    else:
        resolved = _resolve_inside(root, path)
        if resolved is None or (path.is_symlink() and not resolved.is_file()):
            skipped.append(SkipObs(str(path), "symlink target is outside the scan root"))
            return None
        target = resolved
    try:
        if not proc and target.stat().st_size > limit:
            skipped.append(SkipObs(str(path), "file is larger than the read limit"))
            return None
        with target.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        if not proc:
            skipped.append(SkipObs(str(path), exc.strerror or "not readable"))
        return None
    if len(data) > limit:
        skipped.append(SkipObs(str(path), "file is larger than the read limit"))
        return None
    return data.decode("utf-8", "replace")


def _resolve_inside(root: Path, path: Path) -> Path | None:
    current = path
    for _hop in range(_MAX_SYMLINK_HOPS):
        try:
            if not current.is_symlink():
                break
            target = Path(os.readlink(current))
        except OSError:
            return None
        current = target if target.is_absolute() else current.parent / target
    else:
        return None
    try:
        resolved = current.resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root_resolved):
        return None
    return resolved
