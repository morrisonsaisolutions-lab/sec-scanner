"""Observations collected from a host tree. Paths stay as text for the report."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OsInfo:
    os_id: str
    version_id: str
    codename: str
    pretty_name: str


@dataclass(frozen=True, slots=True)
class PackageObs:
    name: str
    source: str
    version: str
    arch: str
    role: str
    files: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProcessObs:
    pid: int
    comm: str
    cmdline: str
    exe: str | None
    exe_deleted: bool
    start_epoch: float | None
    map_paths: tuple[str, ...]
    error: str | None


@dataclass(frozen=True, slots=True)
class BinaryObs:
    path: str
    role: str


@dataclass(frozen=True, slots=True)
class SkipObs:
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class WorkerLink:
    pid: int
    tied: bool
    deleted: bool
    fresh: bool | None
    detail: str


@dataclass(frozen=True, slots=True)
class Discovery:
    os_info: OsInfo
    packages: tuple[PackageObs, ...]
    processes: tuple[ProcessObs, ...]
    binaries: tuple[BinaryObs, ...]
    skipped: tuple[SkipObs, ...]
    searched: tuple[str, ...]
