"""Fixture trees for the read-only scanner."""

from __future__ import annotations

import os
from pathlib import Path


def proc_stat(pid: int, comm: str, start_ticks: int) -> str:
    fields = ["0"] * 20
    fields[0] = "S"
    fields[19] = str(start_ticks)
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def write_os(root: Path, os_id: str, version_id: str, codename: str) -> None:
    path = root / "etc/os-release"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'ID={os_id}\nVERSION_ID="{version_id}"\nVERSION_CODENAME={codename}\n'
        f'PRETTY_NAME="{os_id} {version_id}"\n',
        encoding="utf-8",
    )


def write_package(
    root: Path,
    name: str,
    version: str,
    *,
    arch: str = "amd64",
    files: tuple[str, ...] = (),
) -> None:
    status = root / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True, exist_ok=True)
    block = (
        f"Package: {name}\n"
        "Status: install ok installed\n"
        f"Version: {version}\n"
        f"Architecture: {arch}\n\n"
    )
    with status.open("a", encoding="utf-8") as handle:
        handle.write(block)
    if files:
        info = root / "var/lib/dpkg/info" / f"{name}.list"
        info.parent.mkdir(parents=True, exist_ok=True)
        info.write_text("".join(f"{item}\n" for item in files), encoding="utf-8")
        for item in files:
            relative = item[1:] if item.startswith("/") else item
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                destination.write_bytes(b"")


def write_process(
    root: Path,
    pid: int,
    comm: str,
    exe_target: Path,
    *,
    start_ticks: int,
    btime: int = 1_700_000_000,
    deleted: bool = False,
) -> None:
    proc = root / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "stat").write_text(f"btime {btime}\n", encoding="utf-8")
    (proc / "clk_tck").write_text("100\n", encoding="utf-8")
    entry = proc / str(pid)
    entry.mkdir(parents=True, exist_ok=True)
    (entry / "comm").write_text(comm + "\n", encoding="utf-8")
    (entry / "cmdline").write_bytes(f"{comm}: pool www\x00".encode())
    (entry / "stat").write_text(proc_stat(pid, comm, start_ticks), encoding="utf-8")
    link_text = f"{exe_target} (deleted)" if deleted else str(exe_target)
    exe = entry / "exe"
    if exe.exists() or exe.is_symlink():
        exe.unlink()
    os.symlink(link_text, exe)


def write_ini(root: Path, branch: str, sapi: str, text: str) -> Path:
    path = root / "etc/php" / branch / sapi / "php.ini"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
