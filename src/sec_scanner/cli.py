"""Command line for the local PHP checker."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from sec_scanner.compare import compare_reports
from sec_scanner.errors import SecScannerError
from sec_scanner.report import load_report, redact_report, render_text, write_reports
from sec_scanner.scan import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-scanner",
        description="Read-only local PHP patch and configuration checker.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="inventory PHP on one machine")
    scan_parser.add_argument("--root", type=Path, default=Path("/"))
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--app-dir", action="append", type=Path, default=[])
    scan_parser.add_argument("--query-version", action="append", type=Path, default=[])
    scan_parser.add_argument("--search-dir", action="append", type=Path, default=[])
    scan_parser.add_argument("--advisory", type=Path)
    scan_parser.add_argument("--redact", action="store_true")
    scan_parser.add_argument("--no-proc", action="store_true")
    scan_parser.add_argument("--max-seconds", type=float, default=60.0)

    compare_parser = subcommands.add_parser(
        "compare", help="compare a baseline report with a later one"
    )
    compare_parser.add_argument("baseline", type=Path)
    compare_parser.add_argument("current", type=Path)

    subcommands.add_parser("advisory", help="show the signed advisory bundle")

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "compare":
            return _compare(args.baseline, args.current)
        if args.command == "advisory":
            return _advisory()
    except SecScannerError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 2


def _scan(args: argparse.Namespace) -> int:
    root = args.root.expanduser()
    if not root.is_dir():
        print("scan root is not a directory", file=sys.stderr)
        return 2
    app_dirs = tuple(path.expanduser() for path in args.app_dir)
    if args.max_seconds <= 0:
        print("max seconds has to be greater than zero", file=sys.stderr)
        return 2
    print(f"scope root {root}", file=sys.stderr)
    print(f"processes {'off' if args.no_proc else 'on'}", file=sys.stderr)
    print(f"version queries {len(args.query_version)}", file=sys.stderr)
    print(f"application directories {len(app_dirs)}", file=sys.stderr)
    print(f"time limit {args.max_seconds:g} seconds", file=sys.stderr)
    if args.output is not None:
        problem = _output_problem(root, args.output.expanduser(), app_dirs)
        if problem is not None:
            print(problem, file=sys.stderr)
            return 2
    report = scan(
        root,
        app_dirs=app_dirs,
        query_versions=tuple(path.expanduser() for path in args.query_version),
        read_processes=not args.no_proc,
        extra_search_dirs=tuple(path.expanduser() for path in args.search_dir),
        advisory_path=args.advisory,
        progress=lambda stage: print(stage, file=sys.stderr),
        deadline_seconds=args.max_seconds,
    )
    if args.redact:
        report = redact_report(report, str(Path.home()))
    print(render_text(report), end="")
    if args.output is not None:
        write_reports(report, args.output.expanduser())
        print(f"wrote {args.output.expanduser()}")
    return 0


def _compare(baseline: Path, current: Path) -> int:
    result = compare_reports(load_report(baseline), load_report(current))
    print(json.dumps(result, indent=2, sort_keys=True))
    open_count = result.get("open_count")
    if isinstance(open_count, int) and open_count > 0:
        return 1
    return 0


def _advisory() -> int:
    from sec_scanner.advisory import load_for_scan

    today = datetime.now(UTC).date()
    bundle, notes = load_for_scan(None, today)
    print(f"bundle {bundle.bundle_id}")
    print(f"version {bundle.bundle_version}")
    print(f"reviewed {bundle.reviewed_on.isoformat()}")
    print(f"age_days {bundle.age_days}")
    print(f"freshness_window_days {bundle.freshness_window_days}")
    print(f"stale {str(bundle.stale).lower()}")
    print(f"rules {len(bundle.rules)}")
    for note in notes:
        print(note)
    return 0


def _output_problem(root: Path, output: Path, app_dirs: tuple[Path, ...]) -> str | None:
    try:
        resolved_output = output.resolve()
        resolved_root = root.resolve()
    except OSError:
        return "output path could not be resolved"
    if resolved_root != Path("/").resolve() and _inside(resolved_output, resolved_root):
        return "the output directory has to sit outside the scan root"
    for app_dir in app_dirs:
        try:
            resolved_app = app_dir.resolve()
        except OSError:
            return "an application directory could not be resolved"
        if _inside(resolved_output, resolved_app) or _inside(resolved_app, resolved_output):
            return "the output directory overlaps an application directory"
    return None


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)
