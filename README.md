# sec-scanner

[![CI](https://github.com/morrisonsaisolutions-lab/sec-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/morrisonsaisolutions-lab/sec-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Read-only checker for PHP runtimes on one Linux machine. It reports patch evidence for CVE-2026-109618 and CVE-2026-109619, and it flags the configuration pattern in PHP's notice for CVE-2026-115560. It does not install packages, edit configuration, restart services, send exploit traffic, or open a network connection.

This build is the first slice from the design in `../design/design.md`. It runs on Linux and reads dpkg. RPM, Windows, macOS, containers, and fleet scans are not claimed. It also reads common panel binary directories, systemd `ExecStart` paths for PHP units, and the executable of a running PHP worker. An absolute path in a unit file is read inside the scan root. A `php.ini` beside an unpacked binary is recorded and is not treated as the file PHP loaded. A symlink is read only when its target stays inside the scan root, including when a parent directory is the link. A `proc` directory or clock file that points outside the root is not used. A configuration file that cannot be read does not count as a mitigation. An FPM pool `chroot` is reported and not entered. Opt-in application review also reads `.user.ini` and `.htaccess`. `usr/lib/cgi-bin` is on the search list, and a binary there is reported as CGI. A pool `php_value` that turns upload progress on is not a mitigation. An application walk that skipped a file is not called clean. User and runtime systemd units are read, including an `env` command whose later argument is PHP. A leading byte-order mark does not hide the first setting. Apache `php_admin_*` lines are copied into the evidence. Their directory and virtual-host context is not evaluated, so they do not count as a locked mitigation. A relative php-fpm include that stays inside the scan root is read. One that leaves the root is not a clean configuration. Apache `Include` is followed only inside the scan root, and a serializer named there is a review lead, not a lock. A `-dev` or `-RC` banner is not a released fix. An unversioned `libphp.so` is mod_php.

## What a result means

A vendor package is compared with the signed advisory bundle, not with the upstream version inside it. Ubuntu's fixed `php8.3` package is still version 8.3.6, which is older than upstream 8.3.36, and a match to Ubuntu's fixed package is a vendor fix. A package string that does not match that vendor's version pattern stays unknown. That includes third-party builds whose version merely sorts higher than the distro fix.

`below_vendor_fix` is a mapped package older than the bundled vendor fix. The design's status list did not name that case. Leaving it as unknown would hide a package the advisory already describes.

If the bundle is older than its 14-day freshness window, fixed and affected verdicts become `stale_recheck_vendor`. Fourteen days is this build's window. The design requires one and does not set the number.

CVE-2026-115560 has no fixed release in the bundle. A static match is a review lead.

## Run

```sh
uv run sec-scanner scan
uv run sec-scanner scan --output /tmp/php-check
uv run sec-scanner scan --app-dir /var/www/example --redact
uv run sec-scanner compare /tmp/before/report.json /tmp/after/report.json
uv run sec-scanner advisory
```

`--query-version PATH` runs `PATH -v` for a binary you name. Nothing else is executed. The default scan does not run PHP.

`--output` writes `report.json`, `report.md`, and `report.html`. Without it, the scan prints a summary and writes nothing. A scan of a subtree refuses to write the report inside that subtree.

`compare` exits 1 while any finding is mitigated, unknown, still open, missing, or new. The only resolved result is a serving runtime tied to a fixed build. A temporary mitigation stays open. A missing path is not closure. The comparison records the advisory bundle, its age, scan completion, and skipped paths from both reports.

The default text report lists the searched locations, skipped paths, and limitations. `--max-seconds` defaults to 60. When that limit is reached, the scan stops and reports what it already read.

`memory_limit=-1` is a temporary mitigation for CVE-2026-109618 only when every FPM pool locks it with `php_admin_value` or `php_admin_flag`. `fatal_error_backtraces=0` on PHP 8.5 is reported as one path, not as the session mitigation. `session.upload_progress.enabled=0` does not close CVE-2026-109618.

## Advisory bundle

The bundle and the application file list are signed with Ed25519. The public key is in `src/sec_scanner/data/public_key.pem`. The private key for this machine is `~/.local/share/sec-scanner/advisory-ed25519.pem` and is not part of the tree. A scan refuses to load rules if `data/manifest.json` does not match the installed program. There is no separate release archive. After a rule or code change, run:

```sh
uv run python scripts/build_bundle.py
```

Rules were reviewed on 2026-10-26 against php.net, Ubuntu USN-8948-1 and the Ubuntu CVE pages, and the Debian security tracker. Both runtime CVEs use the same fixed package versions there. RPM, Sury, and other suppliers are absent on purpose.

The checker is free to run. There is no account, no upload, and no paid gate. A license for the source has not been chosen.

## Checks

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and the hard
rules this project runs under (no network calls during a scan, no writes to
the host, no exploit payloads). See [SECURITY.md](SECURITY.md) to report a
vulnerability in the checker itself.

## License

MIT — see [LICENSE](LICENSE).
