# Contributing

Thanks for considering a contribution to sec-scanner. This is a defensive,
read-only local checker, and that trust model is the whole point of the
project — the rules below exist to keep it that way, not as bureaucracy.

## Hard rules for any contribution

- **No network traffic during a scan.** The default scan path must never make
  an HTTP request, DNS lookup, or any other network call. Advisory data ships
  as a signed local bundle; online updates (if ever added) must be a separate,
  explicit, opt-in command — never part of `scan`.
- **No writes to the host.** The scanner must never install, upgrade, or
  remove a package, edit configuration, restart a service, or modify any file
  outside its own output directory.
- **No exploit payloads or probes.** Do not add code that sends
  memory-pressure requests, malformed multipart requests, session payloads,
  or any other attack traffic — to the local host, a staging host, or anyone
  else's system. Detection must stay package/config/metadata-based.
- **Don't execute untrusted binaries.** A binary found while walking a
  scanned directory must not be executed to get its version. Prefer package
  metadata. If an operator explicitly opts into a version query for a named
  path, show the exact command run.
- **Unknown stays unknown.** Never turn an unmapped package string, an
  unsupported vendor, or missing advisory data into a "fixed" or "vulnerable"
  verdict. If evidence is incomplete, say so.
- **Follow symlinks only within the configured scan root.** This project has
  been bitten before by symlink/path-escape bugs in similar tools — any code
  that reads a path derived from scanned input must stay inside scope and be
  tested for the escape case (symlink pointing out of root, `..` segments,
  parent directory being a link).

See `design/design.md` (in the parent directory of this repo checkout) for
the full product design and the reasoning behind these constraints.

## Development setup

```sh
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

All four must pass before a PR is merged; CI runs them on every PR.

## Advisory bundle changes

If you change anything under `src/sec_scanner/data/` or the rule-loading
code, rebuild and re-sign the bundle:

```sh
uv run python scripts/build_bundle.py
```

Cite the primary source (php.net advisory, Ubuntu/Debian security tracker,
etc.) and the date you checked it in the PR description. Do not guess a
vendor's fixed version — unmapped vendors must stay "unknown" in the rule
data, not be filled in by extrapolation from another distro.

## Pull requests

- Keep PRs focused; a bug fix doesn't need unrelated refactors.
- Add or update tests for any behavior change, especially around symlink
  handling, path scope, and patch-status logic.
- Describe what evidence/source backs any new or changed advisory rule.
