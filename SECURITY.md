# Security Policy

sec-scanner is a read-only, local-first PHP patch and configuration checker. It
inspects package metadata, executables, service definitions, and configuration
files on one machine; it makes no changes to the host and sends no network
traffic during a scan.

## Reporting a vulnerability in sec-scanner itself

If you find a bug in the checker that could cause it to:

- read, follow, or execute something outside its stated scan root or
  configured scope,
- crash or hang on a crafted/malicious configuration file, package record, or
  scanned directory,
- misreport a patch status in a way that could cause an operator to believe a
  vulnerable host is fixed,
- leak sensitive host data into a report beyond what the documented scope
  describes,

please report it privately rather than opening a public issue. Open a
[GitHub security advisory](../../security/advisories/new) for this
repository, or, if that is unavailable, open an issue titled only "security
contact requested" with no technical detail and a maintainer will reach out
for a private channel.

Please include:

- the affected version/commit,
- the platform (OS, distro/version),
- steps to reproduce, and
- the observed versus expected behavior.

We aim to acknowledge reports within 7 days.

## Scope notes

- This tool is defensive tooling, not an exploit framework. We will not add
  live exploit payloads, probes against third-party hosts, or anything that
  sends network traffic during a scan.
- Reports about the *accuracy* of a specific CVE's advisory data (for
  example, a vendor fixed-version mapping that is wrong or stale) are welcome
  as regular issues/PRs — these are not security vulnerabilities in the tool
  itself, but incorrect advisory data can still mislead an operator, so please
  flag them.
- This project does not currently support PHP's own CVE reporting process;
  report PHP core vulnerabilities to the
  [PHP security team](https://www.php.net/security.php), not here.

## Supported versions

Only the latest released version is supported with security fixes.
