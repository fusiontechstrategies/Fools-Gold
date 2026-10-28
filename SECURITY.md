# Security policy

Fool's Gold is an offline decoy-detection pilot. It contains no live collection,
delivery, or response functionality, but defects in its parsing, matching, or
evidence handling could mislead an operator who relies on its decisions.

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting ("Report a vulnerability" on the
Security tab) or contact Fusion Technology Strategies directly. Do not open a
public issue for a security report.

Please include synthetic reproduction data only. Do not upload operational
placements, real telemetry, credentials, or client information.

## Scope

In scope: everything under `src/fools_gold/`, the CLI and adapter entry points,
the test suite and synthetic fixtures, and the deployment templates.

Out of scope: the documented production gaps in
[docs/SECURITY.md](docs/SECURITY.md) and
[docs/ADAPTERS.md](docs/ADAPTERS.md) — missing live collection, production SIEM
delivery, authenticated transport, evidence integrity controls and analyst
authentication are known, deliberately unimplemented boundaries, not
vulnerabilities in this release.

## Response expectations

We aim to acknowledge reports within 5 business days and to publish fixes with
release notes describing the affected behavior. Because the pilot is offline by
design, most fixes will ship as ordinary patch releases.
