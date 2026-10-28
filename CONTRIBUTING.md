# Contributing to Fool's Gold

Thank you for looking at the project. This pilot is intentionally small,
offline, and fail-closed, and contributions should keep it that way.

## Ground rules

- **Offline stays offline.** No feature may fetch from AWS, read the Windows
  Security log, deliver to a SIEM, or make any network connection except the
  existing loopback-only mock. Production transport is a separate, future
  deployment component.
- **Synthetic only.** Fixtures and examples must use synthetic content. Never
  submit real placements, telemetry, credentials or client information.
- **Fail closed.** Reject malformed, oversized or ambiguous input with a
  visible error. Never silently accept, drop, or reclassify evidence.
- **Zero runtime dependencies.** The package depends on the standard library
  only. Test-only dependencies belong in `requirements-dev.txt` with hashes.
- **Documented contracts.** Behavior changes must update
  [docs/CONTRACTS.md](docs/CONTRACTS.md) and the relevant test coverage.

## Setup

Python 3.12 or newer.

PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python -m pip install --require-hashes -r requirements-dev.txt
python -m unittest discover -s tests -v
```

Linux:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Before you open a pull request

1. Run the full test suite; it must pass on your machine.
2. Run the synthetic assurance exercise: `python -m scripts.run_synthetic_pilot`.
3. Run `ruff check .` with the repository's `[tool.ruff]` settings.
4. If you can, run a Semgrep scan (`semgrep scan --config p/default`) and
   address or justify findings with an inline `nosemgrep` annotation.
5. Update documentation for any contract, bound, or behavior change.
6. Keep the change focused; one behavior per pull request.

## Reporting defects

Open a GitHub issue with a synthetic reproducer. For suspected security
issues, follow [SECURITY.md](SECURITY.md) instead.

## Licensing

By contributing, you agree your contributions are licensed under the Apache
License 2.0, the project's license. Contributions are made under the same
terms as described in the license's contribution section.
