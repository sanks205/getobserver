# Observer Community Status

Updated: 2026-10-31.

This document summarizes documented capabilities. It is not a claim that every release check was rerun on this date.

## Current release: v0.8.2

- Local CLI auditing, technology detection, and heuristic security/configuration checks.
- Deterministic, local, rule-based remediation guidance.
- HTML, JSON, CSV, and SARIF output.
- Responsive local dashboard, scan history, and issue deltas.
- Updated report navigation, detail pages, printing, and Community Edition branding.
- Baselines, quality gates, changed-code scans, attestations, and pre-commit hook.
- PHP runtime event ingestion and application log analysis.
- Optional Semgrep, PHPStan, Bandit, gosec, and ESLint integrations.
- Opt-in OSV.dev dependency vulnerability lookup.
- Offline enforcement through --assert-offline.

See the [v0.8.2 release notes](docs/RELEASE-NOTES-v0.8.2.md) and [README](README.md).

## Editions

Community remains free and MIT-licensed.

Observer Pro is distributed separately as **one annual all-access subscription at $89/year**, covering premium rules, professional PDF reporting, integrated scheduled scans, and the Pro audit workflow.

[Get Observer Pro](https://observerly1.gumroad.com/l/observer-pro-offline-code-audit)

See the [edition comparison](docs/FREE-VS-PRO.md). Existing legacy-license compatibility is separate from the current sales offer.

## Distribution and validation boundaries

- Published binaries are unsigned; verify the matching release checksums before execution.
- Package-manager definitions must match the exact release assets.
- No dedicated Homebrew tap or Scoop bucket is asserted by this document.
- Scores are heuristic; findings and remediation require engineering review.
- No reproducible benchmark or false-positive rate is claimed.
- Use the [release readiness checklist](docs/RELEASE-READINESS-CHECKLIST.md) for outstanding checks.
