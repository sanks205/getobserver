# Observer Product Overview

**Audit a client or legacy codebase locally and generate a shareable report in one command.**

Observer combines technology detection, heuristic code and configuration checks, dependency analysis, and optional runtime events and logs. The local CLI and dashboard help developers review unfamiliar applications, prepare handovers, and track findings.

## Current release

Observer Community v0.8.2 improves responsive dashboard layouts, report navigation, printable output, and Community Edition branding. See the [release notes](docs/RELEASE-NOTES-v0.8.2.md).

## Community

Community is MIT-licensed and includes:

- Local scanning, stack detection, and core code/configuration/infrastructure checks.
- Deterministic, rule-based remediation guidance.
- HTML, JSON, CSV, and SARIF outputs.
- A local dashboard with scan history and issue deltas.
- Baselines, quality gates, changed-code scans, and a pre-commit hook.
- Optional PHP runtime events and application log analysis.
- Optional local Semgrep, PHPStan, Bandit, gosec, and ESLint engines.
- Opt-in OSV.dev dependency vulnerability lookup.
- Offline enforcement with --assert-offline.

Core scanning needs no account or hosted Observer service. Optional engines are separate installations. Community HTML reports include Community Edition branding, including printed output.

## Observer Pro

Observer Pro is **one annual all-access subscription at $89/year**, distributed separately from the public Community source.

The subscription includes premium framework-specific rules, professional PDF reporting with document control and optional branding, integrated scheduled scans, Git-history secret review, CycloneDX SBOM export, and a local HMAC attestation companion.

[Get Observer Pro](https://observerly1.gumroad.com/l/observer-pro-offline-code-audit)

There are no separate add-on purchases in the current offer. Community automation through CI, cron, or Task Scheduler remains available.

Initial Pro activation requires an online license check. Annual licensing includes machine binding, local expiry verification, and renewal handling. Existing customers' legacy entitlements must remain compatible; the current annual offer does not redefine earlier purchases.

## Privacy

Scans and rule-based guidance run locally by default. OSV dependency lookup, remote Semgrep rule configurations, email, and webhook notifications can use the network when selected. Pro activation and renewal have separate licensing requirements.

Dependency lookups share dependency metadata, and report delivery can share project information with configured recipients. Use --assert-offline for enforced offline scans and review artifacts before sharing.

## Coverage and interpretation

Coverage depends on the project language, rules, supplied inputs, and installed engines. PHP has the shipped runtime collector; other languages can use applicable built-in checks and optional engines.

Security and Code Health scores are heuristic summaries. CWE and OWASP mappings on findings help explain issues; they do not certify compliance. False positives and missed issues are possible.

Observer supports a point-in-time audit workflow. It complements deeper semantic analysis, testing, code review, and production monitoring.

## Documentation

- [Installation, usage, and limitations](README.md)
- [Community and Pro comparison](docs/FREE-VS-PRO.md)
- [Feature evidence and verification boundaries](docs/EDITION-FEATURE-AUDIT.md)
- [CI integration](docs/CI.md)
- [Contribution guide](CONTRIBUTING.md)
