# Observer Community vs Pro

## Current offer

**Community:** free, MIT-licensed local auditing and development workflows.

**Observer Pro:** one annual all-access subscription at **$89/year** for professional audit delivery and repeat assessments.

[Get Observer Pro](https://observerly1.gumroad.com/l/observer-pro-offline-code-audit)

There are no separate add-on purchases in the current offer.

## Capability comparison

| Capability | Community | Pro |
|---|:---:|:---:|
| Local scans, technology detection, and core code/configuration/infrastructure rules | Yes | Yes |
| Runtime event ingestion, log analysis, and dependency parsing | Yes | Yes |
| HTML, JSON, CSV, and SARIF | Yes | Yes |
| Local dashboard, scan history, and issue deltas | Yes | Yes |
| Baselines, quality gates, changed-code scans, CI, and pre-commit hook | Yes | Yes |
| Plain JSON scan attestations | Yes | Yes |
| Rule-based local remediation guidance and offline scan controls | Yes | Yes |
| Optional local analysis engines and opt-in dependency vulnerability lookup | Yes | Yes |
| Premium framework-specific rules | - | Yes |
| Professional PDF with document control, navigation, grouped remediation, and optional branding | - | Yes |
| Integrated recurring scans and dashboard scheduling | - | Yes |
| Git-history secret review | - | Yes |
| CycloneDX SBOM export | - | Yes |
| HMAC companion for local scan attestations | - | Yes |

## Community remains useful on its own

Community has no artificial repository-size, file-count, or finding-count purchase limit and requires no account for core scanning.

Community can be automated through CI, cron, or Windows Task Scheduler. Integrated Pro scheduling adds a local workflow; it does not grant exclusive permission to automate scans.

Community HTML reports can be printed to PDF with Community Edition branding. Pro provides a structured, clean, brandable professional PDF.

## Activation and offline use

Pro is distributed separately. Initial activation requires an online license check. Annual licenses are machine-bound, with local expiry verification and renewal handling. Cached activation does not make an annual subscription perpetual.

Core scans and remediation guidance run locally. Optional OSV lookup, remote Semgrep rules, email, and webhook integrations can use the network. See the [privacy instructions](../README.md#privacy--air-gapped-use).

Existing legacy purchases retain their applicable compatibility requirements; they are not additional products in the current offer.

## Limits

Both editions use heuristic checks and optional engines. Neither guarantees security, certifies compliance, or replaces full semantic analysis.

An HMAC companion provides local tamper evidence. It is not an independent signature, third-party certification, or proof that findings are complete.

See [feature evidence and verification boundaries](EDITION-FEATURE-AUDIT.md).
