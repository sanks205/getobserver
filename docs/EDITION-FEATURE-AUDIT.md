# Edition Feature Evidence and Verification Boundaries

The table below retains implementation evidence recorded by the 2026-10-17 audit. It is not a fresh certification or a claim that all tests were rerun during this documentation update.

Current offer, updated 2026-10-31: **Observer Pro is one annual all-access subscription at $89/year**, available from the [current product page](https://observerly1.gumroad.com/l/observer-pro-offline-code-audit). All Pro capabilities below belong to that subscription. Internal compatibility gates do not indicate separate current products.

Status terms: **Verified implemented**, **Partially implemented**, **Documented but not verified**, **Planned**.

| Capability | Community | Pro | Status and evidence | Dependencies / notes |
|---|---|---|---|---|
| Local repository scan and stack detection | Yes | Yes | Verified implemented: `internal/scanner`, `internal/detector`, CLI tests | Local filesystem |
| Core security/config/infra rules | Yes | Yes | Verified implemented: `internal/analyzer`, integration tests | Heuristic, not full data-flow SAST |
| Runtime event and log analysis | Yes | Yes | Verified implemented: `internal/runtime`, `internal/logger`, tests | PHP runtime agent is shipped; other runtime agents are planned |
| Dependency manifest parsing | Yes | Yes | Verified implemented: `internal/deps` | Local parsing |
| Dependency CVE lookup | Opt-in | Opt-in | Verified implemented: `--cve`, OSV tests | Network access to OSV |
| Optional external engines | Yes | Yes | Verified implemented: Semgrep, PHPStan, Bandit, gosec, ESLint adapters | Tools must be installed; some Semgrep configs use network |
| HTML, JSON, CSV, SARIF | Yes | Yes | Verified implemented: reporter/export/SARIF tests | HTML is printable through the browser |
| Security and code-health scores | Yes | Yes | Verified implemented | Density-based heuristic scores, not certification |
| Baseline and quality gates | Yes | Yes | Verified implemented | Stable exit code 2 for gate failure |
| Changed-code and staged scans | Yes | Yes | Verified implemented: `--diff`, `--diff-base`, `--diff-staged` | Requires Git where applicable |
| Plain JSON attestation | Yes | Yes | Verified implemented | Local scan record, not third-party attestation |
| HMAC companion attestation | No | Included in Pro | Verified implemented | Secret is embedded in the closed binary; tamper evidence, not hardware-backed identity |
| Local dashboard | Yes | Yes | Verified implemented: scans, reports, search, pagination | Bound to localhost by default |
| Dashboard scan history and issue deltas | Yes | Yes | Verified implemented: storage/server | This is not a Pro differentiator |
| CI/SARIF/GitHub workflow | Yes | Yes | Verified implemented: `.github/workflows/observer.yml`, `docs/CI.md` | Community capability |
| Remediation guidance | Yes | Yes | Verified deterministic local heuristics | Possible fixes require developer review |
| Enforced offline mode | Yes | Yes | Verified implemented: `--assert-offline`, tests | Rejects network-capable options; remediation remains local |
| Premium framework rules | No | Included in Pro | Verified implemented: 24 rules across Laravel, CodeIgniter, WordPress, Symfony, Django, Rails, Spring, Express | Regex/heuristic rules; tests cover metadata and representative fixtures |
| Professional PDF | No | Included in Pro | Verified implemented and tested: cover, document control, TOC, bookmarks, links, grouped remediation, metadata, branding | Community HTML can still be printed to PDF |
| Integrated scheduled scans | No | Included in Pro | Verified implemented: CLI loop and dashboard scheduler | Fixed intervals; dashboard supports tracked projects; external cron/CI remains available to Community |
| Scheduled notifications | External automation only | Yes | Verified implemented for Slack, Teams, generic webhook when new findings appear | Dashboard scheduler does not expose notification configuration |
| Git history secret scan | No | Included in Pro | Verified implemented and tested, last 200 commits | Git required; secrets redacted |
| CycloneDX SBOM | No | Included in Pro | Verified implemented | Reads composer, npm, Python, and Go manifests |
| PR summary workflow | No bundled template | Pro package template | Verified implemented as a workflow template | GitHub-hosted automation; not a hosted Observer service |
| Multi-project client report | No | No | Planned/evaluated only | Requires approval |
| Custom report templates/profiles | No | No | Planned/evaluated only | Requires approval |
| Hosted team service or telemetry | No | No | Not implemented by design | No mandatory account or telemetry |

## Current licensing documentation

The v0.8.2 Pro release notes describe annual activation, machine binding, local expiry verification, and renewal handling. Initial activation requires an online check. Existing legacy licenses require compatibility handling and must not be reinterpreted as new annual purchases.

Private licensing implementation and lifecycle tests require a separate Pro review. This Community documentation update does not claim that review is complete.

## Interpretation and evidence limits

- HMAC companions provide local tamper evidence, not independent identity or security certification.
- Pro scheduling is an integrated workflow; Community can still use CI, cron, or Task Scheduler.
- Framework detection does not imply complete semantic analysis or full framework coverage.
- The older audit recorded 24 premium rules. Treat that as a dated private-source observation, not a newly verified v0.8.2 rule inventory.
- No reproducible benchmark or false-positive rate is established by the comparison material. See [comparison validation](marketing/COMPARISON-VALIDATION.md).
- Shared-file synchronization and private/public repository boundaries require release checks.
- Security and Code Health scores are heuristic; CWE and OWASP tags are finding mappings, not proof of compliance.
