# Verified Edition Feature Audit

Audited against the Community and private Pro source trees on 2026-10-17. Source and reproducible tests take precedence over marketing copy.

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
| HMAC companion attestation | No | PDF entitlement | Verified implemented | Secret is embedded in the closed binary; tamper evidence, not hardware-backed identity |
| Local dashboard | Yes | Yes | Verified implemented: scans, reports, search, pagination | Bound to localhost by default |
| Dashboard scan history and issue deltas | Yes | Yes | Verified implemented: storage/server | This is not a Pro differentiator |
| CI/SARIF/GitHub workflow | Yes | Yes | Verified implemented: `.github/workflows/observer.yml`, `docs/CI.md` | Community capability |
| Remediation guidance | Yes | Yes | Verified deterministic local heuristics | Possible fixes require developer review |
| Enforced offline mode | Yes | Yes | Verified implemented: `--assert-offline`, tests | Rejects network options and forces local AI |
| Premium framework rules | No | Premium Rules entitlement | Verified implemented: 24 rules across Laravel, CodeIgniter, WordPress, Symfony, Django, Rails, Spring, Express | Regex/heuristic rules; tests cover metadata and representative fixtures |
| Professional PDF | No | PDF entitlement | Verified implemented and tested: cover, document control, TOC, bookmarks, links, grouped remediation, metadata, branding | Community HTML can still be printed to PDF |
| Integrated scheduled scans | No | Scheduled Scans entitlement | Verified implemented: CLI loop and dashboard scheduler | Fixed intervals; dashboard supports tracked projects; external cron/CI remains available to Community |
| Scheduled notifications | CLI scheduler only | Yes | Verified implemented for Slack, Teams, generic webhook when new findings appear | Dashboard scheduler does not expose notification configuration |
| Git history secret scan | No | Any paid entitlement | Verified implemented and tested, last 200 commits | Git required; secrets redacted |
| CycloneDX SBOM | No | Any paid entitlement | Verified implemented | Reads composer, npm, Python, and Go manifests |
| PR summary workflow | No bundled template | Pro package template | Verified implemented as a workflow template | GitHub-hosted automation; not a hosted Observer service |
| Multi-project client report | No | No | Planned/evaluated only | Requires approval |
| Custom report templates/profiles | No | No | Planned/evaluated only | Requires approval |
| Hosted team service or telemetry | No | No | Not implemented by design | No mandatory account or telemetry |

## Verified entitlement model

Three stable feature IDs are issued: `branded-pdf`, `scheduled-scans`, and `premium-rules`. Gumroad product IDs map one-to-one to the individual products; the bundle maps to all three. Signed keys are verified with an embedded Ed25519 public key. Gumroad licenses are verified once online and cached for offline use with local integrity protection. Legacy signed keys remain readable.

## Material inconsistencies and risks

1. History and SBOM said “any paid feature” but excluded Scheduled-Scans-only customers. Corrected in this phase through a centralized `license.HasAny()` check.
2. The generic upgrade URL pointed to the Gumroad profile rather than the primary bundle. Corrected while retaining individual product URLs.
3. Pro documentation can make HMAC signatures sound stronger than they are. The symmetric secret is present in the client binary; wording must remain “tamper-evident local companion,” never certification or independent identity.
4. Scheduler marketing must distinguish the integrated Pro experience from free automation through cron, Task Scheduler, or CI.
5. The public README claims broad framework support accurately at a family level, but should link to a maintained rule inventory rather than imply semantic framework analysis.
6. No reproducible benchmark source for the four-project SonarQube infographic was found in the repositories. Finding counts must not be used as accuracy proof.
7. There are no build tags; proprietary separation relies on a private Pro repository plus a manifest-based shared-file synchronization check. This is workable but release discipline is essential.
