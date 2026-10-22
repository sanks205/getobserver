# Observer v0.8.1

Released: 23 October 2026

Observer v0.8.1 improves edition clarity, restores scanner updates that were missing from the public repository, and corrects paid-entitlement handling in Observer Pro. No existing Community capability has been moved behind a paywall.

## Community

- Clarified the Community and Pro product boundary across the README and product documentation.
- Added a verified feature inventory, edition comparison, Pro architecture overview, roadmap, implementation report, and release-readiness checklist.
- Improved positioning for local code audits, security triage, project handovers, CI enforcement, and professional reporting.
- Reduced false-positive secret findings in templates, tests, language files, seeders, and examples while retaining detection of credible secrets.
- Added Laravel-aware generated-code exclusions, Git-aware `.env` classification, documented-catch handling, and test/seeder severity refinement.
- Added scoring model v2 with separate all-engine and Observer built-in health scores, explicit external-engine contribution, and unambiguous occurrence versus issue-type counts.
- Made PHPStan imports deterministic and raised the safety ceiling so complete project results are not silently truncated at 1,000.
- Repositioned `--guidance` as deterministic local remediation; `--ai` remains a deprecated local-only alias for script compatibility.
- Improved timeout and child-process cleanup for Bandit, ESLint, and gosec integrations.
- Kept dashboard history and deltas, HTML/JSON/CSV/SARIF export, baselines, quality gates, changed-code scans, offline controls, and deterministic offline remediation guidance available in Community.

## Pro

- Made the All-Access Bundle the primary general upgrade path while retaining the individual Professional PDF, Scheduled Scans, and Premium Rules products.
- Centralized the published Gumroad product URLs and added regression coverage for product-to-entitlement mappings.
- Corrected Git-history analysis and CycloneDX SBOM access for customers with any active paid entitlement, including Scheduled Scans-only licenses.
- Added tests for malformed signed licenses, cached entitlement recognition, and tampered license-cache rejection.
- Improved activation, privacy, package, and local-attestation documentation.
- Finalized gates and attestations only after all enabled finding scans, including Pro Git-history scanning.
- Added exact Git commit provenance and enabled-engine outcomes to attestations.
- Added --require-engine with a distinct INCOMPLETE result and exit code 3.
- Closed the offline-mode Slack/Teams environment-variable bypass.
- Updated CI workflows to preserve reports and then fail when an audit fails or is incomplete.
- Aligned Pro external-engine timeouts with repository-size scaling and the bounded OBSERVER_SCAN_TIMEOUT override for cold CI runs.
- Added a customer-safe package README and refreshed all six Windows, Linux, and macOS Pro binaries.

## Compatibility and privacy

No Community feature, CLI output format, report format, entitlement identifier, activation protocol, or previously issued license was removed. Existing valid licenses remain compatible. No telemetry, paid dependency, mandatory cloud account, or mandatory network service was added.

Network access remains opt-in for features that inherently require it, including Gumroad activation and OSV vulnerability lookup. Remediation guidance is deterministic and local; no LLM or AI provider is used.

## Verification

- Community and Pro: `go test ./...` passed.
- Community and Pro: `go vet ./...` passed.
- Community-to-Pro synchronized-file validation passed.
- Pro package checksums and archive contents were verified.
- The packaged executable reports `observer 0.8.1-pro`.
