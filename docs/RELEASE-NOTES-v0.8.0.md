# Observer Community v0.8.0

Observer v0.8.0 strengthens offline audit reliability, privacy, release integrity, and report usefulness. Scans remain local by default and require no paid API, hosted service, or commercial dependency.

## Highlights

- Added centralized redaction of passwords, tokens, connection strings, private-key material, and other secret-like values across terminal, HTML, JSON, CSV, SARIF, attestation, and stored report output.
- Added `observer doctor` to report the installed version, platform, privacy behavior, and availability of optional local analysis tools without exposing secret values.
- Added checked-in version metadata and consistent version output for packaged binaries.
- Added stable process exit codes: `0` for success, `1` for usage or operational errors, and `2` when a configured quality gate fails.
- Added stricter validation for severity and quality-gate options so invalid values fail before a scan begins.
- Improved default exclusions for generated content, nested worktrees, local tool metadata, logs, archives, signatures, PDFs, and test build directories.
- Added repeatable directory exclusions for tighter audit scope and more accurate file and finding totals.
- Improved report safety, dashboard handling, scanner behavior, and release packaging.

## Audit And CI Improvements

- Expanded automated coverage for CLI validation, secret redaction, scanner exclusions, optional engines, report exports, and quality-gate behavior.
- Added a dedicated Community CI workflow that checks formatting, runs all Go tests, runs `go vet`, builds the CLI, and verifies the executable on pushes and pull requests.
- Preserved SARIF output for GitHub code scanning and pull-request annotations.
- Verified Community builds for Windows, Linux, and macOS on AMD64 and ARM64.

## Offline And Privacy Behavior

Observer continues to analyze source code locally. The `--assert-offline` option rejects configurations that would require a remote Semgrep registry and accepts only an existing local Semgrep configuration.

Built-in findings are curated static-analysis heuristics. They identify review candidates but do not claim full semantic or data-flow proof, third-party certification, or compliance approval.

## Community Edition

Community v0.8.0 includes local scanning, HTML/JSON/CSV/SARIF output, baselines, changed-code audits, quality gates, attestations, and optional local analysis engines.

Organization-ready PDF reporting, premium rules, SBOM generation, audit history, scheduling, and advanced report customization remain Pro features.

## Upgrade

Download the archive for your operating system and architecture from the GitHub release, then verify it with `SHA256SUMS.txt`.

Existing CLI usage remains compatible. Run the following after upgrading:

```text
observer version
observer doctor
observer analyze . --out observer-report.html
```

## Verification

The v0.8.0 source passed:

```text
gofmt
go test ./...
go vet ./...
```

Release binaries were built without a runtime cloud dependency. No paid service, license, signing certificate, or external certification was added.

## Thank You

Issues and reproducible false-positive or false-negative reports are welcome. When reporting a detection problem, include a minimal sanitized example and the Observer version, but never publish production secrets or proprietary source code.
