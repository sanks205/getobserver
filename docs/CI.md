# Using Observer in CI

Observer is a single binary that emits portable reports and returns a nonzero exit code when an audit fails or cannot complete its required checks.

## Policy controls

| Flag | Purpose |
|---|---|
| `--sarif <file>` | Write SARIF 2.1.0 for code-scanning upload |
| `--attest <file>` | Record commit SHA, scope, tool version, engine outcomes, findings, and final status |
| `--fail-on <sev>` | Fail when a finding reaches `Low`, `Medium`, `High`, or `Critical` |
| `--require-engine <list>` | Mark the audit incomplete unless every listed engine completes |
| `--baseline <file>` | Suppress accepted findings and report only new issues |
| `--assert-offline` | Reject explicit or environment-configured network operations |

Exit codes:

- `0`: audit passed
- `1`: usage, input, or output error
- `2`: quality gate failed
- `3`: audit incomplete because a required engine or mandatory phase did not complete

## GitHub Actions

The supplied workflows deliberately allow the audit step to finish without immediately stopping the job. They then upload reports with `if: always()` and use a final enforcement step to fail the job when the audit outcome was unsuccessful. Do not remove that final enforcement step.

```yaml
- name: Run Observer
  id: observer
  continue-on-error: true
  run: >-
    ./observer analyze .
    --out observer-report.html
    --json observer-findings.json
    --sarif observer.sarif
    --attest observer-attestation.json
    --fail-on High
    --require-engine phpstan,semgrep

- name: Upload Observer reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: observer-${{ github.sha }}
    if-no-files-found: warn
    path: |
      observer-report.html
      observer-findings.json
      observer.sarif
      observer-attestation.json
      observer-attestation.json.sig

- name: Enforce Observer result
  if: always() && steps.observer.outcome == 'failure'
  run: exit 1
```

Only require engines that the runner installs first. A missing required engine correctly produces `INCOMPLETE`, not PASS.

## Laravel projects

For a Laravel repository, PHPStan/Larastan and Semgrep can be required audit engines. Application tests remain a separate CI control:

```yaml
- name: Laravel tests
  run: php artisan test

- name: Observer audit
  id: observer
  continue-on-error: true
  run: ./observer analyze . --phpstan --semgrep --require-engine phpstan,semgrep --fail-on High --attest observer-attestation.json --out observer-report.html
```

Observer Pro may additionally add `--history`, `--sbom`, and `--pdf`. When `--history` is enabled, a history-scan failure makes the audit incomplete and history findings participate in the final gate and attestation.

## Baselines

For an established codebase, create a reviewed baseline once and commit it:

```bash
observer analyze . --write-baseline .observer-baseline.json
```

Then use `--baseline .observer-baseline.json` in CI. Fingerprints exclude line numbers, so moved findings remain recognized while genuinely new findings are gated.