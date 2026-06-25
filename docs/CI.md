# Using Observer in CI

Observer fits any CI system: it's a single binary that scans your project,
emits **SARIF** (the standard static-analysis format), and returns a **non-zero
exit code** when a quality gate trips. Uploading the SARIF to GitHub puts
findings in the **Security tab** and annotates pull requests inline — so you get
"PR comments" with no extra tooling.

## The pieces

| Flag | Purpose |
|---|---|
| `--sarif <file>` | Write findings as SARIF 2.1.0 for code-scanning upload |
| `--fail-on <sev>` | Exit non-zero if any finding is at/above `Low\|Medium\|High\|Critical` |
| `--baseline <file>` | Suppress already-known findings — report only **new** issues |
| `--write-baseline <file>` | Record current findings as the accepted baseline |
| `--cve` | Include dependency vulnerabilities (OSV.dev) |
| `--categories` / `--min-severity` | Limit scope |

Exit codes: `0` = clean / gate passed · `2` = quality gate failed · `1` = usage/IO error.

## GitHub Actions (recommended)

The repo ships a ready workflow at [.github/workflows/observer.yml](../.github/workflows/observer.yml)
that builds from source. To scan **your** project without building, download the
released binary instead:

```yaml
name: Observer Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write        # needed to upload SARIF
jobs:
  observer:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download Observer
        run: |
          curl -sSL -o observer \
            https://github.com/<your-org>/observer/releases/latest/download/observer_linux_amd64
          chmod +x observer
      - name: Scan
        continue-on-error: true
        run: ./observer analyze . --sarif observer.sarif --fail-on High --cve
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: observer.sarif
```

After this runs, findings appear under **Security → Code scanning alerts**, and
pull requests get inline annotations automatically.

## Adopting on an existing codebase (baseline)

A mature project has pre-existing findings you don't want to block CI on. Record
them once as a baseline, commit it, and CI will then only fail on **new** issues:

```bash
# one-time, locally:
observer analyze . --write-baseline .observer-baseline.json
git add .observer-baseline.json && git commit -m "Add Observer baseline"
```
```yaml
      # in CI, report only new issues and gate on them:
      - run: ./observer analyze . --baseline .observer-baseline.json --sarif observer.sarif --fail-on Medium
```

Fingerprints exclude line numbers, so findings that merely shift up/down stay
recognized — only genuinely new problems surface.

## Other CI systems

The same binary works anywhere (GitLab CI, Jenkins, CircleCI, etc.): download the
right `observer_<os>_<arch>` asset, run `observer analyze . --fail-on High`, and
use the exit code to pass/fail the job. Most platforms can ingest SARIF too.
