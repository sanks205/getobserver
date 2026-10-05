# Observer

**Finds what's wrong — and shows you the fix.**

*Code, dependencies, config, and infra — one scan, one report. Offline, single binary, no account.*

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![Platforms](https://img.shields.io/badge/platform-windows%20%7C%20macOS%20%7C%20linux-lightgrey)
![Single binary](https://img.shields.io/badge/install-single%20binary%2C%20no%20deps-success)

## ⬇️ Get Observer

Grab the single binary for your OS — no runtime, no dependencies, no account:

| Windows | macOS (Apple Silicon) | macOS (Intel) | Linux |
|:---:|:---:|:---:|:---:|
| [**Download**](https://github.com/sanks205/getobserver/releases/latest/download/observer_windows_amd64.exe) | [**Download**](https://github.com/sanks205/getobserver/releases/latest/download/observer_darwin_arm64) | [**Download**](https://github.com/sanks205/getobserver/releases/latest/download/observer_darwin_amd64) | [**Download**](https://github.com/sanks205/getobserver/releases/latest/download/observer_linux_amd64) |

<sub>Prefer a package manager? Scoop · Homebrew · `go install` — see [Installation](#installation). On macOS/Linux: `chmod +x observer_*`.</sub>

Then point it at any project:

```bash
observer analyze . --out report.html

# Exclude project-specific generated or fixture directories by basename
observer analyze . --exclude-dir fixtures,generated --out report.html
```

You get **one self-contained `report.html`** — grouped findings, a standards-aligned Security Rating (A–E), and a suggested fix for every issue. Fully offline; open it in a browser or print to PDF.

---

> A developer-friendly tool that analyzes an application/codebase and generates a
> **production health report** - combining static analysis, technology detection,
> runtime error analysis, log analysis, dependency analysis, infrastructure and
> config checks (Dockerfile / compose / Kubernetes / .env / web-server), and
> optional AI-powered explanations.

The goal: help developers quickly identify production issues without manually
searching through huge codebases and server logs.

The CLI binary is named **`observer`**.

> **Status:** The local CLI, technology detection, static analysis, runtime and
> log analysis, HTML reporting, packaging, dashboard, opt-in dependency CVEs, and
> CI workflow are implemented. Observer Pro adds local reporting and repeat-audit
> workflow features; no hosted service is required.

---

## Demo

![Observer scanning a project and opening the production-health report](docs/observer-demo.gif)

Point it at any codebase and get one self-contained HTML report - no server, no
account, no instrumentation:

```bash
observer analyze ./examples/php-demo --ai --out report.html
```

Observer detects the stack, flags security, runtime, and dependency issues with
severity and suggested fixes, scores the project on **Security** and **Code
Health**, and writes a shareable `report.html` you can open or print to PDF.

Observer Community is free and MIT licensed and produces detailed HTML, JSON, CSV, and SARIF outputs. Observer Pro adds an organization-ready PDF with document control, grouped remediation planning, bookmarks, hyperlinks, optional client branding, and repeat-audit workflow features without a hosted dependency.

---

## How Observer compares

Observer is a local audit snapshot, not a replacement for a full semantic SAST
platform or production monitoring service. It combines lightweight built-in
heuristics with optional local tools and produces one report without requiring
an account.

| | **Observer** | **Full SAST platforms** | **Cloud security tools** | **Production monitoring** |
|---|---|---|---|---|
| **Primary job** | Private audit snapshot and handover report | Deep continuous code analysis | Hosted code/dependency analysis | Live errors and telemetry |
| **Setup** | One local binary | Local, self-hosted, or cloud setup | Account and cloud workflow | Application instrumentation |
| **Analysis depth** | Curated heuristics; optional local engines | Deeper language and data-flow analysis | Varies by vendor | Runtime rather than source audit |
| **Offline use** | Default; enforce with `--assert-offline` | Available in some products/editions | Usually cloud-dependent | Usually cloud-dependent |
| **Best fit** | Client audits, legacy reviews, handovers, air-gapped work | Large continuous engineering programs | Managed security programs | Operating live applications |

Use Observer when privacy, fast setup, and a readable point-in-time report matter.
Use a deeper SAST platform when you need broad semantic analysis, centralized
policy management, or large-team governance. The tools can complement each
other.

---

## Gate AI-generated code

AI writes a lot of code now — and it ships the exact issues Observer already catches
(hardcoded secrets, injection, weak crypto, risky deps) at a higher rate than hand-written
code. Observer is an **offline safety net for those changes**: instead of re-scanning the
whole project, scan only what changed.

```bash
# Scan only what you (or your AI assistant) just changed, vs the last commit
observer analyze . --diff

# PR review — only the lines this branch added since it forked from main
observer analyze . --diff-base main --fail-on High

# Pre-commit gate — block a commit if staged changes add a High-severity finding
observer install-hook            # one-time; bypass a commit with `git commit --no-verify`
```

Add `--attest attestation.json` to emit a machine-readable local scan record for
a PR or audit trail. It records the tool version, scope, finding counts, and gate
outcome. Observer Pro can add an HMAC companion file for local workflow integrity;
this is not a third-party signature or certification.

---

## Privacy & air-gapped use

Observer runs **fully offline by default** — nothing about your code ever leaves your
machine. There is no account, no telemetry, and no phone-home. The only features that
touch the network are explicitly opt-in: `--cve` (OSV.dev dependency lookup), `--semgrep` when using `auto` or registry rules, and `--ai`
*with* an `OPENAI_API_KEY`, and the `--email` / `--slack` / `--teams` / `--webhook`
notifiers. Leave them off and the scan is entirely local.

For regulated, air-gapped, or client-confidential work you can make that guarantee
**enforceable**:

```bash
observer analyze ./my-project --assert-offline
```

`--assert-offline` refuses network-capable options, requires `SEMGREP_CONFIG` to point to an existing local file or directory when `--semgrep` is used, and unsets
`OPENAI_API_KEY` so the AI layer stays on its local heuristic.

Inspect the privacy contract and available optional local engines without scanning:

```bash
observer doctor
```

During an enforced scan, Observer prints
`Offline mode: no network I/O.` so the enforced mode is visible in an audit log. Ideal for finance,
healthcare, government/defense, or auditing a client's code under NDA — the code stays
put.

---

## Architecture

The product is built around a single **Diagnostic Core Engine** that every
interface (CLI today; API and an enterprise agent later) reuses.

```
        Interfaces
   CLI  ·  API  ·  Enterprise agent
                |
                v
      Diagnostic Core Engine
                |
                v
  ┌─────────────────────────────────────────────┐
  │  Modules                                      │
  │  technology detector · static scanner         │
  │  runtime analyzer · log analyzer              │
  │  dependency analyzer · AI analyzer            │
  │  report generator                             │
  └─────────────────────────────────────────────┘
```

### Repository layout

```
ai-production-debugging-assistant/
├── cmd/cli/            # `observer` CLI entry point
├── internal/
│   ├── scanner/        # Phase 1 — folder scan, file counts, categories
│   ├── detector/       # Phase 2 — language/framework/db/infra detection
│   ├── analyzer/       # Phase 3 — static code analysis
│   ├── logger/         # Phase 5 — log analysis
│   ├── reporter/       # Phase 7 — HTML report generation
│   ├── runtime/        # Phase 4 — ingest observer-agent runtime events
│   ├── ai/             # Phase 6 — provider-agnostic AI abstraction
│   └── storage/        # PostgreSQL persistence (SaaS/enterprise)
├── observer-agent/     # Phase 4 — drop-in PHP runtime error collector
├── api/                # HTTP API (Gin/Fiber) — later phase
├── web-report/         # static report assets / future React dashboard
├── docker/             # Dockerfile + compose assets
├── docs/               # documentation
├── examples/           # demo projects with intentional issues
│   └── php-demo/
├── tests/              # integration tests
└── README.md
```

---

## Installation

### Download a prebuilt binary (recommended)

Observer ships as a **single self-contained executable** — no runtime, no
dependencies, nothing installed on your system. Download the binary for your OS
from the [Releases](https://github.com/sanks205/getobserver/releases) page and run it:

| OS | File |
|---|---|
| Windows | `observer_windows_amd64.exe` |
| macOS (Apple Silicon) | `observer_darwin_arm64` |
| macOS (Intel) | `observer_darwin_amd64` |
| Linux | `observer_linux_amd64` / `observer_linux_arm64` |

On macOS/Linux, make it executable: `chmod +x observer_*` (optionally rename to `observer`).

Binaries are currently **unsigned** — verify your download against `SHA256SUMS.txt` on the
[release](https://github.com/sanks205/getobserver/releases). (Signed/notarized builds are on the roadmap.)

### Install via a package manager

**Windows — [Scoop](https://scoop.sh):**

```powershell
scoop install https://raw.githubusercontent.com/sanks205/getobserver/main/packaging/scoop/observer.json
```

**macOS / Linux — [Homebrew](https://brew.sh):**

```bash
brew install https://raw.githubusercontent.com/sanks205/getobserver/main/packaging/homebrew/observer.rb
```

Both install the `observer` command onto your PATH and verify the download's SHA-256.

### Build from source

Requires [Go 1.26+](https://go.dev/dl/).

```bash
git clone https://github.com/sanks205/getobserver.git
cd getobserver
go build -o observer ./cmd/cli
```

On Windows the output is `observer.exe`. To cross-compile release binaries for all
platforms: `pwsh scripts/build-release.ps1` (or `./scripts/build-release.sh`).

---

## Usage

```bash
# Scan a project and generate report.html
observer analyze ./examples/php-demo

# Choose a custom output path
observer analyze ./examples/php-demo --out booking-report.html

# Include runtime errors captured by observer-agent (see observer-agent/)
observer analyze ./examples/php-demo --runtime /tmp/observer-runtime.jsonl

# Include application log analysis in the report
observer analyze ./examples/php-demo --logs ./examples/php-demo/logs

# Or analyze logs on their own (prints a summary)
observer analyze-log ./examples/php-demo/logs

# Launch the local web dashboard (no command line needed after this):
observer serve            # open http://127.0.0.1:7777 — paste a folder, click Scan
# Past scans, stack, issue counts, and "new since last scan" appear on one page.
# Search scans by project name or path, pick a per-page size (10/25/50), and page
# through history. Each scan row shows a signed "Change" column: +N (orange) new
# issues since the previous scan, -N (green) better, 0 flat.
# Open any report and use the browser's Print → Save as PDF.

# Add AI explanations (root cause / impact / fix) of the findings
observer analyze ./examples/php-demo --ai

# Choose what to report: only some categories, and/or a minimum severity
observer analyze ./examples/php-demo --categories "Security,Database" --min-severity High

# Scan dependencies for known vulnerabilities (OSV.dev; needs network)
observer analyze ./my-project --cve

# Air-gapped / regulated: guarantee NO network I/O — refuses --cve/--email/--slack/
# --teams/--webhook and forces AI to the local heuristic. Prints "Offline mode: no network I/O."
observer analyze ./my-project --assert-offline

# Deeper, multi-language detection if you have Semgrep installed (auto-skips if not)
observer analyze ./my-project --semgrep

# Auto-detect and fold in other engines you already have (each auto-skips if absent):
observer analyze ./my-project --phpstan --bandit --gosec --eslint

# CI: emit SARIF and fail the build on High+ findings (see docs/CI.md)
observer analyze . --sarif observer.sarif --fail-on High

# Export findings for other tools / spreadsheets
observer analyze . --json findings.json --csv findings.csv

# Notify a channel after scanning (Slack / Teams / generic webhook)
observer analyze . --slack "$SLACK_WEBHOOK"   # or --teams <url> / --webhook <url>

# Adopt on an existing codebase: record a baseline, then report only NEW issues
observer analyze . --write-baseline .observer-baseline.json
observer analyze . --baseline .observer-baseline.json --fail-on Medium

# Scan only what changed (AI safety net) — vs HEAD, a base branch, or staged changes
observer analyze . --diff --fail-on High
observer analyze . --diff-base main --fail-on High
observer analyze . --diff-staged --out "" --attest attestation.json

# Install a git pre-commit hook that gates staged changes (bypass: git commit --no-verify)
observer install-hook

# Email the report (configure SMTP via env vars; see below)
observer analyze ./examples/php-demo --email "dev@example.com,lead@example.com"
```

### Email configuration (Phase 8)

`--email` attaches the HTML report and sends a summary via SMTP. Configure with env vars:

| Variable | Purpose | Default |
|---|---|---|
| `SMTP_HOST` | SMTP server host | _(required to send)_ |
| `SMTP_PORT` | Port (587 STARTTLS, 465 implicit TLS, 25) | `587` |
| `SMTP_USER` / `SMTP_PASS` | Credentials (omit for an open relay) | _(none)_ |
| `SMTP_FROM` | From address | `SMTP_USER` |
| `OBSERVER_SMTP_DRYRUN` | Set to `1` to compose a `.eml` file instead of sending (no server needed) | _(off)_ |

```bash
# Verify composition offline without a mail server:
OBSERVER_SMTP_DRYRUN=1 SMTP_FROM=observer@example.com \
  observer analyze ./examples/php-demo --email dev@example.com
# -> writes report.html.eml next to the report
```

### AI configuration

The `--ai` flag explains findings. It is **provider-agnostic** and works offline:

- **No key set** → a local heuristic that only restates the findings (never invents).
- **`OPENAI_API_KEY` set** → uses OpenAI; falls back to local on any error.

| Variable | Purpose | Default |
|---|---|---|
| `OPENAI_API_KEY` | Enable the OpenAI provider | _(unset → local mode)_ |
| `OPENAI_MODEL` | Model id | `gpt-4o-mini` |
| `OPENAI_BASE_URL` | Override API endpoint (for proxies/testing) | OpenAI |
| `OBSERVER_AI_PROVIDER` | Set to `local` to force offline mode even with a key | _(auto)_ |

```bash

# Version / help
observer version
observer help
```

### Scan timeout

Deep scans (PHPStan + Semgrep over thousands of files) run under a single time budget.
Raise or lower it with `OBSERVER_SCAN_TIMEOUT` — a Go duration string like `15m` or `30m`:

| Variable | Purpose | Default |
|---|---|---|
| `OBSERVER_SCAN_TIMEOUT` | Max time for a deep scan before it is stopped (the engine process tree is killed on timeout, so no orphaned processes) | `15m` (hard cap `60m`) |

```bash
OBSERVER_SCAN_TIMEOUT=30m observer analyze ./my-project --phpstan --semgrep
```

### Example output

```
Scanning ./examples/php-demo ...

Project:   php-demo
Language:  PHP
Framework: CodeIgniter 3 3.1.11 [High]
Database:  MySQL [High]

Files:       6
Directories: 4

Code structure:
  Controllers: 1
  Models:      1
  Services:    1
  Config:      2

Report written to .../report.html
```

It also writes a self-contained **`report.html`** with the technology overview,
detected signals, code structure, and file-type breakdown.

---

## Roadmap

| Phase | Scope | Status |
|------:|-------|--------|
| 1 | Core CLI — scan a project, emit HTML report | ✅ Done |
| 2 | Technology detection (framework / DB / infra) | ✅ Done |
| 3 | Static code analysis (security & perf issues) | ✅ Done |
| 4 | Runtime error collection (`observer-agent`) | ✅ Done |
| 5 | Log analyzer (`observer analyze-log`) | ✅ Done |
| 6 | AI analysis module (OpenAI + pluggable providers) | ✅ Done |
| 7 | Professional multi-section HTML report | ✅ Done |
| 8 | Email reporting (SMTP) | ✅ Done |
| 9 | Packaging & distribution — cross-platform single-binary builds | ✅ Done |
| 10 | GitHub quality (README, badges, download/build, contributing) | ✅ Done |
| 11 | `observer serve` — local web dashboard (multi-project, history, deltas) | ✅ Done |
| 12 | Dependency CVE scanning (OSV.dev — PHP/npm/PyPI/Go) | ✅ Done |
| 12+ | Optional engine wrappers — Semgrep / PHPStan / Bandit / gosec / ESLint ✅ (auto-detected) | ✅ Done |
| 13 | CI & team workflow (SARIF, quality gate, baseline, GitHub workflow) | ✅ Done |
| 14 | Changed-code scanning — `--diff` gate + attestation + pre-commit hook (AI-code safety net) | ✅ Done |
| 15 | Deeper local analyzers and additional runtime agents | Planned |

For the product vision, editions, and positioning see **[PRODUCT.md](PRODUCT.md)**.

---

## Observer Pro

The CLI and local dashboard are **free forever**. **Observer Pro** adds optional paid
features — one-time purchase, activated with a license key, fully offline after activation:

- **Branded PDF reports** — client-ready PDF with your logo &amp; brand — [$39](https://observerly1.gumroad.com/l/observer-pdf)
- **Scheduled / automatic scans** — re-scan on a schedule, alert on new issues — [$29](https://observerly1.gumroad.com/l/observer-schedule)
- **Premium rule packs** — deeper framework security rules: Laravel · CodeIgniter · WordPress · Symfony · Django · Rails · Spring · Express — [$49](https://observerly1.gumroad.com/l/observer-rules-php)

Or get everything in the **[All-Access bundle — $89](https://observerly1.gumroad.com/l/observer-pro)**.
Activate with `observer pro activate <key>`.

> **🎉 Launch offer — 25% off** with code **`LAUNCH25`** at checkout (one-time, first 25 buyers).
> No pressure: run the free tool first, and if it earns a spot in your workflow, the discount's here when you want it.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

## License

[MIT](LICENSE)
