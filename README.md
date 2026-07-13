# Observer

**Finds what's wrong — and shows you the fix.**

*Code, dependencies, config, and infra — one scan, one report. Offline, single binary, no account.*

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![Platforms](https://img.shields.io/badge/platform-windows%20%7C%20macOS%20%7C%20linux-lightgrey)
![Single binary](https://img.shields.io/badge/install-single%20binary%2C%20no%20deps-success)

> A developer-friendly tool that analyzes an application/codebase and generates a
> **production health report** — combining static analysis, technology detection,
> runtime error analysis, log analysis, dependency analysis, infrastructure &
> config checks (Dockerfile / compose / Kubernetes / .env / web-server), and
> AI-powered explanations.

The goal: help developers quickly identify production issues without manually
searching through huge codebases and server logs.

The CLI binary is named **`observer`**.

> **Status:** Phases 1–13 complete — CLI, technology detection, static analysis,
> runtime capture, log analysis, AI, HTML report, packaging, local dashboard,
> dependency CVEs, and CI/team workflow. **Observer Pro** adds paid add-ons
> (branded PDF, scheduled scans, premium framework rules); a hosted Cloud is
> future. See [PRODUCT.md](PRODUCT.md).

---

## Demo

![Observer scanning a project and opening the production-health report](docs/observer-demo.gif)

Point it at any codebase and get one self-contained HTML report — no server, no
account, no instrumentation:

```bash
observer analyze ./examples/php-demo --ai --out report.html
```

Observer detects the stack, flags security / runtime / dependency issues with
severity and suggested fixes, scores the project on **Security** and **Code
Health** (A–F), and writes a shareable `report.html` you can open or print to PDF.

> **🎉 Launch offer** — Observer's core is **free & MIT, so start there.** If it earns a place in
> your workflow, the optional [**Observer Pro**](#observer-pro) add-ons (branded PDF reports,
> scheduled scans, deeper framework rules) are **25% off** during launch with code **`LAUNCH25`** —
> one-time purchase, first 25 buyers.

---

## How Observer compares

Observer isn't trying to replace SonarQube or Sentry — it's a different *shape* of
tool: a zero-setup, offline snapshot that unifies code, dependencies, runtime, and
logs into one report. The honest picture:

|  | **Observer** | SonarQube / Semgrep | Snyk | Sentry |
|---|---|---|---|---|
| **Setup** | One binary, offline, no account | Server/CI or cloud account | Cloud account | Instrument app + account |
| **Covers** | Code + deps + runtime + logs + **infra/config**, in **one report** | Code | Dependencies + code | Runtime errors |
| **Static-analysis depth** | Core rules + optional Semgrep | **Deeper** (many languages) | Good | — |
| **Works air-gapped / no signup** | ✅ (enforceable — `--assert-offline`) | — | — | — |
| **Pricing** | Free + one-time Pro | Subscription | Per-developer subscription | Usage + per-contributor |
| **Best for** | Audits, handovers, SMB, offline | Continuous team quality | Dependency-heavy teams | Live production monitoring |

**Use Observer when** you need a one-shot audit, a legacy/client handover, an
air-gapped scan, or a unified health snapshot without standing up a server or
paying per seat. **Reach for the others when** you need deep continuous static
analysis at scale (SonarQube/Semgrep) or always-on production monitoring
(Sentry/Datadog) — many teams happily run both.

---

## Privacy & air-gapped use

Observer runs **fully offline by default** — nothing about your code ever leaves your
machine. There is no account, no telemetry, and no phone-home. The only features that
touch the network are explicitly opt-in: `--cve` (OSV.dev dependency lookup), `--ai`
*with* an `OPENAI_API_KEY`, and the `--email` / `--slack` / `--teams` / `--webhook`
notifiers. Leave them off and the scan is entirely local.

For regulated, air-gapped, or client-confidential work you can make that guarantee
**enforceable**:

```bash
observer analyze ./my-project --assert-offline
```

`--assert-offline` refuses to run if any network-requiring flag was passed, and unsets
`OPENAI_API_KEY` so the AI layer stays on its local heuristic. It prints
`Offline mode: no network I/O.` so you can evidence it in an audit. Ideal for finance,
healthcare, government/defense, or auditing a client's code under NDA — the code stays
put, and you can prove it.

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
| 14 | Desktop app (Pro) & hosted Cloud (Team), multi-language agents | ⏳ Planned |

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
