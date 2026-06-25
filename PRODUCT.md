# Observer — Product Overview

> **AI Production Debugging Assistant.**
> Point it at a codebase and get a production-health report in one command — combining
> technology detection, static analysis, runtime error capture, log analysis, and
> AI-powered explanations. Zero setup. Offline. One portable binary.

**One-liner:** *What Sentry, CodeGuru, and SonarQube give you after weeks of setup, Observer gives you in one command — offline, no account, no instrumentation.*

---

## Table of contents
1. [Vision](#1-vision)
2. [The problem](#2-the-problem)
3. [The solution](#3-the-solution)
4. [What's built today](#4-whats-built-today)
5. [How it works (architecture)](#5-how-it-works-architecture)
6. [Competitive landscape & positioning](#6-competitive-landscape--positioning)
7. [Target users & use cases](#7-target-users--use-cases)
8. [Editions & pricing](#8-editions--pricing)
9. [Roadmap](#9-roadmap)
10. [Differentiators / moat](#10-differentiators--moat)

---

## 1. Vision

A single diagnostic engine that tells a developer **what is wrong with an application and why** — across code, runtime, and logs — and explains it in plain language with concrete fixes. Usable in three forms, all sharing the same core:

- **CLI** — run locally, in CI, or on a server.
- **Local dashboard / desktop app** — pick a folder, click scan, read the report.
- **Cloud / team** — hosted, multi-user, continuous, integrated.

## 2. The problem

When something breaks in production — or before it does — a developer has to manually correlate three disconnected worlds:

- **The code** (where the bug lives)
- **The runtime** (the exception that fired)
- **The logs** (how often, and what else broke)

Existing tools each cover *one* world and require heavy setup: SonarQube needs a server + CI, Sentry/Datadog need instrumentation + accounts + ongoing cost. For a quick audit, a legacy client handover, an air-gapped environment, or a solo developer, that overhead is prohibitive. **There is no zero-setup tool that unifies all three signals into one explained report.**

## 3. The solution

Observer is a ~5 MB Go binary that runs anywhere and produces one **Production Health Report** by combining:

| Signal | What Observer does |
|---|---|
| **Technology detection** | Identifies language, framework, database, infrastructure — with evidence |
| **Static analysis** | Flags security, configuration, performance, and error-handling issues with severity, location, and fix |
| **Runtime errors** | A drop-in agent captures live exceptions (type, file, line, trace, URL, user) and groups them |
| **Log analysis** | Mines existing logs for error frequency, repeated failures, and likely causes |
| **AI explanation** | Explains and prioritizes findings (root cause → impact → fix), grounded in the findings — never invented |

Output: an interactive HTML report with an executive summary, the eight standard sections, severity/category **filters**, full-text search, and **clickable locations that open the source file in VS Code at the exact line**.

## 4. What's built today

Status as of the current build (Phases 1–7 complete; 8–10 pending):

| Phase | Capability | Status |
|------:|-----------|:------:|
| 1 | Core CLI — scan a project, emit HTML report | ✅ |
| 2 | Technology detection (framework / DB / infra, evidence-based) | ✅ |
| 3 | Static code analysis (security, config, perf, error-handling) | ✅ |
| 4 | Runtime error collection (`observer-agent` for PHP) | ✅ |
| 5 | Log analyzer (`observer analyze-log`) | ✅ |
| 6 | AI analysis (OpenAI + local heuristic, provider-agnostic) | ✅ |
| 7 | Professional multi-section report (filters, search, deep links) | ✅ |
| 8 | Email reporting (SMTP) | ⏳ |
| 9 | Docker support | ⏳ |
| 10 | GitHub-quality polish | ⏳ |

**Proven characteristics:**
- **Fast** — a 17,000-file / 290 MB project analyzes in ~2 seconds (parallel workers + substring pre-gating).
- **Low-noise** — vendored code, framework cores, and minified bundles are skipped; block-comment-aware; multi-signal gating keeps false positives down.
- **Offline & dependency-free** — single binary, no server, no account; AI works in a local heuristic mode with no API key.
- **Honest** — findings are framed as *possible* issues; the AI explains, it does not invent.

### Language & capability coverage

Observer's core (report, AI, filtering) is language-agnostic; coverage per language
depends on its inputs (detection rules, static rules, runtime agent, log formats,
dependency manifests). Current state:

| Language | Tech detection | Static analysis | Runtime errors | Log analysis | Dependency CVEs |
|---|---|---|---|---|---|
| **PHP** | **Full** — Laravel, CodeIgniter 3/4, Symfony, Slim, CakePHP, Yii | **Full** — secrets, SQL injection, config, error-handling, perf | **Full** — `observer-agent` | **Full** — CodeIgniter + Monolog/Laravel | **Full** — Composer/Packagist |
| **JavaScript / TypeScript** | **Full** — Express, NestJS, Next.js, Nuxt, Angular, Koa, Fastify, React, Vue | **Good** — secrets, SQL injection, `eval`, empty-catch | Planned | **Good** — generic + Monolog-style | **Full** — npm |
| **Python** | **Full** — Django, FastAPI, Flask | **Basic** — secrets, SQL injection, perf | Planned | **Good** — generic | **Full** — PyPI |
| **Java** | **Good** — Spring (Maven/Gradle) | **Basic** — secrets, empty-catch, perf | Planned | **Good** — generic | Planned — Maven |
| **Go** | **Good** — modules | **Basic** — secrets, perf | Planned | **Good** — generic | **Full** — go.mod |
| **Ruby** | **Basic** — language detect | **Basic** — secrets, perf | Planned | **Good** — generic | Planned — RubyGems |
| **Any other** | — | Universal **secret detection** | — | **Generic** log analysis | — |

Databases detected across stacks: MySQL/MariaDB, PostgreSQL, MongoDB.
Infrastructure: Docker, Docker Compose, Kubernetes, AWS.

**How coverage grows:** runtime agents for Node/Python/Java (Phase 14), Maven &
RubyGems CVE manifests, and optional auto-detected engine wrappers (Semgrep,
PHPStan, ESLint…) that deepen static analysis without becoming a requirement.

## 5. How it works (architecture)

```
        Interfaces
   CLI  ·  Dashboard / Desktop  ·  Cloud API
                  |
                  v
         Diagnostic Core Engine
                  |
   ┌──────────────────────────────────────────────┐
   │  scanner · detector · analyzer                 │
   │  runtime (agent ingest) · logger (logs)        │
   │  ai (provider-agnostic) · reporter             │
   │  storage (SQLite / PostgreSQL)                 │
   └──────────────────────────────────────────────┘
```

- **Language:** Go (cross-platform, single executable, fast).
- **Decoupled modules:** each concern is its own package; the AI layer imports none of the others (it defines its own `Finding` type), so AI logic never leaks into the core.
- **Provider-agnostic AI:** a one-method `Provider` interface; OpenAI today, others by adding a sibling file.
- **Reserved for growth:** `api/`, `web-report/`, and `internal/storage/` are scaffolded for the dashboard and cloud tiers.

## 6. Competitive landscape & positioning

| Camp | Examples | What they miss vs Observer |
|---|---|---|
| Deep static / SAST | SonarQube, Snyk, Semgrep | Code only — no runtime, no logs, needs CI/server |
| Observability + AI | Sentry (Seer), Datadog (Bits AI) | Hosted, must instrument, ongoing cost; light static |
| AI SRE agents | Rootly, Cleric, Resolve.ai | Platforms/agents, not a folder-scanning CLI |

**No single product matches Observer's packaging:** one-shot, offline, single binary, unifying code + runtime + logs + AI. The trade-off is depth — the giants are far deeper and continuous; Observer is a fast, dependency-free **snapshot**. Observer is best positioned as the **zero-setup first-look / triage tool** for the segments the giants underserve (see §7).

> Observer does **not** try to replace SonarQube/Sentry. A team can run both: the giants for deep continuous coverage, Observer for instant offline triage.

## 7. Target users & use cases

- **Agencies & consultancies** auditing a legacy client codebase before quoting/onboarding.
- **Freelancers & SMB dev teams** who can't justify Datadog/Sonar pricing or setup.
- **Air-gapped / regulated environments** where SaaS instrumentation is impossible.
- **Incident triage** — a fast "what's broken across code + logs + runtime" before deeper tools.
- **Pre-handover / due-diligence** — a one-command health snapshot of an unfamiliar project.

## 8. Editions & pricing

Open-core value ladder (pricing illustrative, to be validated):

| Tier | Audience | Includes | Pricing model |
|---|---|---|---|
| **Community** (OSS, free) | Individuals, OSS, evaluation | CLI, single HTML report, core rules, **bring-your-own** AI key | Free |
| **Pro** (desktop) | Freelancers, agencies, SMB | `observer serve` dashboard, multi-project, history/trends, PDF + branding, scheduled scans, expanded rules | **One-time license** (illustrative $99–$149), optional paid major upgrades |
| **Cloud / Team** | Teams, orgs | Hosted, multi-user, CI integration, PR comments, Slack/Jira, retention, **hosted AI included** | **Subscription** (illustrative per-seat or flat team tiers) |

**Why hybrid:** one-time fits the offline desktop tier (low friction, matches the offline strength); subscription is required where *we* carry ongoing cost (hosted infra + AI tokens). The free OSS CLI is the adoption funnel and credibility engine.

## 9. Roadmap

**Shipped:** Phases 1–7 (see §4).

**Near term (OSS completion):**
- **Phase 8** — Email reporting (SMTP via env).
- **Phase 9** — Packaging & distribution: cross-platform single-binary builds (pure Go, no Docker, no runtime deps). *Docker/`docker-compose` is deferred to the Cloud tier (Phase 14), where it affects only our servers — never the customer's machine.*
- **Phase 10** — GitHub-quality polish (docs, screenshots, contributing).

**Product evolution:**
- **Phase 11 — `observer serve`**: local web dashboard. Pick a folder → scan → results on one page; multi-project; history & "what's new since last scan"; PDF export. *Foundation of the Pro tier; satisfies the "single page + no command prompt" goals.*
- **Phase 12 — Dependency security & (optional) engine wrappers**: ✅ dependency CVE scanning via OSV.dev (PHP/npm/PyPI/Go — no extra software, opt-in network). Planned: *optional, auto-detected* wrappers for PHPStan/Psalm, Semgrep, ESLint, gosec, Bandit that enrich results only if those tools are present — never required, preserving the zero-dependency promise. *Closes the accuracy gap with Sonar/Snyk/CodeGuru.*
- **Phase 13 — CI & team workflow**: ✅ SARIF output (GitHub code scanning + automatic PR annotations), quality gate (`--fail-on`), baseline/suppression ("report only new issues"), and a ready GitHub Actions workflow + [CI guide](docs/CI.md).
- **Phase 13.5 — Scores & standards mapping**: ✅ two density-based 0–100 grades — a **Security score** and a **Code Health score** (Sonar-style separation) — shown in the report, dashboard, and CLI and recomputed for the selected scan scope; plus **CWE + OWASP Top 10 tags** on findings (report + SARIF) for security/compliance credibility.
- **Phase 14 — Desktop app & Cloud**: Wails desktop app (one-time Pro) and/or hosted Cloud (subscription) with multi-language runtime agents (Node, Python, Java).

### Platform coverage goal

A first-class goal is **broad language/platform coverage to match what competitors cover** — not PHP-only. The path:

- **Today:** PHP deepest; basic technology signals for Node, Python, Java, Go, Ruby.
- **Phase 12:** wrap best-in-class multi-language engines (Semgrep across many languages; PHPStan/Psalm, ESLint/TypeScript, Bandit, gosec, etc.) — instant broad, accurate static coverage.
- **Phase 14:** multi-language runtime agents (Node, Python, Java) alongside the PHP agent.
- **Ongoing:** expand the detector and log-format parsers so every supported stack gets first-class treatment.

The diagnostic core, report, and AI layer are already language-agnostic — only the per-language *inputs* (rules, agents, log formats) need to grow.

## 10. Differentiators / moat

1. **Unified multi-signal report** (code + runtime + logs + AI) in one artifact — unmatched packaging.
2. **Zero setup, offline, single binary** — runs where SaaS tools can't.
3. **AI synthesis across signals**, grounded and honest.
4. **Open-core trust** — free CLI drives adoption; depth via wrapped best-in-class engines rather than reinventing them.
5. **Underserved-segment focus** — agencies, SMBs, air-gapped, due-diligence — where the giants are too heavy or too costly.

---

*This document describes the product as a whole. For build instructions and usage see [README.md](README.md).*
