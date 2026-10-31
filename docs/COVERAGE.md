# Community Language and Framework Coverage

This documents the v0.8.2 Community source. Detection of a framework is separate from analysis depth.

## Built-in analysis and optional engines

| Language / input | Community analysis | Optional engine |
|---|---|---|
| PHP | PHP-specific patterns, generic secrets, SQL concatenation, reflected-output patterns, null chains, empty catches, and Composer checks | PHPStan, Semgrep |
| JavaScript / TypeScript, JSX / TSX | Selected execution and DOM patterns, generic checks; individual rule extensions can be narrower than the language family | ESLint, Semgrep |
| Python | Selected execution, subprocess, serialization, YAML, TLS, and generic patterns | Bandit, Semgrep |
| Java | Selected execution, SQL concatenation, deserialization, hashing, and generic patterns | Semgrep |
| Ruby | Selected execution, YAML, Marshal, and generic patterns | Semgrep |
| Go | Applicable generic source checks | gosec, Semgrep |
| Dockerfile, Compose, Kubernetes, environment, web-server configuration | 17 infrastructure rule IDs | Separate third-party tools are not bundled |
| Application logs and PHP runtime events | Supplied-input analysis; not counted as source rule IDs | No additional runtime agents are claimed |

Core source eligibility includes .php, .js, .ts, .jsx, .tsx, .py, .java, .rb, and .go. Each rule can further restrict extensions or contexts. Generic checks do not mean full language support.

## Technology detection

| Family | Named framework signals in Community |
|---|---|
| PHP | Laravel, CodeIgniter 3/4, Symfony, Slim, CakePHP, Yii 2 |
| JavaScript / TypeScript | NestJS, Next.js, Nuxt, Angular, Express, Koa, Fastify, Hapi, React, Vue |
| Python | Django, FastAPI, Flask |
| Java | Spring |
| Go | Module-based language signals; no Go framework-specific analysis is claimed |

These are manifest/marker signals, not a promise that all files, versions, configurations, or vulnerabilities are analyzed. Community detection must not be confused with private Pro framework-rule coverage.

Source: [detector rules](../internal/detector/rules.go).

## Dependency and input boundaries

Local parsing and heuristic manifest checks are distinct from the opt-in OSV lookup. OSV coverage uses the implemented Composer/Packagist, npm, PyPI, and Go inputs and depends on the available manifest data and service results.

Runtime event ingestion uses the shipped PHP collector. Log analysis depends on supplied logs and recognized formats. No running application is required for source scanning.

## Rule inventory and practical evidence

There are **54 distinct built-in analyzer rule IDs**: 29 line rules, 17 infrastructure rules, and 8 specialized checks. Token patterns can share an ID. This total excludes external tools, OSV vulnerability entries, technology signals, runtime/log groups, and private Pro rules.

- [Generated rule inventory](RULE-INVENTORY.md)
- [Rating methodology](RATING-METHODOLOGY.md)
- [Pinned DVWA reference run, including limits](benchmarks/DVWA-v0.8.2.md)
- [Public sample report](sample-report.html)

No overall detection rate or false-positive rate is established by these examples.
