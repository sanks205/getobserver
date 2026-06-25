# Contributing

Thanks for your interest in improving the AI Production Debugging Assistant!

## Development setup

1. Install [Go 1.26+](https://go.dev/dl/).
2. Clone the repo and build:
   ```bash
   go build -o observer ./cmd/cli
   ```
3. Run the test suite:
   ```bash
   go test ./...
   ```

## Project principles

- **Modular core.** Every interface (CLI, API, agent) reuses the same diagnostic
  core engine. Keep modules in `internal/` decoupled and single-purpose.
- **MVP first.** This is a practical tool, not an enterprise monitoring platform.
  Prefer the simplest thing that works; avoid unnecessary complexity.
- **Phase by phase.** Work follows the phased roadmap in the README. Land one
  phase fully — code, docs, tests — before starting the next.
- **AI explains, it does not invent.** The AI layer must ground its output in
  collected findings, never fabricate solutions.

## Pull requests

- Run `gofmt`/`go vet` and `go test ./...` before submitting.
- Include tests for new behavior.
- Keep PRs scoped to a single concern where possible.
- Update the README/roadmap when you change user-facing behavior.

## Code style

- Standard Go formatting (`gofmt`).
- Exported identifiers carry doc comments.
- Favor small packages with clear boundaries over large catch-all ones.
