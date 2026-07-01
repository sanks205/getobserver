// Package phpstan is an optional, auto-detected integration with PHPStan, the
// de-facto static analyzer for PHP (Theme 1 — detection depth).
//
// Like the Semgrep integration, it is never required: Observer stays a single
// self-contained binary. If the project already has PHPStan installed
// (vendor/bin/phpstan, or a global `phpstan`) AND a phpstan.neon config, Observer
// runs it with the project's own setup and folds the findings into the report —
// adding deep PHP type/bug analysis the built-in regex rules don't do. Otherwise
// it skips gracefully. We reuse the project's config rather than guessing a level,
// so results match what the team already runs.
package phpstan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// ErrNotAvailable means no phpstan binary was found (global or vendor/bin).
	ErrNotAvailable = errors.New("phpstan not found (no global phpstan and no vendor/bin/phpstan)")
	// ErrNoConfig means PHPStan is present but the project has no phpstan.neon(.dist).
	ErrNoConfig = errors.New("no phpstan.neon(.dist) config found in project root")
)

// Finding is one PHPStan result, normalized for the caller to adapt.
type Finding struct {
	RuleID   string
	Severity string // always Medium (PHPStan has no severity levels)
	Category string // Error Handling (code-health, not security)
	Title    string
	File     string
	Line     int
	Message  string
}

const (
	maxFindings = 1000
	maxTitle    = 120
)

// locate finds a runnable phpstan: a global one on PATH first, then the project's
// vendor/bin copy (the .bat shim on Windows).
func locate(root string) (bin string, ok bool) {
	if p, err := exec.LookPath("phpstan"); err == nil {
		return p, true
	}
	local := filepath.Join(root, "vendor", "bin", "phpstan")
	if runtime.GOOS == "windows" {
		local += ".bat"
	}
	if fileExists(local) {
		return local, true
	}
	return "", false
}

func hasConfig(root string) bool {
	return fileExists(filepath.Join(root, "phpstan.neon")) ||
		fileExists(filepath.Join(root, "phpstan.neon.dist"))
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Available reports whether PHPStan can run for this project (binary + config).
func Available(root string) bool {
	_, ok := locate(root)
	return ok && hasConfig(root)
}

// Scan runs PHPStan from the project root using its own config and returns parsed
// findings. Returns ErrNotAvailable / ErrNoConfig when it can't run.
func Scan(ctx context.Context, root string) ([]Finding, error) {
	bin, ok := locate(root)
	if !ok {
		return nil, ErrNotAvailable
	}
	if !hasConfig(root) {
		return nil, ErrNoConfig
	}
	cmd := exec.CommandContext(ctx, bin, "analyse", "--error-format=json", "--no-progress")
	cmd.Dir = root // run from project root so PHPStan finds its config + autoload
	out, err := cmd.Output()
	// PHPStan exits non-zero when it reports errors — expected. Only fail if we
	// got no JSON back at all.
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return Parse(out, root)
}

// --- PHPStan JSON shape (subset) ---

type phpstanOutput struct {
	Files map[string]struct {
		Messages []struct {
			Message    string `json:"message"`
			Line       int    `json:"line"`
			Identifier string `json:"identifier"`
		} `json:"messages"`
	} `json:"files"`
}

// Parse converts `phpstan analyse --error-format=json` output into Findings.
// Exported for testing. root is used to make file paths project-relative.
func Parse(data []byte, root string) ([]Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// Some setups emit a warning line before the JSON; trim to the first '{'.
	if i := strings.IndexByte(string(data), '{'); i > 0 {
		data = data[i:]
	}
	var out phpstanOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(out.Files))
	for path, fe := range out.Files {
		rel := relPath(root, path)
		for _, m := range fe.Messages {
			if len(findings) >= maxFindings {
				return findings, nil
			}
			id := m.Identifier
			if id == "" {
				id = "error"
			}
			findings = append(findings, Finding{
				RuleID:   "PHPSTAN:" + id,
				Severity: "Medium",
				Category: "Error Handling",
				Title:    truncate(m.Message, maxTitle),
				File:     rel,
				Line:     m.Line,
				Message:  m.Message,
			})
		}
	}
	return findings, nil
}

func relPath(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(p)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
