// Package eslint is an optional, auto-detected integration with ESLint, the
// standard linter for JavaScript/TypeScript (Theme 1 — multi-language detection).
//
// Like the Semgrep/PHPStan/Bandit/gosec integrations, it is never required:
// Observer stays a single self-contained binary. If ESLint is available (a
// project-local install in node_modules/.bin, or on PATH) and the user opts in
// (--eslint), Observer runs it over the project and merges its findings. ESLint
// is a code-quality linter rather than a security scanner, so its findings are
// filed under "Error Handling" (mirroring the PHPStan integration) and never
// inflate the Security score. Otherwise it skips gracefully.
package eslint

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

// ErrNotAvailable means no eslint executable was found (neither in the project's
// node_modules/.bin nor on PATH).
var ErrNotAvailable = errors.New("eslint not found (looked in node_modules/.bin and PATH)")

// Finding is one ESLint result, normalized for the caller to adapt.
type Finding struct {
	RuleID   string
	Severity string // Medium | Low  (ESLint has only error/warn)
	Category string // Error Handling
	Title    string
	File     string
	Line     int
	Snippet  string
	Message  string
}

const (
	maxFindings = 1000
	maxTitle    = 120
)

// resolve locates an eslint executable, preferring a project-local install.
// It returns the command name, any leading args, and whether it was found. On
// Windows the local shim is a .cmd, which must be run through the command
// processor.
func resolve(root string) (name string, pre []string, ok bool) {
	bin := "eslint"
	if runtime.GOOS == "windows" {
		bin = "eslint.cmd"
	}
	local := filepath.Join(root, "node_modules", ".bin", bin)
	if fileExists(local) {
		if runtime.GOOS == "windows" {
			return "cmd", []string{"/c", local}, true
		}
		return local, nil, true
	}
	if p, err := exec.LookPath("eslint"); err == nil {
		return p, nil, true
	}
	return "", nil, false
}

// Available reports whether an eslint executable can be found for this project.
func Available(root string) bool {
	_, _, ok := resolve(root)
	return ok
}

// Scan runs ESLint over the project at root and returns parsed findings.
// Returns ErrNotAvailable if no eslint executable is found.
func Scan(ctx context.Context, root string) ([]Finding, error) {
	name, pre, ok := resolve(root)
	if !ok {
		return nil, ErrNotAvailable
	}
	// -f json machine output; "." lints the project using its own config.
	args := append(append([]string{}, pre...), "-f", "json", ".")
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = root
	out, err := cmd.Output()
	// ESLint exits 1 when it reports lint problems — expected. Only fail if we
	// got no JSON back at all (e.g. a fatal config error, exit 2, no output).
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return Parse(out, root)
}

// --- ESLint JSON shape (subset of `eslint -f json`) ---

type eslintFile struct {
	FilePath string `json:"filePath"`
	Messages []struct {
		RuleID   string `json:"ruleId"`   // null for fatal parse errors
		Severity int    `json:"severity"` // 1 = warn, 2 = error
		Message  string `json:"message"`
		Line     int    `json:"line"`
	} `json:"messages"`
}

// Parse converts `eslint -f json` output into Findings. Exported for testing.
// root is used to make file paths project-relative.
func Parse(data []byte, root string) ([]Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// The payload is a JSON array; skip any leading noise before '['.
	if i := strings.IndexByte(string(data), '['); i > 0 {
		data = data[i:]
	}
	var files []eslintFile
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, f := range files {
		for _, m := range f.Messages {
			if len(findings) >= maxFindings {
				return findings, nil
			}
			rule := m.RuleID
			if rule == "" {
				rule = "parse-error" // fatal errors carry a null ruleId
			}
			findings = append(findings, Finding{
				RuleID:   "ESLINT:" + rule,
				Severity: mapSeverity(m.Severity),
				Category: "Error Handling",
				Title:    truncate(m.Message, maxTitle),
				File:     relPath(root, f.FilePath),
				Line:     m.Line,
				Message:  m.Message,
			})
		}
	}
	return findings, nil
}

// mapSeverity maps ESLint's 2=error/1=warn onto our scale. ESLint isn't a
// security tool, so even an "error" is capped at Medium.
func mapSeverity(s int) string {
	if s >= 2 {
		return "Medium"
	}
	return "Low"
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
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
