// Package gosec is an optional, auto-detected integration with gosec, the
// standard security scanner for Go (Theme 1 — multi-language detection).
//
// Like the Semgrep/PHPStan/Bandit integrations, it is never required: Observer
// stays a single self-contained binary. If `gosec` is on PATH and the user opts
// in (--gosec), Observer runs it over the Go project and merges its findings —
// adding Go security coverage (command injection, weak crypto, unhandled errors,
// hardcoded credentials, …). Otherwise it skips gracefully.
package gosec

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNotAvailable means the gosec binary was not found on PATH.
var ErrNotAvailable = errors.New("gosec not found on PATH")

// Finding is one gosec result, normalized for the caller to adapt.
type Finding struct {
	RuleID   string
	Severity string // Critical | High | Medium | Low
	Category string // Security
	Title    string
	File     string
	Line     int
	Snippet  string
	Message  string
	CWE      string
}

const (
	maxFindings = 1000
	maxTitle    = 120
)

// Available reports whether the gosec binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("gosec")
	return err == nil
}

// Scan runs gosec over the Go project at root and returns parsed findings.
// Returns ErrNotAvailable if gosec is not installed.
func Scan(ctx context.Context, root string) ([]Finding, error) {
	if !Available() {
		return nil, ErrNotAvailable
	}
	// -fmt=json machine output, -quiet suppresses the progress log; ./... scans
	// all packages in the module rooted at cmd.Dir.
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	// gosec exits non-zero when it finds issues — expected. Only fail if we got
	// no JSON back at all.
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return Parse(out, root)
}

// --- gosec JSON shape (subset) ---

type gosecOutput struct {
	Issues []struct {
		Severity string `json:"severity"` // LOW | MEDIUM | HIGH
		RuleID   string `json:"rule_id"`
		Details  string `json:"details"`
		File     string `json:"file"`
		Code     string `json:"code"`
		Line     string `json:"line"` // "42" or "42-44"
		CWE      struct {
			ID string `json:"id"`
		} `json:"cwe"`
	} `json:"Issues"`
}

// Parse converts `gosec -fmt=json` output into Findings. Exported for testing.
// root is used to make file paths project-relative.
func Parse(data []byte, root string) ([]Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if i := strings.IndexByte(string(data), '{'); i > 0 {
		data = data[i:]
	}
	var out gosecOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(out.Issues))
	for _, is := range out.Issues {
		if len(findings) >= maxFindings {
			break
		}
		cwe := ""
		if id := strings.TrimSpace(is.CWE.ID); id != "" {
			cwe = "CWE-" + id
		}
		findings = append(findings, Finding{
			RuleID:   "GOSEC:" + is.RuleID,
			Severity: mapSeverity(is.Severity),
			Category: "Security",
			Title:    truncate(is.Details, maxTitle),
			File:     relPath(root, is.File),
			Line:     firstInt(is.Line),
			Snippet:  truncate(strings.TrimSpace(is.Code), maxTitle),
			Message:  is.Details,
			CWE:      cwe,
		})
	}
	return findings, nil
}

func mapSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	default:
		return "Low"
	}
}

// firstInt parses the leading integer from a gosec line field like "42" or "42-44".
func firstInt(s string) int {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '-'); i > 0 {
		s = s[:i]
	}
	n, _ := strconv.Atoi(s)
	return n
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
