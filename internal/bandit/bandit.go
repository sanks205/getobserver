// Package bandit is an optional, auto-detected integration with Bandit, the
// standard security linter for Python (Theme 1 — multi-language detection).
//
// Like the Semgrep/PHPStan integrations, it is never required: Observer stays a
// single self-contained binary. If `bandit` is on PATH and the user opts in
// (--bandit), Observer runs it and merges its findings — adding Python security
// coverage (shell injection, insecure deserialization, weak crypto, hardcoded
// passwords, …) that the built-in regex rules don't do. Otherwise it skips
// gracefully. Bandit needs no project config, so it wraps cleanly ad-hoc.
package bandit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNotAvailable means the bandit binary was not found on PATH.
var ErrNotAvailable = errors.New("bandit not found on PATH")

// Finding is one Bandit result, normalized for the caller to adapt.
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

// Available reports whether the bandit binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("bandit")
	return err == nil
}

// Scan runs bandit recursively over root and returns parsed findings. Returns
// ErrNotAvailable if bandit is not installed.
func Scan(ctx context.Context, root string) ([]Finding, error) {
	if !Available() {
		return nil, ErrNotAvailable
	}
	// -r recursive, -f json machine output, -q quiet (no banner on stdout).
	cmd := exec.CommandContext(ctx, "bandit", "-r", root, "-f", "json", "-q")
	out, err := cmd.Output()
	// Bandit exits 1 when it finds issues — that's success for us. Only treat it
	// as an error if we got no parseable JSON back.
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return Parse(out, root)
}

// --- Bandit JSON shape (subset) ---

type banditOutput struct {
	Results []struct {
		Filename      string `json:"filename"`
		IssueSeverity string `json:"issue_severity"` // LOW | MEDIUM | HIGH | UNDEFINED
		IssueText     string `json:"issue_text"`
		TestID        string `json:"test_id"`
		LineNumber    int    `json:"line_number"`
		Code          string `json:"code"`
		IssueCWE      struct {
			ID int `json:"id"`
		} `json:"issue_cwe"`
	} `json:"results"`
}

// Parse converts `bandit -f json` output into Findings. Exported for testing.
// root is used to make file paths project-relative.
func Parse(data []byte, root string) ([]Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if i := strings.IndexByte(string(data), '{'); i > 0 {
		data = data[i:]
	}
	var out banditOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(out.Results))
	for _, r := range out.Results {
		if len(findings) >= maxFindings {
			break
		}
		cwe := ""
		if r.IssueCWE.ID > 0 {
			cwe = fmt.Sprintf("CWE-%d", r.IssueCWE.ID)
		}
		findings = append(findings, Finding{
			RuleID:   "BANDIT:" + r.TestID,
			Severity: mapSeverity(r.IssueSeverity),
			Category: "Security",
			Title:    truncate(r.IssueText, maxTitle),
			File:     relPath(root, r.Filename),
			Line:     r.LineNumber,
			Snippet:  codeLine(r.Code, r.LineNumber),
			Message:  r.IssueText,
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

func relPath(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(p)
}

// codeLine pulls the source line matching want from Bandit's "code" excerpt,
// which is formatted like "41 import os\n42 os.system(cmd)\n". Falls back to the
// first meaningful line if the wanted line number isn't present.
func codeLine(code string, want int) string {
	first := ""
	for _, ln := range strings.Split(code, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		num, rest := splitLineNum(ln)
		if rest == "" {
			continue
		}
		if first == "" {
			first = rest
		}
		if num == want {
			return truncate(rest, maxTitle)
		}
	}
	return truncate(first, maxTitle)
}

// splitLineNum splits "42 code here" into (42, "code here"). If there's no
// leading line number, returns (0, s).
func splitLineNum(s string) (int, string) {
	if i := strings.IndexByte(s, ' '); i > 0 && isDigits(s[:i]) {
		n, _ := strconv.Atoi(s[:i])
		return n, strings.TrimSpace(s[i+1:])
	}
	return 0, s
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
