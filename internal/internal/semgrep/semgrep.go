// Package semgrep is an optional, auto-detected integration with the Semgrep
// static-analysis engine (Phase 12+/Theme 1).
//
// It is never required: Observer remains a single self-contained binary. If the
// user happens to have `semgrep` on their PATH and opts in (--semgrep), Observer
// runs it and merges its findings — adding real multi-language, data-flow-grade
// detection (XSS, SSRF, path traversal, deserialization, …) that the built-in
// regex rules don't cover. If semgrep isn't installed, the feature is skipped
// gracefully.
package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

// ErrNotAvailable means the semgrep binary was not found on PATH.
var ErrNotAvailable = errors.New("semgrep not found on PATH")

// Finding is one Semgrep result, normalized for the caller to adapt.
type Finding struct {
	RuleID   string
	Severity string // Critical | High | Medium | Low
	Category string // Security | Performance | Error Handling
	Title    string
	File     string
	Line     int
	Snippet  string
	Message  string
	CWE      string
	OWASP    string
}

// Available reports whether the semgrep binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

const maxFindings = 1000

// Scan runs semgrep over root with the given config (e.g. "auto" or a ruleset
// path) and returns parsed findings. Returns ErrNotAvailable if semgrep is not
// installed.
func Scan(ctx context.Context, root, config string) ([]Finding, error) {
	if !Available() {
		return nil, ErrNotAvailable
	}
	if config == "" {
		config = "auto"
	}
	cmd := exec.CommandContext(ctx, "semgrep", "--json", "--quiet", "--config", config, root)
	out, err := cmd.Output()
	// Semgrep exits 1 when it finds something — that's success for us. Only treat
	// it as an error if we got no parseable JSON back.
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return Parse(out)
}

// --- Semgrep JSON shape (subset) ---

type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"` // ERROR | WARNING | INFO
			Lines    string `json:"lines"`
			Metadata struct {
				CWE      json.RawMessage `json:"cwe"`      // string or []string
				OWASP    json.RawMessage `json:"owasp"`    // string or []string
				Category string          `json:"category"` // security, performance, …
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

// Parse converts semgrep --json output into Findings. Exported for testing.
func Parse(data []byte) ([]Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(out.Results))
	for _, r := range out.Results {
		if len(findings) >= maxFindings {
			break
		}
		findings = append(findings, Finding{
			RuleID:   "SEMGREP:" + shortRuleID(r.CheckID),
			Severity: mapSeverity(r.Extra.Severity),
			Category: mapCategory(r.Extra.Metadata.Category),
			Title:    firstLine(r.Extra.Message),
			File:     r.Path,
			Line:     r.Start.Line,
			Snippet:  strings.TrimSpace(firstLine(r.Extra.Lines)),
			Message:  r.Extra.Message,
			CWE:      firstOf(r.Extra.Metadata.CWE),
			OWASP:    firstOf(r.Extra.Metadata.OWASP),
		})
	}
	return findings, nil
}

func mapSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "ERROR":
		return "High"
	case "WARNING":
		return "Medium"
	default:
		return "Low"
	}
}

func mapCategory(c string) string {
	switch strings.ToLower(c) {
	case "performance":
		return "Performance"
	case "correctness", "best-practice", "maintainability":
		return "Error Handling"
	default:
		return "Security" // semgrep's default rulesets are security-focused
	}
}

// firstOf extracts the first value from a metadata field that may be a JSON
// string or an array of strings.
func firstOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return cleanCWE(s)
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return cleanCWE(arr[0])
	}
	return ""
}

// cleanCWE trims a Semgrep CWE string like "CWE-79: Cross-site Scripting" to
// just "CWE-79" for compact display.
func cleanCWE(s string) string {
	if i := strings.Index(s, ":"); i > 0 && strings.HasPrefix(s, "CWE-") {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func shortRuleID(id string) string {
	if i := strings.LastIndex(id, "."); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
