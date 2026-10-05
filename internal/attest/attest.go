// Package attest writes a machine-readable local scan record: what was scanned,
// what was found, and whether the quality gate passed. It can support a review
// trail, but it is not third-party certification. Pro may add a local HMAC
// companion file for workflow integrity checks.
package attest

import (
	"encoding/json"
	"os"
)

// Attestation is the record written by --attest.
type Attestation struct {
	Tool         string         `json:"tool"`         // always "observer"
	Version      string         `json:"version"`      // tool version
	GeneratedAt  string         `json:"generated_at"` // RFC3339 UTC
	Scope        string         `json:"scope"`        // "full" | "diff" | "diff-staged" | "diff-base:<ref>"
	Target       string         `json:"target"`       // scanned path
	FilesChanged int            `json:"files_changed,omitempty"`
	Findings     map[string]int `json:"findings"` // count by severity, e.g. {"High":1,"Medium":2}
	Total        int            `json:"total_findings"`
	Gate         *Gate          `json:"gate,omitempty"`
}

// Gate captures the quality-gate outcome when --fail-on was used.
type Gate struct {
	Threshold string `json:"threshold"`
	FailCount int    `json:"fail_count"`
	Passed    bool   `json:"passed"`
}

// Write marshals the attestation as indented JSON to path.
func Write(path string, a Attestation) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
