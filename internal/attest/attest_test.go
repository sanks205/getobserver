package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attest.json")
	in := Attestation{
		Tool: "observer", Version: "0.5.0", GeneratedAt: "2026-01-01T00:00:00Z",
		Scope: "diff-staged", Target: "/repo", FilesChanged: 2,
		Findings: map[string]int{"High": 1, "Medium": 2}, Total: 3,
		Gate: &Gate{Threshold: "High", FailCount: 1, Passed: false},
	}
	if err := Write(path, in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var out Attestation
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Scope != "diff-staged" || out.Total != 3 || out.Gate == nil || out.Gate.Passed {
		t.Errorf("round-trip mismatch: %+v", out)
	}
	if out.Findings["High"] != 1 {
		t.Errorf("expected High=1, got %d", out.Findings["High"])
	}
}
