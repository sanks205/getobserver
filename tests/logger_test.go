package tests

import (
	"path/filepath"
	"testing"

	"github.com/aipda/observer/internal/logger"
)

func TestAnalyzeLogs(t *testing.T) {
	path := filepath.Join("testdata", "logs")
	s, err := logger.Analyze(path)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	if s.FilesParsed != 1 {
		t.Errorf("FilesParsed = %d, want 1", s.FilesParsed)
	}
	// 4 connection-refused + 2 deadlock + 1 curl = 7 error lines (INFO/DEBUG ignored).
	if s.TotalErrors != 7 {
		t.Errorf("TotalErrors = %d, want 7", s.TotalErrors)
	}
	if len(s.Groups) != 3 {
		t.Fatalf("distinct signatures = %d, want 3: %+v", len(s.Groups), s.Groups)
	}

	// The connection-refused error (varying host/port) must group to the top with 4.
	top := s.Groups[0]
	if top.Count != 4 {
		t.Errorf("top group count = %d, want 4", top.Count)
	}
	if top.Category != "Database" {
		t.Errorf("top group category = %q, want Database", top.Category)
	}
	if top.Cause == "" {
		t.Error("top group should have a heuristic cause")
	}

	// The cURL timeout must be categorized as API.
	foundAPI := false
	for _, g := range s.Groups {
		if g.Category == "API" {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Error("expected an API-category group (cURL timeout)")
	}
}

func TestAnalyzeLogsMissing(t *testing.T) {
	if _, err := logger.Analyze("testdata/no-such-log-dir"); err == nil {
		t.Error("expected error for missing log path")
	}
}
