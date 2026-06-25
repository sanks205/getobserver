package tests

import (
	"path/filepath"
	"testing"

	"github.com/aipda/observer/internal/runtime"
)

func TestLoadAndSummarizeRuntime(t *testing.T) {
	path := filepath.Join("testdata", "runtime.jsonl")
	events, err := runtime.Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// 7 valid events; the malformed line must be skipped.
	if len(events) != 7 {
		t.Fatalf("loaded %d events, want 7 (malformed line should be skipped)", len(events))
	}

	s := runtime.Summarize(events)
	if s.Total != 7 {
		t.Errorf("Total = %d, want 7", s.Total)
	}
	if len(s.Groups) != 3 {
		t.Fatalf("distinct signatures = %d, want 3: %+v", len(s.Groups), s.Groups)
	}

	// Most frequent signature must be the DatabaseException (4 occurrences).
	top := s.Groups[0]
	if top.Type != "DatabaseException" || top.Count != 4 {
		t.Errorf("top group = %s x%d, want DatabaseException x4", top.Type, top.Count)
	}
	if top.Line != 120 {
		t.Errorf("top group line = %d, want 120", top.Line)
	}

	// Recent events are newest-first.
	if len(s.Recent) > 0 && s.Recent[0].Timestamp < s.Recent[len(s.Recent)-1].Timestamp {
		t.Error("recent events are not sorted newest-first")
	}
}

func TestLoadRuntimeMissing(t *testing.T) {
	if _, err := runtime.Load("testdata/does-not-exist.jsonl"); err == nil {
		t.Error("expected error loading missing runtime file")
	}
}
