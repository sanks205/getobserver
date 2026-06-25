package tests

import (
	"path/filepath"
	"testing"

	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/baseline"
)

func resultWith(issues ...analyzer.Issue) *analyzer.Result {
	r := &analyzer.Result{BySeverity: map[analyzer.Severity]int{}, ByCategory: map[string]int{}}
	r.AddIssues(issues...)
	return r
}

func TestBaselineSuppressesKnownButKeepsNew(t *testing.T) {
	known := analyzer.Issue{RuleID: "SEC_TOKEN", Severity: analyzer.Critical, Category: "Security",
		Title: "Hardcoded key", File: "app/Model.php", Line: 7, Snippet: "$k='sk_live_x'"}
	// Same finding, different line — must still be recognized as the same.
	knownMoved := known
	knownMoved.Line = 42
	fresh := analyzer.Issue{RuleID: "DB_RAW_SQL_CONCAT", Severity: analyzer.High, Category: "Database",
		Title: "SQL concat", File: "app/Model.php", Line: 20, Snippet: "$q='..'.$id"}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if _, err := baseline.Write(path, []analyzer.Issue{known}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	set, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// A later scan finds the known issue (moved) plus a new one.
	got := baseline.Apply(resultWith(knownMoved, fresh), set)
	if len(got.Issues) != 1 {
		t.Fatalf("after baseline: %d issues, want 1 (only the new one)", len(got.Issues))
	}
	if got.Issues[0].RuleID != "DB_RAW_SQL_CONCAT" {
		t.Errorf("kept the wrong issue: %s", got.Issues[0].RuleID)
	}
	// Counts must be recomputed.
	if got.BySeverity[analyzer.High] != 1 || got.BySeverity[analyzer.Critical] != 0 {
		t.Errorf("counts not recomputed: %+v", got.BySeverity)
	}
}

func TestCountAtLeast(t *testing.T) {
	r := resultWith(
		analyzer.Issue{RuleID: "a", Severity: analyzer.Critical, Category: "Security", Title: "x"},
		analyzer.Issue{RuleID: "b", Severity: analyzer.Medium, Category: "Performance", Title: "y"},
		analyzer.Issue{RuleID: "c", Severity: analyzer.Low, Category: "Performance", Title: "z"},
	)
	if n := analyzer.CountAtLeast(r, analyzer.High); n != 1 {
		t.Errorf("CountAtLeast(High) = %d, want 1", n)
	}
	if n := analyzer.CountAtLeast(r, analyzer.Low); n != 3 {
		t.Errorf("CountAtLeast(Low) = %d, want 3", n)
	}
}
