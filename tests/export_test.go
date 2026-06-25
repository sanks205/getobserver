package tests

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/reporter"
	"github.com/aipda/observer/internal/scanner"
)

func exportData(t *testing.T) reporter.Data {
	t.Helper()
	res := &scanner.Result{ProjectName: "demo", RootPath: "/x", DominantLang: "PHP"}
	a := &analyzer.Result{BySeverity: map[analyzer.Severity]int{}, ByCategory: map[string]int{}, FilesScanned: 10}
	a.AddIssues(
		analyzer.Issue{RuleID: "DB_RAW_SQL_CONCAT", Severity: analyzer.High, Category: "Database",
			Title: "SQL concat", File: "m.php", Line: 12, Recommendation: "Use bindings"},
		analyzer.Issue{RuleID: "SEC_TOKEN", Severity: analyzer.Critical, Category: "Security",
			Title: "Hardcoded key", File: "c.php", Line: 7, Recommendation: "Rotate"},
	)
	return reporter.Data{Scan: res, Analysis: a}
}

func TestGenerateJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.json")
	if err := reporter.GenerateJSON(exportData(t), out); err != nil {
		t.Fatalf("json export: %v", err)
	}
	b, _ := os.ReadFile(out)
	var doc struct {
		Project       string `json:"project"`
		SecurityScore struct {
			Value int    `json:"value"`
			Grade string `json:"grade"`
		} `json:"security_score"`
		Summary  map[string]int `json:"summary"`
		Findings []struct {
			Rule, Severity, CWE, OWASP string
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Project != "demo" || doc.Summary["total"] != 2 || len(doc.Findings) != 2 {
		t.Errorf("unexpected JSON: %+v", doc)
	}
	// CWE/OWASP should be filled from the rule map.
	found := false
	for _, f := range doc.Findings {
		if f.Rule == "DB_RAW_SQL_CONCAT" && f.CWE == "CWE-89" && f.OWASP != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL finding to carry CWE-89 + OWASP in JSON")
	}
}

func TestGenerateCSV(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.csv")
	if err := reporter.GenerateCSV(exportData(t), out); err != nil {
		t.Fatalf("csv export: %v", err)
	}
	f, _ := os.Open(out)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v", err)
	}
	if len(rows) != 3 { // header + 2 findings
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0][0] != "Severity" || !strings.Contains(strings.Join(rows[0], ","), "CWE") {
		t.Errorf("unexpected header: %v", rows[0])
	}
}
