package tests

import (
	"testing"

	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/compliance"
)

func TestComplianceBuild(t *testing.T) {
	issues := []analyzer.Issue{
		{RuleID: "DB_RAW_SQL_CONCAT", Severity: analyzer.High, Category: "Database", Title: "sql"},   // A03 / CWE-89
		{RuleID: "DB_RAW_SQL_CONCAT", Severity: analyzer.High, Category: "Database", Title: "sql2"},  // A03 again
		{RuleID: "SEC_TOKEN", Severity: analyzer.Critical, Category: "Security", Title: "secret"},    // A07 / CWE-798
		{RuleID: "PERF_SELECT_STAR", Severity: analyzer.Medium, Category: "Performance", Title: "*"}, // no OWASP
	}
	rep := compliance.Build(issues)

	if len(rep.OWASP) != 10 {
		t.Fatalf("OWASP rows = %d, want 10", len(rep.OWASP))
	}
	statusByCode := map[string]compliance.OWASPRow{}
	for _, r := range rep.OWASP {
		statusByCode[r.Code] = r
	}
	if statusByCode["A03"].Count != 2 || statusByCode["A03"].Status != "Issues found" {
		t.Errorf("A03 = %+v, want count 2 / Issues found", statusByCode["A03"])
	}
	if statusByCode["A07"].Status != "Issues found" {
		t.Errorf("A07 status = %q, want Issues found", statusByCode["A07"].Status)
	}
	if statusByCode["A04"].Status != "Not assessed" {
		t.Errorf("A04 status = %q, want Not assessed", statusByCode["A04"].Status)
	}
	if statusByCode["A10"].Status != "No issues detected" {
		t.Errorf("A10 status = %q, want No issues detected", statusByCode["A10"].Status)
	}

	// Framework mapping: A03 must be "Action needed" with PCI-DSS + ISO set.
	var a03 *compliance.FrameworkRow
	for i := range rep.Frameworks {
		if rep.Frameworks[i].OWASP == "A03" {
			a03 = &rep.Frameworks[i]
		}
	}
	if a03 == nil || a03.Status != "Action needed" || a03.PCIDSS == "" || a03.ISO == "" {
		t.Errorf("A03 framework row wrong: %+v", a03)
	}

	// CWE breakdown: CWE-89 should top the list with count 2.
	if len(rep.CWE) == 0 || rep.CWE[0].ID != "CWE-89" || rep.CWE[0].Count != 2 {
		t.Errorf("top CWE = %+v, want CWE-89 x2", rep.CWE)
	}
}
