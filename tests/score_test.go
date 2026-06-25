package tests

import (
	"testing"

	"github.com/aipda/observer/internal/analyzer"
)

// scoreResult builds a Result with a given file count and issues.
func scoreResult(files int, issues ...analyzer.Issue) *analyzer.Result {
	r := &analyzer.Result{BySeverity: map[analyzer.Severity]int{}, ByCategory: map[string]int{}, FilesScanned: files}
	r.AddIssues(issues...)
	return r
}

func iss(sev analyzer.Severity) analyzer.Issue {
	return analyzer.Issue{Severity: sev, RuleID: "x", Title: "t", Category: "Security"}
}

func TestScoreProperties(t *testing.T) {
	// Clean project -> perfect score.
	if s, g := analyzer.Score(scoreResult(100)); s != 100 || g != "A" {
		t.Errorf("clean = %d (%s), want 100 (A)", s, g)
	}

	// Density-based: the SAME few findings hurt a tiny project more than a huge one.
	small, _ := analyzer.Score(scoreResult(5, iss(analyzer.High), iss(analyzer.High)))
	large, _ := analyzer.Score(scoreResult(2000, iss(analyzer.High), iss(analyzer.High)))
	if !(large > small) {
		t.Errorf("expected large project (%d) to score higher than small (%d) for same findings", large, small)
	}

	// More findings (same size) -> lower score.
	few, _ := analyzer.Score(scoreResult(100, iss(analyzer.High)))
	many := []analyzer.Issue{}
	for i := 0; i < 50; i++ {
		many = append(many, iss(analyzer.High))
	}
	manyScore, _ := analyzer.Score(scoreResult(100, many...))
	if !(manyScore < few) {
		t.Errorf("expected more findings to score lower: many=%d few=%d", manyScore, few)
	}

	// Any Critical caps the grade at C or worse (never A/B).
	s, g := analyzer.Score(scoreResult(100000, iss(analyzer.Critical)))
	if s > 79 || g == "A" || g == "B" {
		t.Errorf("one Critical in a huge project = %d (%s); must cap at C or worse", s, g)
	}

	// Score never floors uninformatively at 0 — always >= 1.
	huge := []analyzer.Issue{}
	for i := 0; i < 6000; i++ {
		huge = append(huge, iss(analyzer.Medium))
	}
	hs, _ := analyzer.Score(scoreResult(1449, huge...))
	if hs < 1 {
		t.Errorf("score should never be < 1, got %d", hs)
	}
}

func TestSecurityVsHealthSplit(t *testing.T) {
	secIssue := analyzer.Issue{Severity: analyzer.High, RuleID: "DB_RAW_SQL_CONCAT", Title: "sql", Category: "Database"}
	perfIssue := analyzer.Issue{Severity: analyzer.High, RuleID: "PERF_SELECT_STAR", Title: "perf", Category: "Performance"}

	// Only a security finding: Security score drops, Health stays perfect.
	r := scoreResult(100, secIssue)
	sec, _ := analyzer.SecurityScore(r)
	hlt, hgrade := analyzer.HealthScore(r)
	if sec >= 100 {
		t.Errorf("security finding should lower Security score, got %d", sec)
	}
	if hlt != 100 || hgrade != "A" {
		t.Errorf("no health findings -> Health should be 100/A, got %d/%s", hlt, hgrade)
	}

	// Only a performance finding: Health drops, Security stays perfect.
	r2 := scoreResult(100, perfIssue)
	sec2, sgrade2 := analyzer.SecurityScore(r2)
	hlt2, _ := analyzer.HealthScore(r2)
	if sec2 != 100 || sgrade2 != "A" {
		t.Errorf("no security findings -> Security should be 100/A, got %d/%s", sec2, sgrade2)
	}
	if hlt2 >= 100 {
		t.Errorf("performance finding should lower Health score, got %d", hlt2)
	}
}

func TestCWEandOWASPMapping(t *testing.T) {
	if got := analyzer.CWEFor("DB_RAW_SQL_CONCAT"); got != "CWE-89" {
		t.Errorf("SQL injection CWE = %q, want CWE-89", got)
	}
	if got := analyzer.OWASPFor("DB_RAW_SQL_CONCAT"); got == "" {
		t.Error("SQL injection should map to an OWASP category")
	}
	if got := analyzer.CWEFor("SEC_TOKEN"); got != "CWE-798" {
		t.Errorf("hardcoded secret CWE = %q, want CWE-798", got)
	}
	if got := analyzer.CWEFor("PERF_SELECT_STAR"); got != "" {
		t.Errorf("perf rule should have no CWE, got %q", got)
	}
}
