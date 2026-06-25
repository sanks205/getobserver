package tests

import (
	"testing"

	"github.com/aipda/observer/internal/analyzer"
)

func issuesByRule(issues []analyzer.Issue, ruleID string) []analyzer.Issue {
	var out []analyzer.Issue
	for _, is := range issues {
		if is.RuleID == ruleID {
			out = append(out, is)
		}
	}
	return out
}

func TestAnalyzePHPDemo(t *testing.T) {
	res, err := analyzer.Analyze(phpDemoPath(t))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if res.FilesScanned == 0 {
		t.Fatal("no files scanned")
	}

	// Each intentional issue category must be detected at least once.
	mustHave := map[string]string{
		"SEC_TOKEN":                "Stripe live secret key",
		"SEC_HARDCODED_CREDENTIAL": "hardcoded password",
		"DB_RAW_SQL_CONCAT":        "SQL string concatenation",
		"ERR_EMPTY_CATCH":          "empty catch block",
		"CFG_DISPLAY_ERRORS":       "display_errors enabled",
		"PHP_SUPERGLOBAL_INPUT":    "unvalidated input",
	}
	for rule, desc := range mustHave {
		if len(issuesByRule(res.Issues, rule)) == 0 {
			t.Errorf("expected at least one %s (%s) finding", rule, desc)
		}
	}

	// The Stripe key must be Critical.
	for _, is := range issuesByRule(res.Issues, "SEC_TOKEN") {
		if is.Severity != analyzer.Critical {
			t.Errorf("SEC_TOKEN severity = %q, want Critical", is.Severity)
		}
	}

	// Every issue must be fully populated (the report depends on this).
	for _, is := range res.Issues {
		if is.File == "" || is.Line == 0 || is.Title == "" || is.Recommendation == "" {
			t.Errorf("incomplete issue: %+v", is)
		}
	}
}

func TestAnalyzeMissingDir(t *testing.T) {
	if _, err := analyzer.Analyze("nope-not-here"); err == nil {
		t.Error("expected error for non-existent path")
	}
}
