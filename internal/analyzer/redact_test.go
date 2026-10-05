package analyzer

import (
	"strings"
	"testing"
)

func TestRedactTextRemovesCommonSecrets(t *testing.T) {
	secret := "OBSERVER_SENTINEL_SECRET_123456789"
	cases := []string{
		"API_KEY=" + secret,
		"password: '" + secret + "'",
		"Authorization: Bearer " + secret,
		"postgres://observer:" + secret + "@localhost/app",
		"ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
		"AKIA1234567890ABCDEF",
	}
	for _, input := range cases {
		got := RedactText(input)
		if strings.Contains(got, secret) || strings.Contains(got, "ghp_") || strings.Contains(got, "AKIA123") {
			t.Fatalf("secret survived redaction: %q", got)
		}
	}
}

func TestSanitizeIssueRedactsSensitiveRuleSnippet(t *testing.T) {
	issue := SanitizeIssue(Issue{
		RuleID: "SEC_TOKEN", CWE: "CWE-798", Snippet: `const token = "OBSERVER_SENTINEL_SECRET_123456789"`,
	})
	if issue.Snippet != "[redacted secret-like content]" {
		t.Fatalf("Snippet = %q", issue.Snippet)
	}
}

func TestResultAddIssuesSanitizesExternalFindings(t *testing.T) {
	result := &Result{BySeverity: map[Severity]int{}, ByCategory: map[string]int{}}
	result.AddIssues(Issue{
		RuleID: "external.secret", Severity: High, Category: "Security", CWE: "CWE-798",
		Snippet: "client_secret=OBSERVER_SENTINEL_SECRET_123456789",
	})
	if strings.Contains(result.Issues[0].Snippet, "OBSERVER_SENTINEL") {
		t.Fatalf("external issue was not sanitized: %q", result.Issues[0].Snippet)
	}
}
