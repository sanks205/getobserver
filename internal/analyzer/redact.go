package analyzer

import (
	"regexp"
	"strings"
)

const redactedValue = "[REDACTED]"

var sensitiveRuleTerms = []string{
	"SECRET", "TOKEN", "CREDENTIAL", "PASSWORD", "PRIVATE_KEY", "API_KEY",
}

var sensitiveTextPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|pwd|db_password|database_url)\b(\s*[:=]\s*)["']?[^\s"';,}\]]+["']?`), `$1$2[REDACTED]`},
	{regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`), `Bearer [REDACTED]`},
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`), redactedValue},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), redactedValue},
	{regexp.MustCompile(`(?i)\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b`), redactedValue},
	{regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:)[^\s/@]+@`), `$1[REDACTED]@`},
	{regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`), `[REDACTED PRIVATE KEY]`},
}

// RedactText removes common credential values while preserving enough context
// to explain why a finding was raised. It is deliberately deterministic so
// reports, baselines, and tests remain stable.
func RedactText(value string) string {
	out := value
	for _, pattern := range sensitiveTextPatterns {
		out = pattern.re.ReplaceAllString(out, pattern.replacement)
	}
	return out
}

// SanitizeIssue returns an issue safe for console, stored reports, and exports.
// Secret-specific rules hide the whole snippet because partial masking can still
// expose usable credentials or private material.
func SanitizeIssue(issue Issue) Issue {
	issue.Title = RedactText(issue.Title)
	issue.Explanation = RedactText(issue.Explanation)
	issue.Recommendation = RedactText(issue.Recommendation)

	upperRule := strings.ToUpper(issue.RuleID)
	sensitive := issue.CWE == "CWE-798" || issue.CWE == "CWE-321"
	for _, term := range sensitiveRuleTerms {
		if strings.Contains(upperRule, term) {
			sensitive = true
			break
		}
	}
	if sensitive && strings.TrimSpace(issue.Snippet) != "" {
		issue.Snippet = "[redacted secret-like content]"
	} else {
		issue.Snippet = RedactText(issue.Snippet)
	}
	return issue
}
