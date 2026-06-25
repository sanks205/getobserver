package tests

import (
	"testing"

	"github.com/aipda/observer/internal/analyzer"
)

// TestBuiltinOWASPClasses verifies the built-in rules catch the major OWASP
// vulnerability classes (no Semgrep required) on the demo's VulnController.
func TestBuiltinOWASPClasses(t *testing.T) {
	res, err := analyzer.Analyze(phpDemoPath(t))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	want := map[string]string{
		"XSS_REFLECTED":            "reflected XSS",
		"SEC_PATH_TRAVERSAL":       "path traversal / LFI",
		"SEC_SSRF":                 "SSRF",
		"SEC_INSECURE_DESERIALIZE": "insecure deserialization",
		"SEC_TLS_VERIFY_DISABLED":  "disabled TLS verification",
	}
	for rule, desc := range want {
		if len(issuesByRule(res.Issues, rule)) == 0 {
			t.Errorf("expected a %s finding (%s)", rule, desc)
		}
	}

	// Each new rule must carry CWE + OWASP metadata.
	for rule := range want {
		if analyzer.CWEFor(rule) == "" || analyzer.OWASPFor(rule) == "" {
			t.Errorf("%s is missing CWE/OWASP mapping", rule)
		}
	}
}
