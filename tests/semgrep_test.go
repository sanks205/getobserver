package tests

import (
	"testing"

	"github.com/aipda/observer/internal/semgrep"
)

// A realistic slice of `semgrep --json` output, including both CWE-as-array and
// CWE-as-string metadata shapes.
const semgrepJSON = `{
  "results": [
    {
      "check_id": "php.lang.security.xss.echoed-request",
      "path": "src/views/profile.php",
      "start": {"line": 42, "col": 5},
      "extra": {
        "message": "Reflected XSS: request value echoed without escaping.",
        "severity": "ERROR",
        "lines": "echo $_GET['name'];",
        "metadata": {"cwe": ["CWE-79: Cross-site Scripting (XSS)"], "owasp": ["A03:2021 - Injection"], "category": "security"}
      }
    },
    {
      "check_id": "generic.perf.inefficient-loop",
      "path": "src/lib/util.php",
      "start": {"line": 10, "col": 1},
      "extra": {
        "message": "Inefficient loop.",
        "severity": "WARNING",
        "lines": "for (...) {}",
        "metadata": {"cwe": "CWE-1050", "category": "performance"}
      }
    }
  ]
}`

func TestSemgrepParse(t *testing.T) {
	findings, err := semgrep.Parse([]byte(semgrepJSON))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	xss := findings[0]
	if xss.Severity != "High" {
		t.Errorf("ERROR severity = %q, want High", xss.Severity)
	}
	if xss.Category != "Security" {
		t.Errorf("category = %q, want Security", xss.Category)
	}
	if xss.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79 (trimmed)", xss.CWE)
	}
	if xss.OWASP == "" {
		t.Error("expected OWASP to be carried through")
	}
	if xss.File != "src/views/profile.php" || xss.Line != 42 {
		t.Errorf("location wrong: %s:%d", xss.File, xss.Line)
	}

	perf := findings[1]
	if perf.Severity != "Medium" || perf.Category != "Performance" {
		t.Errorf("perf finding mismapped: %+v", perf)
	}
	if perf.CWE != "CWE-1050" { // string form, no colon
		t.Errorf("string CWE = %q, want CWE-1050", perf.CWE)
	}
}

func TestSemgrepParseEmpty(t *testing.T) {
	if f, err := semgrep.Parse(nil); err != nil || f != nil {
		t.Errorf("empty input should yield (nil, nil), got %v / %v", f, err)
	}
}
