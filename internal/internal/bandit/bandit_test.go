package bandit

import "testing"

func TestParse(t *testing.T) {
	data := []byte(`{"results":[` +
		`{"filename":"app/views.py","issue_severity":"HIGH","issue_confidence":"HIGH","issue_text":"subprocess call with shell=True identified.","test_id":"B602","line_number":42,"code":"41 import subprocess\n42 subprocess.call(cmd, shell=True)\n","issue_cwe":{"id":78,"link":"https://cwe.mitre.org/data/definitions/78.html"}},` +
		`{"filename":"app/db.py","issue_severity":"MEDIUM","issue_confidence":"MEDIUM","issue_text":"Possible SQL injection vector through string-based query construction.","test_id":"B608","line_number":15,"code":"15 q = \"SELECT * FROM t WHERE id=\" + uid\n","issue_cwe":{"id":89}}` +
		`],"metrics":{}}`)

	findings, err := Parse(data, "")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "BANDIT:B602" {
		t.Errorf("RuleID = %q, want BANDIT:B602", f0.RuleID)
	}
	if f0.Severity != "High" {
		t.Errorf("Severity = %q, want High", f0.Severity)
	}
	if f0.Category != "Security" {
		t.Errorf("Category = %q, want Security", f0.Category)
	}
	if f0.CWE != "CWE-78" {
		t.Errorf("CWE = %q, want CWE-78", f0.CWE)
	}
	if f0.Line != 42 {
		t.Errorf("Line = %d, want 42", f0.Line)
	}
	if f0.File != "app/views.py" {
		t.Errorf("File = %q, want app/views.py", f0.File)
	}
	if f0.Snippet != "subprocess.call(cmd, shell=True)" {
		t.Errorf("Snippet = %q", f0.Snippet)
	}
	if findings[1].CWE != "CWE-89" {
		t.Errorf("findings[1].CWE = %q, want CWE-89", findings[1].CWE)
	}
}

func TestParseEmpty(t *testing.T) {
	f, err := Parse(nil, "")
	if err != nil || f != nil {
		t.Fatalf("empty input: got %v, %v", f, err)
	}
}
