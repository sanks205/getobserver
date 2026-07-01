package gosec

import "testing"

func TestParse(t *testing.T) {
	data := []byte(`{"Issues":[` +
		`{"severity":"HIGH","confidence":"HIGH","cwe":{"id":"78","url":"https://cwe.mitre.org/data/definitions/78.html"},"rule_id":"G204","details":"Subprocess launched with a potential tainted input or cmd arguments","file":"/proj/cmd/main.go","code":"12: cmd := exec.Command(userInput)","line":"12","column":"2"},` +
		`{"severity":"MEDIUM","confidence":"HIGH","cwe":{"id":"327"},"rule_id":"G401","details":"Use of weak cryptographic primitive","file":"/proj/hash.go","code":"7: h := md5.New()","line":"7-9","column":"1"}` +
		`],"Stats":{},"GolangErrors":{}}`)

	findings, err := Parse(data, "/proj")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "GOSEC:G204" {
		t.Errorf("RuleID = %q, want GOSEC:G204", f0.RuleID)
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
	if f0.Line != 12 {
		t.Errorf("Line = %d, want 12", f0.Line)
	}
	if f0.File != "cmd/main.go" {
		t.Errorf("File = %q, want cmd/main.go", f0.File)
	}

	// line range "7-9" should parse to 7
	if findings[1].Line != 7 {
		t.Errorf("findings[1].Line = %d, want 7", findings[1].Line)
	}
	if findings[1].CWE != "CWE-327" {
		t.Errorf("findings[1].CWE = %q, want CWE-327", findings[1].CWE)
	}
}

func TestParseEmpty(t *testing.T) {
	f, err := Parse(nil, "")
	if err != nil || f != nil {
		t.Fatalf("empty input: got %v, %v", f, err)
	}
}
