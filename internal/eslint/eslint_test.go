package eslint

import "testing"

func TestParse(t *testing.T) {
	data := []byte(`[` +
		`{"filePath":"/proj/src/app.js","messages":[` +
		`{"ruleId":"no-eval","severity":2,"message":"eval can be harmful.","line":12,"column":3},` +
		`{"ruleId":"no-unused-vars","severity":1,"message":"'x' is assigned a value but never used.","line":4,"column":7}` +
		`]},` +
		`{"filePath":"/proj/src/bad.js","messages":[` +
		`{"ruleId":null,"severity":2,"message":"Parsing error: Unexpected token","line":1,"column":1}` +
		`]},` +
		`{"filePath":"/proj/src/clean.js","messages":[]}` +
		`]`)

	findings, err := Parse(data, "/proj")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(findings))
	}

	f0 := findings[0]
	if f0.RuleID != "ESLINT:no-eval" {
		t.Errorf("RuleID = %q, want ESLINT:no-eval", f0.RuleID)
	}
	if f0.Severity != "Medium" {
		t.Errorf("Severity = %q, want Medium (error)", f0.Severity)
	}
	if f0.Category != "Error Handling" {
		t.Errorf("Category = %q, want Error Handling", f0.Category)
	}
	if f0.Line != 12 {
		t.Errorf("Line = %d, want 12", f0.Line)
	}
	if f0.File != "src/app.js" {
		t.Errorf("File = %q, want src/app.js", f0.File)
	}

	// severity 1 (warn) -> Low
	if findings[1].Severity != "Low" {
		t.Errorf("findings[1].Severity = %q, want Low (warn)", findings[1].Severity)
	}

	// null ruleId (fatal parse error) -> ESLINT:parse-error
	if findings[2].RuleID != "ESLINT:parse-error" {
		t.Errorf("findings[2].RuleID = %q, want ESLINT:parse-error", findings[2].RuleID)
	}
}

func TestParseEmpty(t *testing.T) {
	f, err := Parse(nil, "")
	if err != nil || f != nil {
		t.Fatalf("empty input: got %v, %v", f, err)
	}
}
