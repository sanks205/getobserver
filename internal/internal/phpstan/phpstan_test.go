package phpstan

import "testing"

func TestParse(t *testing.T) {
	data := []byte(`{"totals":{"errors":0,"file_errors":2},"files":{"app/Model.php":{"errors":2,"messages":[` +
		`{"message":"Variable $x might not be defined.","line":10,"identifier":"variable.undefined"},` +
		`{"message":"Call to an undefined method Foo::bar().","line":20,"identifier":"method.notFound"}` +
		`]}},"errors":[]}`)

	findings, err := Parse(data, "")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	v, ok := byID["PHPSTAN:variable.undefined"]
	if !ok {
		t.Fatalf("missing variable.undefined finding; got %+v", findings)
	}
	if v.Line != 10 {
		t.Errorf("line = %d, want 10", v.Line)
	}
	if v.Severity != "Medium" {
		t.Errorf("severity = %q, want Medium", v.Severity)
	}
	if v.Category != "Error Handling" {
		t.Errorf("category = %q, want Error Handling", v.Category)
	}
	if v.File != "app/Model.php" {
		t.Errorf("file = %q, want app/Model.php", v.File)
	}
}

func TestParseEmpty(t *testing.T) {
	f, err := Parse(nil, "")
	if err != nil || f != nil {
		t.Fatalf("empty input: got %v, %v", f, err)
	}
}
