package analyzer

import (
	"path/filepath"
	"testing"
)

func TestCredentialSeverityByScope(t *testing.T) {
	if got := credentialSeverity("tests/Feature/LoginTest.php"); got != Low {
		t.Fatalf("test credential severity = %s, want Low", got)
	}
	if got := credentialSeverity("database/seeders/DemoSeeder.php"); got != Medium {
		t.Fatalf("seeder credential severity = %s, want Medium", got)
	}
	if got := credentialSeverity("app/Services/Auth.php"); got != High {
		t.Fatalf("application credential severity = %s, want High", got)
	}
}

func TestCredentialFrameworkDescriptorsArePlaceholders(t *testing.T) {
	for _, value := range []string{"encrypted", "hashed"} {
		if !isPlaceholder(value) {
			t.Errorf("%q should be treated as a framework descriptor", value)
		}
	}
}

func TestLaravelBootstrapCacheIsGenerated(t *testing.T) {
	root := t.TempDir()
	if !isGeneratedProjectDir(root, filepath.Join(root, "bootstrap", "cache")) {
		t.Fatal("Laravel bootstrap/cache should be excluded as generated output")
	}
	if !isGeneratedProjectDir(root, filepath.Join(root, "storage", "framework", "views")) {
		t.Fatal("Laravel storage/framework should be excluded as generated output")
	}
	if isGeneratedProjectDir(root, filepath.Join(root, "app", "Cache")) {
		t.Fatal("application Cache source directory must remain in scope")
	}
}
func TestDocumentedEmptyCatchIsNotReported(t *testing.T) {
	lines := []string{"try {", "work();", "} catch (error) {", "// Storage can be unavailable in privacy mode.", "}"}
	if got := detectEmptyCatch("view.js", ".js", lines, []bool{true, true, true, true, true}); len(got) != 0 {
		t.Fatalf("documented catch produced %d finding(s), want 0", len(got))
	}

	lines = []string{"try {", "work();", "} catch (error) {", "// TODO", "}"}
	if got := detectEmptyCatch("view.js", ".js", lines, []bool{true, true, true, true, true}); len(got) != 1 {
		t.Fatalf("TODO-only catch produced %d finding(s), want 1", len(got))
	}
}
func TestBuiltInHealthSeparatesExternalEngines(t *testing.T) {
	r := &Result{FilesScanned: 10, BySeverity: map[Severity]int{}, ByCategory: map[string]int{}}
	r.AddIssues(
		Issue{RuleID: "ERR_EMPTY_CATCH", Severity: High, Category: "Error Handling"},
		Issue{RuleID: "PHPSTAN:property.notFound", Severity: Medium, Category: "Error Handling"},
	)
	overall, _ := HealthScore(r)
	builtIn, _ := BuiltInHealthScore(r)
	if builtIn <= overall {
		t.Fatalf("built-in score %d should exceed overall score %d with external findings", builtIn, overall)
	}
	if got := ExternalHealthFindings(r); got != 1 {
		t.Fatalf("external health findings = %d, want 1", got)
	}
}
