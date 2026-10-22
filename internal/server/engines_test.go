package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aipda/observer/internal/bandit"
	"github.com/aipda/observer/internal/detector"
	"github.com/aipda/observer/internal/eslint"
	"github.com/aipda/observer/internal/gosec"
	"github.com/aipda/observer/internal/semgrep"
)

// writeFakePhpstan drops a vendored phpstan binary (and the Windows .bat shim)
// into root so the engine is "installed" for the purposes of the suggestion
// helper. Whether a phpstan.neon config exists is left to the caller.
func writeFakePhpstan(t *testing.T, root string) {
	t.Helper()
	binDir := filepath.Join(root, "vendor", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "phpstan"), []byte("@echo off\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(filepath.Join(binDir, "phpstan.bat"), []byte("@echo off\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecommendedEngines_PHPStanAutoConfig(t *testing.T) {
	root := t.TempDir()
	// Binary present but NO config => Observer offers to create phpstan.neon.
	writeFakePhpstan(t, root)

	tech := &detector.TechStack{Frameworks: []detector.Finding{{Name: "Laravel"}}}
	out := recommendedEngines(root, tech)

	var php *EngineSuggestion
	for i := range out {
		if strings.Contains(out[i].Name, "PHPStan") {
			php = &out[i]
		}
	}
	if php == nil {
		t.Fatalf("expected a PHPStan suggestion for a Laravel project, got %+v", out)
	}
	if !php.AutoConfig {
		t.Errorf("expected AutoConfig=true when phpstan binary is present but no config; suggestion=%+v", php)
	}
}

func TestRecommendedEngines_PHPStanConfigPresentNoSuggestion(t *testing.T) {
	root := t.TempDir()
	// Binary present AND config present => Already available, nothing to suggest.
	writeFakePhpstan(t, root)
	if err := os.WriteFile(filepath.Join(root, "phpstan.neon"), []byte("parameters:\n    level: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tech := &detector.TechStack{Frameworks: []detector.Finding{{Name: "Laravel"}}}
	out := recommendedEngines(root, tech)
	for i := range out {
		if strings.Contains(out[i].Name, "PHPStan") {
			t.Fatalf("did not expect a PHPStan suggestion when config already exists, got %+v", out)
		}
	}
}

func TestRecommendedEngines_StackMapping(t *testing.T) {
	root := t.TempDir()
	tech := &detector.TechStack{
		Languages: []detector.Finding{
			{Name: "Python"}, {Name: "Go"}, {Name: "JavaScript"}, {Name: "TypeScript"},
		},
		Frameworks: []detector.Finding{{Name: "Laravel"}},
	}
	out := recommendedEngines(root, tech)

	byName := map[string]bool{}
	for _, s := range out {
		byName[s.Name] = true
	}

	// PHPStan only shows when not already available; covered deterministically above.
	// The remaining engines self-report availability, so skip when installed.
	if !bandit.Available() && !byName["Bandit"] {
		t.Errorf("expected Bandit suggestion for a Python stack")
	}
	if !gosec.Available() && !byName["gosec"] {
		t.Errorf("expected gosec suggestion for a Go stack")
	}
	if !eslint.Available(root) && !byName["ESLint"] {
		t.Errorf("expected ESLint suggestion for a JS/TS stack")
	}
	if !semgrep.Available() && !byName["Semgrep"] {
		t.Errorf("expected Semgrep suggestion (relevant for any project)")
	}
}

func TestRecommendedEngines_EmptyStack(t *testing.T) {
	root := t.TempDir()
	out := recommendedEngines(root, nil)
	// Nil tech must not panic; Semgrep is still relevant for any project when absent.
	if !semgrep.Available() {
		if _, ok := outContains(out, "Semgrep"); !ok {
			t.Errorf("expected Semgrep suggestion even for an empty/nil stack")
		}
	}
}

func outContains(list []EngineSuggestion, name string) (EngineSuggestion, bool) {
	for _, s := range list {
		if strings.Contains(s.Name, name) {
			return s, true
		}
	}
	return EngineSuggestion{}, false
}
