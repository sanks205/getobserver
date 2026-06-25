package tests

import (
	"path/filepath"
	"testing"

	"github.com/aipda/observer/internal/scanner"
)

// phpDemoPath resolves the bundled PHP demo project relative to this test file.
func phpDemoPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "examples", "php-demo"))
	if err != nil {
		t.Fatalf("resolving demo path: %v", err)
	}
	return p
}

func TestScanPHPDemo(t *testing.T) {
	res, err := scanner.Scan(phpDemoPath(t))
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if res.ProjectName != "php-demo" {
		t.Errorf("ProjectName = %q, want %q", res.ProjectName, "php-demo")
	}
	if res.DominantLang != "PHP" {
		t.Errorf("DominantLang = %q, want PHP", res.DominantLang)
	}
	if res.TotalFiles == 0 {
		t.Error("TotalFiles = 0, expected demo files to be counted")
	}

	// composer.json must be picked up as a marker.
	found := false
	for _, m := range res.Markers {
		if m == "PHP (Composer)" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'PHP (Composer)' marker, got %v", res.Markers)
	}

	// The demo has controllers, a model, a service, and config.
	for _, c := range []scanner.Category{
		scanner.CategoryController, scanner.CategoryModel,
		scanner.CategoryService, scanner.CategoryConfig,
	} {
		if res.Categories[c] == 0 {
			t.Errorf("expected at least one %s, got 0", c)
		}
	}
}

func TestScanMissingDir(t *testing.T) {
	if _, err := scanner.Scan(filepath.Join("does", "not", "exist")); err == nil {
		t.Error("expected error scanning non-existent path, got nil")
	}
}
