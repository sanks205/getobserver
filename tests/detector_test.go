package tests

import (
	"testing"

	"github.com/aipda/observer/internal/detector"
)

func hasFinding(findings []detector.Finding, name string) *detector.Finding {
	for i := range findings {
		if findings[i].Name == name {
			return &findings[i]
		}
	}
	return nil
}

func TestDetectPHPDemo(t *testing.T) {
	ts, err := detector.Detect(phpDemoPath(t))
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	if f := hasFinding(ts.Languages, "PHP"); f == nil {
		t.Errorf("expected PHP language, got %+v", ts.Languages)
	}

	// composer.json requires codeigniter/framework 3.1.11.
	ci := hasFinding(ts.Frameworks, "CodeIgniter 3")
	if ci == nil {
		t.Fatalf("expected CodeIgniter 3 framework, got %+v", ts.Frameworks)
	}
	if ci.Version != "3.1.11" {
		t.Errorf("CodeIgniter version = %q, want 3.1.11", ci.Version)
	}
	if ci.Confidence != detector.High {
		t.Errorf("CodeIgniter confidence = %q, want High", ci.Confidence)
	}

	// database.php declares the mysqli driver.
	if f := hasFinding(ts.Databases, "MySQL"); f == nil {
		t.Errorf("expected MySQL database, got %+v", ts.Databases)
	}
}

func TestDetectMissingDir(t *testing.T) {
	if _, err := detector.Detect("does-not-exist-xyz"); err == nil {
		t.Error("expected error detecting non-existent path, got nil")
	}
}
