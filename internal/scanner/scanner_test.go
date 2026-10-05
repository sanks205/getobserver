package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanIgnoresKiloWorktrees(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("<?php echo 'ok';"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app/main.php")
	write(".kilo/worktrees/copy/app/main.php")

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalFiles != 1 {
		t.Fatalf("TotalFiles = %d, want 1", result.TotalFiles)
	}
	if !IsIgnoredDir(".kilo") {
		t.Fatal(".kilo must be part of the shared ignore policy")
	}
}

func TestAddIgnoredDirs(t *testing.T) {
	if err := AddIgnoredDirs([]string{"generated-audit-fixture"}); err != nil {
		t.Fatal(err)
	}
	if !IsIgnoredDir("GENERATED-AUDIT-FIXTURE") {
		t.Fatal("custom exclusion should be case-insensitive")
	}
	if err := AddIgnoredDirs([]string{"nested/path"}); err == nil {
		t.Fatal("expected path-like exclusion to be rejected")
	}
}
