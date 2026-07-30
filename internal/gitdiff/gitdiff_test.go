package gitdiff

import "testing"

func TestParseUnifiedDiff(t *testing.T) {
	// A modified file (added lines 11-12, one changed line at 22) and a brand-new file.
	diff := "diff --git a/foo.php b/foo.php\n" +
		"index 111..222 100644\n" +
		"--- a/foo.php\n" +
		"+++ b/foo.php\n" +
		"@@ -10,0 +11,2 @@\n" +
		"+echo $x;\n" +
		"+echo $y;\n" +
		"@@ -20 +22 @@\n" +
		"-old();\n" +
		"+new();\n" +
		"diff --git a/new.js b/new.js\n" +
		"new file mode 100644\n" +
		"--- /dev/null\n" +
		"+++ b/new.js\n" +
		"@@ -0,0 +1,3 @@\n" +
		"+a\n+b\n+c\n"

	c := &Changes{files: map[string]*lineSet{}}
	parseUnifiedDiff(diff, c)

	changed := []struct {
		file string
		line int
	}{
		{"foo.php", 11}, {"foo.php", 12}, {"foo.php", 22},
		{"new.js", 1}, {"new.js", 2}, {"new.js", 3},
		{"foo.php", 0}, // file-level finding in a changed file
	}
	for _, tc := range changed {
		if !c.Contains(tc.file, tc.line) {
			t.Errorf("expected %s:%d to be reported as changed", tc.file, tc.line)
		}
	}

	unchanged := []struct {
		file string
		line int
	}{
		{"foo.php", 15}, {"foo.php", 100}, {"new.js", 4}, {"other.php", 1},
	}
	for _, tc := range unchanged {
		if c.Contains(tc.file, tc.line) {
			t.Errorf("did not expect %s:%d to be reported as changed", tc.file, tc.line)
		}
	}

	if c.FileCount() != 2 {
		t.Errorf("expected 2 changed files, got %d", c.FileCount())
	}
}

func TestParseHandlesDeletedFile(t *testing.T) {
	// A deleted file: the new side is /dev/null, so nothing should be recorded for it.
	diff := "diff --git a/gone.php b/gone.php\n" +
		"deleted file mode 100644\n" +
		"--- a/gone.php\n" +
		"+++ /dev/null\n" +
		"@@ -1,3 +0,0 @@\n" +
		"-a\n-b\n-c\n"
	c := &Changes{files: map[string]*lineSet{}}
	parseUnifiedDiff(diff, c)
	if c.Contains("gone.php", 1) {
		t.Errorf("deleted file lines should not be reported as changed")
	}
}
