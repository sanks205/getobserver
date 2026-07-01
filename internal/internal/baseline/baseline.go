// Package baseline implements finding suppression (Phase 13).
//
// A baseline records fingerprints of findings a team has accepted. On later
// runs, baselined findings are suppressed so only NEW issues surface — the
// standard way to adopt a scanner on an existing codebase without drowning in
// pre-existing noise. Fingerprints exclude line numbers so they survive code
// shifting up/down.
package baseline

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aipda/observer/internal/analyzer"
)

type file struct {
	CreatedAt    string   `json:"created_at"`
	Fingerprints []string `json:"fingerprints"`
}

// Fingerprint returns a stable identifier for an issue: rule + file + the
// offending content (snippet, or title when there is no snippet, e.g. CVEs).
// Line numbers are intentionally excluded so edits elsewhere don't churn it.
func Fingerprint(is analyzer.Issue) string {
	key := is.Snippet
	if key == "" {
		key = is.Title
	}
	sum := sha1.Sum([]byte(is.RuleID + "|" + is.File + "|" + key))
	return fmt.Sprintf("%x", sum)
}

// Write saves the fingerprints of the given issues to path.
func Write(path string, issues []analyzer.Issue) (int, error) {
	seen := map[string]bool{}
	out := file{Fingerprints: []string{}, CreatedAt: time.Now().Format(time.RFC3339)}
	for _, is := range issues {
		fp := Fingerprint(is)
		if !seen[fp] {
			seen[fp] = true
			out.Fingerprints = append(out.Fingerprints, fp)
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 0, err
	}
	return len(out.Fingerprints), os.WriteFile(path, b, 0o644)
}

// Load reads a baseline file into a fingerprint set.
func Load(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(f.Fingerprints))
	for _, fp := range f.Fingerprints {
		set[fp] = true
	}
	return set, nil
}

// Apply returns a result with baselined (already-known) issues removed, leaving
// only findings not present in the baseline.
func Apply(r *analyzer.Result, set map[string]bool) *analyzer.Result {
	return r.Keep(func(is analyzer.Issue) bool { return !set[Fingerprint(is)] })
}
