package detector

import (
	"path/filepath"
	"regexp"
	"strings"
)

// versionRe matches a dotted version number like 3.1.11 or 4.4.
var versionRe = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`)

// extractVersionNear finds the first dotted version number appearing shortly
// after the given keyword (e.g. CI_VERSION). Returns "" if none is found.
func extractVersionNear(body, keyword string) string {
	idx := strings.Index(body, keyword)
	if idx < 0 {
		return ""
	}
	window := body[idx:]
	if len(window) > 80 {
		window = window[:80]
	}
	return versionRe.FindString(window)
}

// add* helpers append a finding unless one with the same Name already exists.
// The first (typically highest-confidence) finding wins, keeping output stable
// and free of duplicates when multiple signals point to the same technology.

func (ts *TechStack) addLanguage(f Finding)  { ts.Languages = appendUnique(ts.Languages, f) }
func (ts *TechStack) addFramework(f Finding) { ts.Frameworks = appendUnique(ts.Frameworks, f) }
func (ts *TechStack) addDatabase(f Finding)  { ts.Databases = appendUnique(ts.Databases, f) }
func (ts *TechStack) addInfra(f Finding)     { ts.Infrastructure = appendUnique(ts.Infrastructure, f) }

func (ts *TechStack) hasFramework(name string) bool {
	for _, f := range ts.Frameworks {
		if f.Name == name {
			return true
		}
	}
	return false
}

func appendUnique(list []Finding, f Finding) []Finding {
	for i, existing := range list {
		if existing.Name == f.Name {
			// Merge evidence so we don't lose corroborating signals.
			list[i].Evidence = append(list[i].Evidence, f.Evidence...)
			if list[i].Version == "" && f.Version != "" {
				list[i].Version = f.Version
			}
			return list
		}
	}
	return append(list, f)
}

// merge combines two dependency maps; the first takes precedence on conflict.
func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range b {
		out[k] = v
	}
	for k, v := range a {
		out[k] = v
	}
	return out
}

// readIf returns the capped contents of a manifest if present, else "".
func readIf(c *collected, basename string) string {
	if body, ok := c.read(basename); ok {
		return body
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// cleanVersion trims common version-constraint prefixes for display.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=< ")
	return v
}

func baseName(p string) string { return filepath.Base(p) }
