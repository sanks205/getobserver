// Package deps scans a project's declared dependencies for known
// vulnerabilities (Phase 12) using the free OSV.dev database.
//
// It adds no software requirement for the user: it parses dependency manifests
// the project already has and queries OSV over the network only when asked
// (opt-in). With no network it fails gracefully, preserving the offline,
// single-binary promise.
package deps

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aipda/observer/internal/scanner"
)

// Dep is one declared dependency.
type Dep struct {
	Ecosystem string // OSV ecosystem: Packagist | npm | PyPI | Go
	Name      string
	Version   string
	Source    string // manifest filename it came from
}

// manifest filenames we know how to parse.
var manifestNames = map[string]bool{
	"composer.lock":     true,
	"package-lock.json": true,
	"requirements.txt":  true,
	"go.mod":            true,
}

// Parse collects dependencies from supported manifests under root (first
// occurrence of each manifest type wins). Unsupported/unreadable files are
// skipped.
func Parse(root string) ([]Dep, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	found := map[string]string{} // basename -> path
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if p != abs && scanner.IsIgnoredDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if manifestNames[d.Name()] {
			if _, seen := found[d.Name()]; !seen {
				found[d.Name()] = p
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var deps []Dep
	if p, ok := found["composer.lock"]; ok {
		deps = append(deps, parseComposerLock(p)...)
	}
	if p, ok := found["package-lock.json"]; ok {
		deps = append(deps, parsePackageLock(p)...)
	}
	if p, ok := found["requirements.txt"]; ok {
		deps = append(deps, parseRequirements(p)...)
	}
	if p, ok := found["go.mod"]; ok {
		deps = append(deps, parseGoMod(p)...)
	}
	return deps, nil
}

func parseComposerLock(path string) []Dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var deps []Dep
	add := func(pkgs []struct{ Name, Version string }) {
		for _, p := range pkgs {
			if p.Name == "" {
				continue
			}
			deps = append(deps, Dep{Ecosystem: "Packagist", Name: p.Name, Version: cleanVersion(p.Version), Source: "composer.lock"})
		}
	}
	add(doc.Packages)
	add(doc.PackagesDev)
	return deps
}

func parsePackageLock(path string) []Dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages     map[string]struct{ Version string } `json:"packages"`     // lockfile v2/v3
		Dependencies map[string]struct{ Version string } `json:"dependencies"` // v1
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	seen := map[string]bool{}
	var deps []Dep
	for key, v := range doc.Packages {
		if key == "" || v.Version == "" {
			continue // "" is the root project
		}
		name := key
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			name = key[i+len("node_modules/"):]
		}
		if name == "" || seen[name+v.Version] {
			continue
		}
		seen[name+v.Version] = true
		deps = append(deps, Dep{Ecosystem: "npm", Name: name, Version: cleanVersion(v.Version), Source: "package-lock.json"})
	}
	for name, v := range doc.Dependencies {
		if name == "" || v.Version == "" || seen[name+v.Version] {
			continue
		}
		seen[name+v.Version] = true
		deps = append(deps, Dep{Ecosystem: "npm", Name: name, Version: cleanVersion(v.Version), Source: "package-lock.json"})
	}
	return deps
}

func parseRequirements(path string) []Dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var deps []Dep
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Only pinned versions (pkg==1.2.3) can be checked reliably.
		if i := strings.Index(line, "=="); i > 0 {
			name := strings.TrimSpace(line[:i])
			ver := strings.TrimSpace(line[i+2:])
			if j := strings.IndexAny(ver, " ;#"); j >= 0 {
				ver = ver[:j]
			}
			if name != "" && ver != "" {
				deps = append(deps, Dep{Ecosystem: "PyPI", Name: name, Version: ver, Source: "requirements.txt"})
			}
		}
	}
	return deps
}

func parseGoMod(path string) []Dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var deps []Dep
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "require ("):
			inBlock = true
			continue
		case inBlock && t == ")":
			inBlock = false
			continue
		case strings.HasPrefix(t, "require "):
			t = strings.TrimPrefix(t, "require ")
		case !inBlock:
			continue
		}
		// t is like "module/path v1.2.3 // indirect"
		fields := strings.Fields(t)
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "v") {
			deps = append(deps, Dep{Ecosystem: "Go", Name: fields[0], Version: cleanVersion(fields[1]), Source: "go.mod"})
		}
	}
	return deps
}

// cleanVersion strips a leading "v" and surrounding whitespace.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	return strings.TrimPrefix(v, "v")
}
