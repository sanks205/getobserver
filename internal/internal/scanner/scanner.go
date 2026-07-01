// Package scanner performs the Phase 1 static project scan: it walks a project
// directory, counts and categorizes files, and surfaces basic technology
// signals (marker files and dominant language).
//
// Deep technology detection (framework/database/infrastructure) is the
// responsibility of the detector package and is implemented in Phase 2. The
// scanner only collects raw signals so later phases can build on them.
package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ignoredDirs are directories that should never be walked. They contain
// vendored or generated code that would skew file counts and slow scanning.
var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".idea":        true,
	".vscode":      true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"target":       true, // Java/Rust build output
	"bin":          true,
	"obj":          true,
}

// IsIgnoredDir reports whether a directory of the given name should be skipped
// during traversal (vendored/generated code). Exported so other modules (e.g.
// the detector) walk the project consistently with the scanner.
func IsIgnoredDir(name string) bool { return ignoredDirs[name] }

// markerFiles map a well-known dependency manifest to a human label. Their mere
// presence is a strong technology signal that the Phase 2 detector will expand.
var markerFiles = map[string]string{
	"composer.json":      "PHP (Composer)",
	"package.json":       "Node.js (npm)",
	"requirements.txt":   "Python (pip)",
	"pyproject.toml":     "Python (PEP 518)",
	"pom.xml":            "Java (Maven)",
	"build.gradle":       "Java (Gradle)",
	"go.mod":             "Go (modules)",
	"Gemfile":            "Ruby (Bundler)",
	"Dockerfile":         "Docker",
	"docker-compose.yml": "Docker Compose",
}

// backendMarkerLang maps a backend manifest filename to the language it
// implies. Front-end asset files (JS/CSS) frequently outnumber backend source
// files, so the presence of one of these manifests is a stronger signal of the
// project's primary language than raw file counts.
var backendMarkerLang = map[string]string{
	"composer.json":    "PHP",
	"requirements.txt": "Python",
	"pyproject.toml":   "Python",
	"pom.xml":          "Java",
	"build.gradle":     "Java",
	"go.mod":           "Go",
	"Gemfile":          "Ruby",
}

// extLanguage maps source extensions to a language name for dominant-language
// inference. Kept intentionally small; Phase 2 refines this.
var extLanguage = map[string]string{
	".php":  "PHP",
	".js":   "JavaScript",
	".ts":   "TypeScript",
	".jsx":  "JavaScript",
	".tsx":  "TypeScript",
	".py":   "Python",
	".java": "Java",
	".go":   "Go",
	".rb":   "Ruby",
	".cs":   "C#",
}

// Category groups files by their architectural role, inferred from path
// segments. This produces the "Controllers: 50, Models: 30" style counts.
type Category string

const (
	CategoryController Category = "Controllers"
	CategoryModel      Category = "Models"
	CategoryService    Category = "Services"
	CategoryView       Category = "Views"
	CategoryTest       Category = "Tests"
	CategoryConfig     Category = "Config"
	CategoryMigration  Category = "Migrations"
)

// Result is the outcome of a project scan. It is consumed by the reporter and,
// in later phases, by the analyzer and AI modules.
type Result struct {
	ProjectName  string
	RootPath     string
	TotalFiles   int
	TotalDirs    int
	Categories   map[Category]int
	FilesByExt   map[string]int
	Markers      []string // human labels for detected manifest/marker files
	DominantLang string
}

// Scan walks the project rooted at path and returns an aggregated Result.
// It never follows ignored directories and tolerates unreadable entries.
func Scan(path string) (*Result, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, err
	}

	res := &Result{
		ProjectName: filepath.Base(abs),
		RootPath:    abs,
		Categories:  map[Category]int{},
		FilesByExt:  map[string]int{},
	}
	seenMarkers := map[string]bool{}
	backendLangs := map[string]bool{} // languages implied by backend manifests

	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip entries we cannot read rather than aborting the whole scan.
			return nil //nolint:nilerr
		}
		name := d.Name()

		if d.IsDir() {
			if p != abs && ignoredDirs[name] {
				return fs.SkipDir
			}
			if p != abs {
				res.TotalDirs++
			}
			return nil
		}

		res.TotalFiles++

		// Marker / manifest detection.
		if label, ok := markerFiles[name]; ok && !seenMarkers[label] {
			seenMarkers[label] = true
			res.Markers = append(res.Markers, label)
		}
		if lang, ok := backendMarkerLang[name]; ok {
			backendLangs[lang] = true
		}

		// Extension tally.
		ext := strings.ToLower(filepath.Ext(name))
		if ext != "" {
			res.FilesByExt[ext]++
		}

		// Architectural category by path segment.
		if cat, ok := categorize(p); ok {
			res.Categories[cat]++
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	res.DominantLang = dominantLanguage(res.FilesByExt, backendLangs)
	sort.Strings(res.Markers)
	return res, nil
}

// categorize infers an architectural role from the file's path. A role encoded
// in the file *name* (e.g. PaymentService.php) is a stronger signal than the
// containing directory, so filename checks run first; directory conventions
// (app/Models, application/controllers, src/services) are the fallback.
func categorize(p string) (Category, bool) {
	lower := strings.ToLower(filepath.ToSlash(p))
	base := strings.ToLower(filepath.Base(p))

	// 1. Filename-encoded role (highest confidence).
	switch {
	case strings.Contains(base, "test"):
		return CategoryTest, true
	case strings.Contains(base, "controller"):
		return CategoryController, true
	case strings.Contains(base, "service"):
		return CategoryService, true
	case strings.Contains(base, "model"):
		return CategoryModel, true
	case strings.Contains(base, "migration"):
		return CategoryMigration, true
	}

	// 2. Directory convention (fallback).
	switch {
	case strings.Contains(lower, "/tests/") || strings.Contains(lower, "/test/"):
		return CategoryTest, true
	case strings.Contains(lower, "/controllers/") || strings.Contains(lower, "/controller/"):
		return CategoryController, true
	case strings.Contains(lower, "/services/") || strings.Contains(lower, "/service/"):
		return CategoryService, true
	case strings.Contains(lower, "/models/") || strings.Contains(lower, "/model/"):
		return CategoryModel, true
	case strings.Contains(lower, "/views/") || strings.Contains(lower, "/view/") || strings.HasSuffix(base, ".blade.php") || strings.HasSuffix(base, ".twig"):
		return CategoryView, true
	case strings.Contains(lower, "migration"):
		return CategoryMigration, true
	case strings.Contains(lower, "/config/") || base == "config.php" || strings.HasSuffix(base, ".env"):
		return CategoryConfig, true
	}
	return "", false
}

// dominantLanguage returns the project's primary language. A backend language
// implied by a manifest (e.g. composer.json -> PHP) wins when that language has
// source files, since front-end assets often outnumber backend files. Failing
// that, it falls back to the language with the most source files.
func dominantLanguage(byExt map[string]int, backendLangs map[string]bool) string {
	langCount := map[string]int{}
	for ext, n := range byExt {
		if lang, ok := extLanguage[ext]; ok {
			langCount[lang] += n
		}
	}

	// Prefer the backend manifest language with the most source files.
	bestBackend, bestBackendN := "", 0
	for lang := range backendLangs {
		if n := langCount[lang]; n > bestBackendN {
			bestBackend, bestBackendN = lang, n
		}
	}
	if bestBackend != "" {
		return bestBackend
	}

	// Fall back to the most common source language overall.
	best, bestN := "", 0
	for lang, n := range langCount {
		if n > bestN {
			best, bestN = lang, n
		}
	}
	if best == "" {
		return "Unknown"
	}
	return best
}
