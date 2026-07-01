// Package detector performs deep technology detection (Phase 2).
//
// Where the scanner only collects raw signals (file counts, manifest presence),
// the detector reads the *contents* of manifests and config files to positively
// identify the backend framework, database, and infrastructure, and attaches
// the evidence behind each conclusion.
//
// Detection is signal-based and best-effort: every finding carries a confidence
// level so consumers (report, AI layer) can present results honestly rather
// than asserting certainty.
package detector

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aipda/observer/internal/scanner"
)

// Confidence expresses how strongly the evidence supports a finding.
type Confidence string

const (
	High   Confidence = "High"
	Medium Confidence = "Medium"
	Low    Confidence = "Low"
)

// Finding is a single detected technology with the evidence that justifies it.
type Finding struct {
	Name       string
	Version    string // optional; empty if unknown
	Confidence Confidence
	Evidence   []string
}

// TechStack is the full Phase 2 result: the identified technologies grouped by
// concern. Each slice may be empty if nothing was detected for that concern.
type TechStack struct {
	Languages      []Finding
	Frameworks     []Finding
	Databases      []Finding
	Infrastructure []Finding
}

// Caps keep detection bounded on large repositories: we only read small,
// relevant files and only scan a limited number of YAML/Terraform files.
const (
	maxManifestBytes = 512 * 1024
	maxScanFiles     = 200
	maxScanFileBytes = 64 * 1024
)

// collected holds the project files relevant to detection, gathered in a single
// lightweight walk. Only allowlisted files are recorded; their contents are
// read on demand.
type collected struct {
	root      string
	manifests map[string]string // basename -> file path (first occurrence)
	yamlFiles []string
	tfFiles   []string
	dirs      map[string]bool // set of directory basenames seen
}

// interestingFiles are basenames whose presence or contents drive detection.
var interestingFiles = map[string]bool{
	"composer.json":       true,
	"package.json":        true,
	"requirements.txt":    true,
	"pyproject.toml":      true,
	"Pipfile":             true,
	"setup.py":            true,
	"pom.xml":             true,
	"build.gradle":        true,
	"build.gradle.kts":    true,
	"Gemfile":             true,
	"go.mod":              true,
	"artisan":             true, // Laravel
	"spark":               true, // CodeIgniter 4
	"CodeIgniter.php":     true, // CodeIgniter core (vendored, not via Composer)
	"manage.py":           true, // Django
	"Dockerfile":          true,
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
	"serverless.yml":      true,
	"serverless.yaml":     true,
	"database.php":        true, // CodeIgniter DB config
	".env":                true,
	".env.example":        true,
}

// Detect walks the project rooted at root and returns the identified TechStack.
func Detect(root string) (*TechStack, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, err
	}

	c, err := gather(abs)
	if err != nil {
		return nil, err
	}

	ts := &TechStack{}
	detectFrameworksAndLanguages(c, ts)
	detectDatabases(c, ts)
	detectInfrastructure(c, ts)
	return ts, nil
}

// gather performs the single detection walk, recording only allowlisted files.
func gather(root string) (*collected, error) {
	c := &collected{
		root:      root,
		manifests: map[string]string{},
		dirs:      map[string]bool{},
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && scanner.IsIgnoredDir(name) {
				return fs.SkipDir
			}
			c.dirs[strings.ToLower(name)] = true
			return nil
		}
		if interestingFiles[name] {
			if _, seen := c.manifests[name]; !seen {
				c.manifests[name] = p
			}
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".yaml", ".yml":
			if len(c.yamlFiles) < maxScanFiles {
				c.yamlFiles = append(c.yamlFiles, p)
			}
		case ".tf":
			if len(c.tfFiles) < maxScanFiles {
				c.tfFiles = append(c.tfFiles, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// read returns the (capped) contents of a manifest recorded under basename, or
// "" with ok=false if it was not present.
func (c *collected) read(basename string) (string, bool) {
	p, ok := c.manifests[basename]
	if !ok {
		return "", false
	}
	return readCapped(p, maxManifestBytes), true
}

func readCapped(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}
