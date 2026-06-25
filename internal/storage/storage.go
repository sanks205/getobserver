// Package storage persists scan results for the dashboard (Phase 11).
//
// The local/desktop tier uses a dependency-free file store: each scan is saved
// as a metadata JSON file plus the rendered HTML report, under a data
// directory. This keeps the binary self-contained (no SQLite/CGO, no server).
// The hosted Cloud tier will swap in PostgreSQL behind the same Store interface.
package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// Record is the metadata for one saved scan.
type Record struct {
	ID            string   `json:"id"`
	Project       string   `json:"project"`
	Path          string   `json:"path"`
	CreatedAt     string   `json:"created_at"` // RFC3339
	Language      string   `json:"language"`
	Stack         []string `json:"stack"`
	Total         int      `json:"total"`
	Critical      int      `json:"critical"`
	High          int      `json:"high"`
	Medium        int      `json:"medium"`
	Low           int      `json:"low"`
	NewSince      int      `json:"new_since"` // new issues vs the previous scan of this path
	FilesScanned  int      `json:"files_scanned"`
	DurationMs    int64    `json:"duration_ms"`
	SecurityScore int      `json:"security_score"`
	SecurityGrade string   `json:"security_grade"`
	HealthScore   int      `json:"health_score"`
	HealthGrade   string   `json:"health_grade"`
}

// Store is a file-based scan store.
type Store struct {
	dir string
}

// New opens (creating if needed) a store rooted at dir. If dir is empty it uses
// the user config dir (~/.config/observer or %AppData%/observer), falling back
// to ./.observer-data.
func New(dir string) (*Store, error) {
	if dir == "" {
		if cfg, err := os.UserConfigDir(); err == nil {
			dir = filepath.Join(cfg, "observer", "scans")
		} else {
			dir = ".observer-data"
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store's data directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) metaPath(id string) string { return filepath.Join(s.dir, id+".json") }
func (s *Store) htmlPath(id string) string { return filepath.Join(s.dir, id+".html") }

// Save writes the record metadata and its rendered HTML report.
func (s *Store) Save(rec Record, html string) error {
	if err := os.WriteFile(s.htmlPath(rec.ID), []byte(html), 0o644); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(rec.ID), b, 0o644)
}

// List returns all records, newest first.
func (s *Store) List() ([]Record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var r Record
		if json.Unmarshal(b, &r) == nil {
			recs = append(recs, r)
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].CreatedAt > recs[j].CreatedAt })
	return recs, nil
}

// HTML returns the stored HTML report for an id.
func (s *Store) HTML(id string) (string, error) {
	b, err := os.ReadFile(s.htmlPath(id))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// LatestForPath returns the most recent prior record for a project path, used
// to compute "new since last scan". Returns ok=false if there is none.
func (s *Store) LatestForPath(path string) (Record, bool) {
	recs, err := s.List()
	if err != nil {
		return Record{}, false
	}
	for _, r := range recs {
		if r.Path == path {
			return r, true
		}
	}
	return Record{}, false
}
