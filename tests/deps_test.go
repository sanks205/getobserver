package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aipda/observer/internal/deps"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestParseManifests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "composer.lock", `{"packages":[{"name":"monolog/monolog","version":"1.0.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}`)
	writeFile(t, dir, "requirements.txt", "Django==2.2.0\nrequests>=2.0\n# comment\nflask==1.0.0\n")

	got, err := deps.Parse(dir)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	// 2 composer + 2 pinned pip (requests is unpinned -> skipped) = 4
	if len(got) != 4 {
		t.Fatalf("parsed %d deps, want 4: %+v", len(got), got)
	}
	var foundMonolog, foundDjango bool
	for _, d := range got {
		if d.Name == "monolog/monolog" && d.Ecosystem == "Packagist" && d.Version == "1.0.0" {
			foundMonolog = true
		}
		if d.Name == "Django" && d.Ecosystem == "PyPI" && d.Version == "2.2.0" {
			foundDjango = true
		}
	}
	if !foundMonolog || !foundDjango {
		t.Errorf("expected monolog (Packagist) and Django (PyPI); got %+v", got)
	}
}

// TestScanWithMockOSV verifies the full scan path against a mock OSV server.
func TestScanWithMockOSV(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "composer.lock", `{"packages":[{"name":"vuln/pkg","version":"1.0.0"},{"name":"safe/pkg","version":"2.0.0"}]}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/querybatch"):
			// First dep is vulnerable, second is clean.
			resp := map[string]any{"results": []any{
				map[string]any{"vulns": []any{map[string]string{"id": "GHSA-xxxx-1"}}},
				map[string]any{},
			}}
			_ = json.NewEncoder(w).Encode(resp)
		case strings.Contains(r.URL.Path, "/v1/vulns/"):
			resp := map[string]any{
				"id":                "GHSA-xxxx-1",
				"summary":           "Remote code execution in vuln/pkg",
				"database_specific": map[string]string{"severity": "CRITICAL"},
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &deps.Client{BaseURL: srv.URL, HTTP: srv.Client()}
	rep, err := deps.Scan(dir, client)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if rep.DepsScanned != 2 {
		t.Errorf("DepsScanned = %d, want 2", rep.DepsScanned)
	}
	if len(rep.Vulns) != 1 {
		t.Fatalf("vulns = %d, want 1: %+v", len(rep.Vulns), rep.Vulns)
	}
	v := rep.Vulns[0]
	if v.ID != "GHSA-xxxx-1" || v.Severity != "Critical" || v.Package != "vuln/pkg" {
		t.Errorf("unexpected vuln: %+v", v)
	}
	if !strings.Contains(v.Summary, "Remote code execution") {
		t.Errorf("summary not carried through: %q", v.Summary)
	}
}
