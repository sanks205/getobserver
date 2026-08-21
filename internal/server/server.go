// Package server implements `observer serve` (Phase 11): a local web dashboard.
//
// It runs the same diagnostic core as the CLI but presents results on a single
// page — pick a project folder, scan it, browse past scans and their reports,
// and see how many issues are new since the previous scan. Results are persisted
// via the storage package so history survives restarts.
//
// This is the foundation of the Pro tier; the core engine stays open while
// premium features (branding, scheduling, team accounts) layer on top later.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/bandit"
	"github.com/aipda/observer/internal/detector"
	"github.com/aipda/observer/internal/eslint"
	"github.com/aipda/observer/internal/gosec"
	"github.com/aipda/observer/internal/phpstan"
	"github.com/aipda/observer/internal/reporter"
	"github.com/aipda/observer/internal/scanner"
	"github.com/aipda/observer/internal/semgrep"
	"github.com/aipda/observer/internal/storage"
)

// Server holds dependencies for the dashboard.
type Server struct {
	store *storage.Store
}

// New creates a dashboard server backed by the given store.
func New(store *storage.Store) *Server {
	return &Server{store: store}
}

// Routes returns the HTTP handler for the dashboard.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/prepare-scan", s.handlePrepareScan)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/report/", s.handleReport)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

// scanRequest is the JSON body for POST /api/scan. Categories empty = all;
// MinSeverity empty = include all severities.
type scanRequest struct {
	Path        string   `json:"path"`
	Categories  []string `json:"categories"`
	MinSeverity string   `json:"min_severity"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'path'"})
		return
	}

	rec, err := s.runScan(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handlePrepareScan checks which recommended local engines are missing for the
// project's stack WITHOUT running a full scan. The dashboard uses this to show
// an optional accuracy-upgrade prompt before scanning, so the user can install
// engines first. It never blocks the scan — missing engines are only a hint.
func (s *Server) handlePrepareScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'path'"})
		return
	}
	tech, _ := detector.Detect(req.Path)
	missing := recommendedEngines(req.Path, tech)
	// Large-project hint from the last scan's file count (drives a "deep scan may
	// take a while" note when engines will run).
	large := false
	if prev, ok := s.store.LatestForPath(req.Path); ok && prev.FilesScanned > 1500 {
		large = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"missing": missing,
		"stack":   stackNames(tech),
		"large":   large,
	})
}

// scanTimeout is the maximum wall-clock time allowed for the engine phase of a
// scan (all optional engines share this single budget). It is configurable via
// the OBSERVER_SCAN_TIMEOUT env var (a Go duration string such as "15m" or
// "30m"); it defaults to 15 minutes. A cap is kept as a safety net so a very
// large project cannot strand a scan indefinitely, but it is high enough that
// deep scans of big codebases (PHPStan + Semgrep over thousands of files) finish.
func scanTimeout() time.Duration {
	const def = 15 * time.Minute
	const max = 60 * time.Minute
	if v := os.Getenv("OBSERVER_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute && d <= max {
			return d
		}
	}
	return def
}

// runScan executes the diagnostic core, applies the customer's category/severity
// scope, renders + stores the report, and returns the saved record (with scan
// duration and the count of issues new since the last scan).
func (s *Server) runScan(req scanRequest) (storage.Record, error) {
	start := time.Now()

	res, err := scanner.Scan(req.Path)
	if err != nil {
		return storage.Record{}, err
	}
	tech, _ := detector.Detect(req.Path)
	analysis, _ := analyzer.Analyze(req.Path)

	// Theme 1 — optional local engines run AUTOMATICALLY in the dashboard whenever
	// installed (no flags). Each engine self-reports availability and is skipped if
	// absent, so users without engines stay fast (built-in only) while users who
	// install them get deeper, type-aware analysis with far fewer false positives.
	// engineMode records which path the scan took.
	engineMode := "builtin"
	var ranEngines []string
	if analysis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout())
		defer cancel()

		// Semgrep — multi-language security/taint analysis.
		if findings, err := semgrep.Scan(ctx, req.Path, os.Getenv("SEMGREP_CONFIG")); err != nil {
			if !errors.Is(err, semgrep.ErrNotAvailable) {
				fmt.Fprintf(os.Stderr, "warning: semgrep run failed: %v\n", err)
			}
		} else {
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the Semgrep finding and remediate.",
					CWE: f.CWE, OWASP: f.OWASP,
				})
			}
			analysis.AddIssues(issues...)
			engineMode = "deep"
			ranEngines = append(ranEngines, "Semgrep")
		}

		// PHPStan — type-aware PHP/Laravel analysis. If the project has no config,
		// Observer creates a minimal phpstan.neon so it still runs.
		findings, err := phpstan.Scan(ctx, req.Path)
		if errors.Is(err, phpstan.ErrNoConfig) {
			if phpstan.EnsureConfig(req.Path) == nil {
				findings, err = phpstan.Scan(ctx, req.Path)
			}
		}
		switch {
		case errors.Is(err, phpstan.ErrNotAvailable):
			// not installed — skip
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: phpstan run failed: %v\n", err)
		default:
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line,
					Explanation: f.Message, Recommendation: "Review the PHPStan finding and fix the reported issue.",
				})
			}
			analysis.AddIssues(issues...)
			engineMode = "deep"
			ranEngines = append(ranEngines, "PHPStan")
		}

		// Bandit — Python security patterns.
		if findings, err := bandit.Scan(ctx, req.Path); err != nil {
			if !errors.Is(err, bandit.ErrNotAvailable) {
				fmt.Fprintf(os.Stderr, "warning: bandit run failed: %v\n", err)
			}
		} else {
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the Bandit finding and remediate.",
					CWE: f.CWE,
				})
			}
			analysis.AddIssues(issues...)
			engineMode = "deep"
			ranEngines = append(ranEngines, "Bandit")
		}

		// gosec — Go security analysis.
		if findings, err := gosec.Scan(ctx, req.Path); err != nil {
			if !errors.Is(err, gosec.ErrNotAvailable) {
				fmt.Fprintf(os.Stderr, "warning: gosec run failed: %v\n", err)
			}
		} else {
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the gosec finding and remediate.",
					CWE: f.CWE,
				})
			}
			analysis.AddIssues(issues...)
			engineMode = "deep"
			ranEngines = append(ranEngines, "GoSec")
		}

		// ESLint — JavaScript/TypeScript lint + security rules.
		if findings, err := eslint.Scan(ctx, req.Path); err != nil {
			if !errors.Is(err, eslint.ErrNotAvailable) {
				fmt.Fprintf(os.Stderr, "warning: eslint run failed: %v\n", err)
			}
		} else {
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the ESLint finding and remediate.",
				})
			}
			analysis.AddIssues(issues...)
			engineMode = "deep"
			ranEngines = append(ranEngines, "ESLint")
		}
	}

	// Apply the chosen scope (categories + minimum severity).
	if analysis != nil {
		allowed := map[string]bool{}
		for _, c := range req.Categories {
			allowed[c] = true
		}
		analysis = analyzer.Filter(analysis, allowed, analyzer.ParseSeverity(req.MinSeverity))
	}

	durationMs := time.Since(start).Milliseconds()
	data := reporter.Data{Scan: res, Tech: tech, Analysis: analysis, DurationMs: durationMs}
	html, err := reporter.RenderHTML(data)
	if err != nil {
		return storage.Record{}, err
	}

	rec := storage.Record{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Project:    res.ProjectName,
		Path:       res.RootPath,
		CreatedAt:  time.Now().Format(time.RFC3339),
		Language:   res.DominantLang,
		Stack:      stackNames(tech),
		DurationMs: durationMs,
		EngineMode: engineMode,
		Engines:   ranEngines,
	}
	if analysis != nil {
		rec.Total = len(analysis.Issues)
		rec.Critical = analysis.BySeverity[analyzer.Critical]
		rec.High = analysis.BySeverity[analyzer.High]
		rec.Medium = analysis.BySeverity[analyzer.Medium]
		rec.Low = analysis.BySeverity[analyzer.Low]
		rec.FilesScanned = analysis.FilesScanned
		rec.SecurityScore, rec.SecurityGrade = analyzer.SecurityScore(analysis)
		rec.HealthScore, rec.HealthGrade = analyzer.HealthScore(analysis)
	}

	// "New since last scan" — net delta vs the previous scan of this path.
	// Stored as a signed value so reductions show as negative (e.g. -5 means
	// five issues were fixed since the last scan).
	if prev, ok := s.store.LatestForPath(res.RootPath); ok {
		rec.NewSince = rec.Total - prev.Total
	}

	if err := s.store.Save(rec, html); err != nil {
		return storage.Record{}, err
	}
	return rec, nil
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, recs)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/report/"):]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	html, err := s.store.HTML(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func stackNames(tech *detector.TechStack) []string {
	if tech == nil {
		return nil
	}
	var names []string
	for _, f := range tech.Frameworks {
		names = append(names, f.Name)
	}
	for _, f := range tech.Databases {
		names = append(names, f.Name)
	}
	return names
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
