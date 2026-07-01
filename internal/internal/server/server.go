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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/detector"
	"github.com/aipda/observer/internal/reporter"
	"github.com/aipda/observer/internal/scanner"
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

	// "New since last scan" — delta vs the previous scan of this path.
	if prev, ok := s.store.LatestForPath(res.RootPath); ok {
		if d := rec.Total - prev.Total; d > 0 {
			rec.NewSince = d
		}
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
