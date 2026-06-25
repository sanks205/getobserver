// Package logger implements the log analyzer (Phase 5).
//
// It parses application log files (a single file or a directory of them),
// classifies error-level entries, and groups repeated failures by a normalized
// signature so the report can answer "what is the most common production issue
// and how often does it happen?" — rather than dumping thousands of raw lines.
//
// It understands CodeIgniter and Monolog/Laravel line formats and falls back to
// a generic level-keyword scan for everything else.
package logger

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Group is a set of log entries sharing the same normalized signature.
type Group struct {
	Signature string // normalized message (grouping key)
	Sample    string // a representative raw message
	Category  string // Database, API, Auth, Resource, Application
	Level     string // highest-severity level seen for this signature
	Count     int
	FirstSeen string
	LastSeen  string
	Cause     string // heuristic possible cause (may be empty)
}

// Summary is the aggregated result of analyzing logs.
type Summary struct {
	FilesParsed int
	TotalLines  int
	TotalErrors int
	ByLevel     map[string]int
	ByCategory  map[string]int
	Groups      []Group // distinct error signatures, most frequent first
}

// errorLevels are the levels we aggregate as problems. DEBUG/INFO/NOTICE are
// counted as parsed lines but excluded from error grouping.
var errorLevels = map[string]bool{
	"EMERGENCY": true, "ALERT": true, "CRITICAL": true, "ERROR": true,
	"FATAL": true, "EXCEPTION": true, "WARNING": true,
}

// Line-format parsers.
var (
	ciLine      = regexp.MustCompile(`^(?i)(ERROR|CRITICAL|WARNING|DEBUG|INFO|NOTICE|ALL)\s*-\s*([0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9:]+)\s*-->\s*(.*)$`)
	monologLine = regexp.MustCompile(`^\[([0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9:.+-]+)\]\s+[\w.\-]+\.(?i:(ERROR|CRITICAL|WARNING|ALERT|EMERGENCY|NOTICE|INFO|DEBUG)):\s*(.*)$`)
	genericLvl  = regexp.MustCompile(`(?i)\b(EMERGENCY|ALERT|CRITICAL|FATAL|ERROR|WARNING|EXCEPTION)\b`)
)

// logFileGlobs match files we treat as logs inside a directory.
var logFileGlobs = []string{"*.log", "*.txt", "log-*.php"}

// Analyze parses the logs at path (a file or directory) and returns a Summary.
func Analyze(path string) (*Summary, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		for _, g := range logFileGlobs {
			m, _ := filepath.Glob(filepath.Join(path, g))
			files = append(files, m...)
		}
	} else {
		files = []string{path}
	}

	s := &Summary{ByLevel: map[string]int{}, ByCategory: map[string]int{}}
	groups := map[string]*Group{}

	for _, f := range files {
		if parseFile(f, s, groups) {
			s.FilesParsed++
		}
	}

	s.Groups = make([]Group, 0, len(groups))
	for _, g := range groups {
		s.Groups = append(s.Groups, *g)
	}
	sort.SliceStable(s.Groups, func(i, j int) bool {
		if s.Groups[i].Count != s.Groups[j].Count {
			return s.Groups[i].Count > s.Groups[j].Count
		}
		return s.Groups[i].Signature < s.Groups[j].Signature
	})
	return s, nil
}

func parseFile(path string, s *Summary, groups map[string]*Group) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		s.TotalLines++

		level, ts, msg, ok := parseLine(line)
		if !ok || !errorLevels[level] {
			continue
		}
		s.TotalErrors++
		s.ByLevel[level]++

		sig := signature(msg)
		cat := classify(msg)
		s.ByCategory[cat]++

		g, exists := groups[sig]
		if !exists {
			g = &Group{
				Signature: sig, Sample: truncate(msg, 200), Category: cat,
				Level: level, FirstSeen: ts, LastSeen: ts, Cause: cause(msg),
			}
			groups[sig] = g
		}
		g.Count++
		if severityRank(level) > severityRank(g.Level) {
			g.Level = level
		}
		if ts != "" {
			if g.FirstSeen == "" || ts < g.FirstSeen {
				g.FirstSeen = ts
			}
			if ts > g.LastSeen {
				g.LastSeen = ts
			}
		}
	}
	return true
}

// parseLine extracts (level, timestamp, message) from one log line.
func parseLine(line string) (level, ts, msg string, ok bool) {
	if m := ciLine.FindStringSubmatch(line); m != nil {
		return strings.ToUpper(m[1]), m[2], strings.TrimSpace(m[3]), true
	}
	if m := monologLine.FindStringSubmatch(line); m != nil {
		return strings.ToUpper(m[2]), m[1], strings.TrimSpace(m[3]), true
	}
	if m := genericLvl.FindStringSubmatch(line); m != nil {
		return strings.ToUpper(m[1]), "", line, true
	}
	return "", "", "", false
}

func severityRank(level string) int {
	switch level {
	case "EMERGENCY", "ALERT", "CRITICAL", "FATAL":
		return 4
	case "ERROR", "EXCEPTION":
		return 3
	case "WARNING":
		return 2
	}
	return 1
}

// --- message normalization & classification ---------------------------------

var (
	reQuoted = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	reNumber = regexp.MustCompile(`\b[0-9a-fA-Fx]*[0-9][0-9a-fA-Fx]*\b`)
	reSpace  = regexp.MustCompile(`\s+`)
)

// signature normalizes a message into a stable grouping key by stripping
// volatile parts (quoted values, numbers/ids/hex) and collapsing whitespace.
func signature(msg string) string {
	s := reQuoted.ReplaceAllString(msg, "?")
	s = reNumber.ReplaceAllString(s, "#")
	s = reSpace.ReplaceAllString(s, " ")
	s = strings.ToLower(strings.TrimSpace(s))
	return truncate(s, 120)
}

// categoryKeywords maps a category to the substrings that identify it.
var categoryKeywords = []struct {
	cat      string
	keywords []string
}{
	{"Database", []string{"sqlstate", "mysqli", "mysql", "deadlock", "lock wait", "pdo", "doctrine",
		"query", "database", "too many connections", "sql syntax", "2002", "1205", "1213"}},
	{"API", []string{"curl", "guzzle", "http error", "http request", "upstream", "gateway",
		"502", "503", "504", "ssl", "connection timed out", "api "}},
	{"Auth", []string{"unauthorized", "forbidden", "permission denied", "auth", "token", "csrf", "login failed"}},
	{"Resource", []string{"allowed memory size", "maximum execution time", "out of memory", "disk", "too many open files"}},
}

func classify(msg string) string {
	low := strings.ToLower(msg)
	for _, c := range categoryKeywords {
		for _, kw := range c.keywords {
			if strings.Contains(low, kw) {
				return c.cat
			}
		}
	}
	return "Application"
}

// cause returns a heuristic likely cause based on recognizable message markers.
func cause(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "deadlock"):
		return "Concurrent transactions deadlocking; review locking order and transaction scope."
	case strings.Contains(low, "lock wait") || strings.Contains(low, "1205"):
		return "Lock wait timeout from long-running transactions; shorten transactions, add indexes."
	case strings.Contains(low, "too many connections"):
		return "Database connection pool exhausted; tune pool size and close connections."
	case strings.Contains(low, "2002") || strings.Contains(low, "connection refused"):
		return "Database unreachable; check host/port/credentials and that the DB is running."
	case strings.Contains(low, "timeout") && (strings.Contains(low, "query") || strings.Contains(low, "sql")):
		return "Slow query timing out; add indexes / optimize the query."
	case strings.Contains(low, "allowed memory size") || strings.Contains(low, "out of memory"):
		return "Excessive memory use; stream/paginate data or raise memory_limit."
	case strings.Contains(low, "maximum execution time"):
		return "Long-running request; optimize or move work to a background job."
	case strings.Contains(low, "curl") || strings.Contains(low, "504") || strings.Contains(low, "connection timed out"):
		return "Upstream/API latency or downtime; add timeouts, retries, and a circuit breaker."
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
