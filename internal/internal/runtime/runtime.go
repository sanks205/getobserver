// Package runtime ingests runtime error events captured by observer-agent
// (Phase 4).
//
// The PHP agent writes one JSON object per line (JSONL). This package loads
// those events and aggregates them — grouping repeated failures by signature
// (type + file + line) so the report can surface the most common production
// errors rather than a raw, unreadable event dump.
package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Event is a single captured runtime failure. Fields mirror the JSON the
// observer-agent emits; all are optional so partial events still load.
type Event struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Trace     string `json:"trace"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	User      string `json:"user"`
	Severity  string `json:"severity"`
	App       string `json:"app"`
}

// Group is a set of events sharing the same signature (type + file + line).
type Group struct {
	Type        string
	File        string
	Line        int
	Count       int
	LastSeen    string
	LastMessage string
	Severity    string
}

// Summary is the aggregated view of all loaded events.
type Summary struct {
	Total  int
	Groups []Group // distinct error signatures, most frequent first
	Recent []Event // most recent events, newest first
}

const maxRecent = 15

// Load reads runtime events from a JSONL file, or from every *.jsonl file in a
// directory. Malformed lines are skipped so one bad record can't break loading.
func Load(path string) ([]Event, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		matches, err := filepath.Glob(filepath.Join(path, "*.jsonl"))
		if err != nil {
			return nil, err
		}
		files = matches
	} else {
		files = []string{path}
	}

	var events []Event
	for _, f := range files {
		evs, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		events = append(events, evs...)
	}
	return events, nil
}

func loadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // allow long trace lines
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(line, &e) != nil {
			continue // skip malformed lines
		}
		events = append(events, e)
	}
	return events, sc.Err()
}

// Summarize groups events by signature and selects the most recent ones.
func Summarize(events []Event) *Summary {
	s := &Summary{Total: len(events)}

	type acc struct {
		g     Group
		order int
	}
	groups := map[string]*acc{}
	for i, e := range events {
		key := fmt.Sprintf("%s|%s|%d", e.Type, e.File, e.Line)
		a, ok := groups[key]
		if !ok {
			a = &acc{g: Group{Type: e.Type, File: e.File, Line: e.Line, Severity: e.Severity}, order: i}
			groups[key] = a
		}
		a.g.Count++
		// Keep the most recent occurrence's details.
		if e.Timestamp >= a.g.LastSeen {
			a.g.LastSeen = e.Timestamp
			a.g.LastMessage = e.Message
			a.g.Severity = e.Severity
		}
	}

	s.Groups = make([]Group, 0, len(groups))
	for _, a := range groups {
		s.Groups = append(s.Groups, a.g)
	}
	sort.SliceStable(s.Groups, func(i, j int) bool {
		if s.Groups[i].Count != s.Groups[j].Count {
			return s.Groups[i].Count > s.Groups[j].Count
		}
		return s.Groups[i].LastSeen > s.Groups[j].LastSeen
	})

	// Recent events: newest first by timestamp.
	recent := make([]Event, len(events))
	copy(recent, events)
	sort.SliceStable(recent, func(i, j int) bool {
		return recent[i].Timestamp > recent[j].Timestamp
	})
	if len(recent) > maxRecent {
		recent = recent[:maxRecent]
	}
	s.Recent = recent
	return s
}
