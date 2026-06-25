// Package ai is the AI explanation layer (Phase 6).
//
// It is deliberately decoupled from the rest of the system: it defines its own
// Finding type and imports none of the scanner/analyzer/runtime/logger
// packages. Callers adapt their findings into ai.Finding, so AI logic never
// leaks into the diagnostic core.
//
// The LLM is abstracted behind the Provider interface so OpenAI (today) and
// other providers (later) are interchangeable. When no provider is configured
// the Explainer falls back to a deterministic local mode that only restates the
// findings — which enforces the core rule: the AI explains findings, it never
// invents issues or solutions that the findings do not support.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Finding is a normalized issue handed to the AI layer. It is intentionally
// independent of the analyzer/runtime/logger types.
type Finding struct {
	Source         string `json:"source"`   // "static" | "runtime" | "log"
	Severity       string `json:"severity"` // Critical | High | Medium | Low
	Category       string `json:"category"`
	Title          string `json:"title"`
	Location       string `json:"location,omitempty"`
	Detail         string `json:"detail,omitempty"`         // why it matters
	Recommendation string `json:"recommendation,omitempty"` // suggested fix, if known
	Cause          string `json:"cause,omitempty"`          // likely cause, if known
	CWE            string `json:"cwe,omitempty"`            // for remediation lookup
	Count          int    `json:"count,omitempty"`
}

// Input is everything the AI layer reasons over.
type Input struct {
	ProjectName string
	Stack       []string
	Findings    []Finding
}

// Insight is the AI explanation of one finding or group of findings.
type Insight struct {
	Title      string
	Severity   string
	Problem    string
	RootCause  string
	Impact     string
	Suggestion string
	Exploit    string // how it could be exploited / why it bites in production
	FixExample string // generic before/after remediation pattern
	Complexity string // Low | Medium | High
	Effort     string // rough effort estimate, e.g. "~15 min"
}

// Report is the AI layer's structured output.
type Report struct {
	Provider   string
	Summary    string
	Insights   []Insight
	Priorities []string
}

// Request is a single LLM completion request.
type Request struct {
	System      string
	User        string
	Temperature float32
	MaxTokens   int
}

// Provider abstracts an LLM backend. Implementations must be safe for the
// Explainer to call once per report.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (string, error)
}

// Explainer produces a Report from an Input. If Provider is nil it uses the
// deterministic local mode.
type Explainer struct {
	Provider Provider
}

const maxInsights = 12

// Explain returns a Report for the given input. With no provider it returns the
// local heuristic report. With a provider it builds a grounded prompt, calls
// the provider, and parses the JSON response; any failure is returned so the
// caller can fall back to LocalReport.
func (e *Explainer) Explain(ctx context.Context, in Input) (*Report, error) {
	if e == nil || e.Provider == nil {
		return LocalReport(in), nil
	}

	system, user := buildPrompt(in)
	raw, err := e.Provider.Complete(ctx, Request{
		System:      system,
		User:        user,
		Temperature: 0.1,
		MaxTokens:   1500,
	})
	if err != nil {
		return nil, err
	}
	rep, err := parseResponse(raw)
	if err != nil {
		return nil, err
	}
	rep.Provider = e.Provider.Name()
	return rep, nil
}

// systemPrompt instructs the model to explain only the provided findings.
const systemPrompt = `You are a senior production-debugging assistant.
You are given findings already detected by static analysis, runtime error capture, and log analysis of a software project.
Your job is to EXPLAIN these findings to a developer.

Strict rules:
1. Discuss ONLY the findings provided. Never invent issues or vulnerabilities a finding does not support.
2. For each insight provide: problem, possible root cause, impact (business + technical), how it could be exploited or bite in production, a suggested fix, a short before/after fix example, a fix-complexity (Low/Medium/High), and a rough effort estimate.
3. If information is insufficient, say so instead of guessing. Keep exploit/fix examples generic to the vulnerability class — do not fabricate specifics about their code.
4. Be concise, concrete, and practical.

Respond with ONLY valid JSON (no markdown fences) matching:
{"summary": string,
 "insights": [{"title": string, "severity": string, "problem": string, "root_cause": string, "impact": string, "exploit": string, "suggestion": string, "fix_example": string, "complexity": string, "effort": string}],
 "priorities": [string]}`

func buildPrompt(in Input) (system, user string) {
	findings := in.Findings
	if len(findings) > maxInsights {
		findings = findings[:maxInsights]
	}
	payload := struct {
		Project  string    `json:"project"`
		Stack    []string  `json:"stack"`
		Findings []Finding `json:"findings"`
	}{in.ProjectName, in.Stack, findings}

	b, _ := json.MarshalIndent(payload, "", "  ")
	user = "Here are the findings to explain:\n" + string(b)
	return systemPrompt, user
}

// aiResponse mirrors the JSON schema requested from the model.
type aiResponse struct {
	Summary  string `json:"summary"`
	Insights []struct {
		Title      string `json:"title"`
		Severity   string `json:"severity"`
		Problem    string `json:"problem"`
		RootCause  string `json:"root_cause"`
		Impact     string `json:"impact"`
		Exploit    string `json:"exploit"`
		Suggestion string `json:"suggestion"`
		FixExample string `json:"fix_example"`
		Complexity string `json:"complexity"`
		Effort     string `json:"effort"`
	} `json:"insights"`
	Priorities []string `json:"priorities"`
}

func parseResponse(raw string) (*Report, error) {
	raw = stripFences(strings.TrimSpace(raw))
	var r aiResponse
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w", err)
	}
	rep := &Report{Summary: r.Summary, Priorities: r.Priorities}
	for _, i := range r.Insights {
		rep.Insights = append(rep.Insights, Insight{
			Title: i.Title, Severity: i.Severity, Problem: i.Problem,
			RootCause: i.RootCause, Impact: i.Impact, Suggestion: i.Suggestion,
			Exploit: i.Exploit, FixExample: i.FixExample, Complexity: i.Complexity, Effort: i.Effort,
		})
	}
	return rep, nil
}

// stripFences removes a leading/trailing ```json ... ``` wrapper if present.
func stripFences(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

// =============================================================================
// Local (no-LLM) deterministic report — restates findings only.
// =============================================================================

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// LocalReport synthesizes a report from the findings alone, without any LLM.
// It never adds information beyond what the findings contain.
func LocalReport(in Input) *Report {
	findings := append([]Finding(nil), in.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Count > findings[j].Count
	})

	rep := &Report{Provider: "local (heuristic, no LLM)"}
	rep.Summary = localSummary(in, findings)

	limit := len(findings)
	if limit > maxInsights {
		limit = maxInsights
	}
	for _, f := range findings[:limit] {
		rem := remediationFor(f)
		rep.Insights = append(rep.Insights, Insight{
			Title:      f.Title,
			Severity:   f.Severity,
			Problem:    problemText(f),
			RootCause:  rootCauseText(f),
			Impact:     impactText(f.Severity),
			Suggestion: suggestionText(f),
			Exploit:    rem.Exploit,
			FixExample: rem.FixExample,
			Complexity: rem.Complexity,
			Effort:     rem.Effort,
		})
		rep.Priorities = append(rep.Priorities, fmt.Sprintf("[%s] %s", f.Severity, f.Title))
	}
	if len(rep.Priorities) > 5 {
		rep.Priorities = rep.Priorities[:5] // keep the priority list short
	}
	return rep
}

func localSummary(in Input, findings []Finding) string {
	var c, h, m, l int
	for _, f := range findings {
		switch severityRank(f.Severity) {
		case 4:
			c++
		case 3:
			h++
		case 2:
			m++
		case 1:
			l++
		}
	}
	stack := "unknown stack"
	if len(in.Stack) > 0 {
		stack = strings.Join(in.Stack, ", ")
	}
	return fmt.Sprintf(
		"Analyzed %s (%s). Collected %d finding(s): %d critical, %d high, %d medium, %d low, "+
			"spanning static analysis, runtime errors, and logs. The most pressing items are listed below; "+
			"explanations restate the detected findings without adding unverified conclusions.",
		nonEmpty(in.ProjectName, "the project"), stack, len(findings), c, h, m, l)
}

func problemText(f Finding) string {
	loc := ""
	if f.Location != "" {
		loc = " (" + f.Location + ")"
	}
	count := ""
	if f.Count > 1 {
		count = fmt.Sprintf(" — observed %d times", f.Count)
	}
	return f.Title + loc + count
}

func rootCauseText(f Finding) string {
	if f.Cause != "" {
		return f.Cause
	}
	if f.Detail != "" {
		return f.Detail
	}
	return "Not determined from the available findings."
}

func impactText(severity string) string {
	switch severityRank(severity) {
	case 4:
		return "Critical — can cause outages, data loss, or a security breach if unaddressed."
	case 3:
		return "High — significant risk to stability, security, or correctness."
	case 2:
		return "Medium — degrades performance or quality, or creates latent risk."
	case 1:
		return "Low — minor issue or best-practice deviation."
	}
	return "Unclassified."
}

func suggestionText(f Finding) string {
	if f.Recommendation != "" {
		return f.Recommendation
	}
	return "Investigate the finding at its location and address the underlying condition."
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
