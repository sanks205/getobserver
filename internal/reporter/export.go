package reporter

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/aipda/observer/internal/analyzer"
)

// jsonReport is the machine-readable export shape.
type jsonReport struct {
	Project     string         `json:"project"`
	GeneratedAt string         `json:"generated_at"`
	Security    scoreJSON      `json:"security_score"`
	CodeHealth  scoreJSON      `json:"code_health_score"`
	Summary     map[string]int `json:"summary"`
	Findings    []jsonFinding  `json:"findings"`
}

type scoreJSON struct {
	Value int    `json:"value"`
	Grade string `json:"grade"`
}

type jsonFinding struct {
	Rule           string `json:"rule"`
	Severity       string `json:"severity"`
	CVSS           string `json:"cvss"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	File           string `json:"file"`
	Line           int    `json:"line"`
	Snippet        string `json:"snippet,omitempty"`
	Explanation    string `json:"explanation,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	CWE            string `json:"cwe,omitempty"`
	OWASP          string `json:"owasp,omitempty"`
}

func buildJSON(d Data) jsonReport {
	rep := jsonReport{
		Project:     d.Scan.ProjectName,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Summary:     map[string]int{},
	}
	if d.Analysis != nil {
		secV, secG := analyzer.SecurityScore(d.Analysis)
		hV, hG := analyzer.HealthScore(d.Analysis)
		rep.Security = scoreJSON{secV, secG}
		rep.CodeHealth = scoreJSON{hV, hG}
		rep.Summary["total"] = len(d.Analysis.Issues)
		rep.Summary["critical"] = d.Analysis.BySeverity[analyzer.Critical]
		rep.Summary["high"] = d.Analysis.BySeverity[analyzer.High]
		rep.Summary["medium"] = d.Analysis.BySeverity[analyzer.Medium]
		rep.Summary["low"] = d.Analysis.BySeverity[analyzer.Low]
		rep.Summary["remediation_effort_minutes"] = analyzer.RemediationMinutes(d.Analysis)
		for _, is := range d.Analysis.Issues {
			rep.Findings = append(rep.Findings, jsonFinding{
				Rule: is.RuleID, Severity: string(is.Severity), CVSS: analyzer.CVSS(is.Severity), Category: is.Category,
				Title: is.Title, File: is.File, Line: is.Line, Snippet: is.Snippet,
				Explanation: is.Explanation, Recommendation: is.Recommendation,
				CWE:   firstNonEmpty(is.CWE, analyzer.CWEFor(is.RuleID)),
				OWASP: firstNonEmpty(is.OWASP, analyzer.OWASPFor(is.RuleID)),
			})
		}
	}
	return rep
}

// JSONBytes returns the findings + scores as JSON (for export or webhook POST).
func JSONBytes(d Data) ([]byte, error) {
	return json.MarshalIndent(buildJSON(d), "", "  ")
}

// GenerateJSON writes the findings and scores as JSON to outPath.
func GenerateJSON(d Data, outPath string) error {
	b, err := JSONBytes(d)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, b, 0o644)
}

// GenerateCSV writes the findings as CSV (opens directly in Excel/Sheets).
func GenerateCSV(d Data, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{"Severity", "Category", "CWE", "OWASP", "File", "Line", "Title", "Recommendation"})
	if d.Analysis == nil {
		return w.Error()
	}
	for _, is := range d.Analysis.Issues {
		_ = w.Write([]string{
			string(is.Severity), is.Category,
			firstNonEmpty(is.CWE, analyzer.CWEFor(is.RuleID)),
			firstNonEmpty(is.OWASP, analyzer.OWASPFor(is.RuleID)),
			is.File, strconv.Itoa(is.Line), is.Title, is.Recommendation,
		})
	}
	return w.Error()
}
