// Package sarif renders analyzer findings as SARIF 2.1.0 (Phase 13).
//
// SARIF is the standard static-analysis interchange format. Uploading it to
// GitHub populates the Security tab and produces inline pull-request
// annotations automatically — so Observer integrates with CI without any
// GitHub-API code of its own.
package sarif

import (
	"encoding/json"
	"path/filepath"

	"github.com/aipda/observer/internal/analyzer"
)

const schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
const infoURI = "https://github.com/aipda/observer"

// Generate produces SARIF 2.1.0 JSON for the given issues.
func Generate(issues []analyzer.Issue, version string) ([]byte, error) {
	rulesByID := map[string]rule{}
	var ruleOrder []string
	var results []result

	for _, is := range issues {
		if _, ok := rulesByID[is.RuleID]; !ok {
			tags := []string{is.Category}
			cwe := is.CWE
			if cwe == "" {
				cwe = analyzer.CWEFor(is.RuleID)
			}
			if cwe != "" {
				tags = append(tags, cwe)
			}
			owasp := is.OWASP
			if owasp == "" {
				owasp = analyzer.OWASPFor(is.RuleID)
			}
			if owasp != "" {
				tags = append(tags, "OWASP "+owasp)
			}
			rulesByID[is.RuleID] = rule{
				ID:               is.RuleID,
				Name:             is.Title,
				ShortDescription: text{Text: is.Title},
				FullDescription:  text{Text: is.Explanation},
				Help:             text{Text: is.Recommendation},
				Properties: ruleProps{
					Tags:             tags,
					SecuritySeverity: securitySeverity(is.Severity),
				},
			}
			ruleOrder = append(ruleOrder, is.RuleID)
		}
		results = append(results, result{
			RuleID:  is.RuleID,
			Level:   level(is.Severity),
			Message: text{Text: is.Title + " — " + is.Recommendation},
			Locations: []location{{PhysicalLocation: physLoc{
				ArtifactLocation: artifact{URI: filepath.ToSlash(is.File)},
				Region:           regionFor(is.Line),
			}}},
		})
	}

	rules := make([]rule, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rules = append(rules, rulesByID[id])
	}

	doc := sarifDoc{
		Schema:  schemaURI,
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "Observer",
				InformationURI: infoURI,
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func level(s analyzer.Severity) string {
	switch s {
	case analyzer.Critical, analyzer.High:
		return "error"
	case analyzer.Medium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the numeric (CVSS-like) score GitHub uses to bucket
// findings in the Security tab.
func securitySeverity(s analyzer.Severity) string {
	switch s {
	case analyzer.Critical:
		return "9.5"
	case analyzer.High:
		return "8.0"
	case analyzer.Medium:
		return "5.0"
	default:
		return "2.0"
	}
}

func regionFor(line int) *region {
	if line <= 0 {
		return nil
	}
	return &region{StartLine: line}
}

// --- SARIF 2.1.0 types (subset) ---

type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}
type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}
type tool struct {
	Driver driver `json:"driver"`
}
type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Version        string `json:"version"`
	Rules          []rule `json:"rules"`
}
type rule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription text      `json:"shortDescription"`
	FullDescription  text      `json:"fullDescription"`
	Help             text      `json:"help"`
	Properties       ruleProps `json:"properties"`
}
type ruleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}
type text struct {
	Text string `json:"text"`
}
type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   text       `json:"message"`
	Locations []location `json:"locations"`
}
type location struct {
	PhysicalLocation physLoc `json:"physicalLocation"`
}
type physLoc struct {
	ArtifactLocation artifact `json:"artifactLocation"`
	Region           *region  `json:"region,omitempty"`
}
type artifact struct {
	URI string `json:"uri"`
}
type region struct {
	StartLine int `json:"startLine"`
}
