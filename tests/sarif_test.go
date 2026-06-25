package tests

import (
	"encoding/json"
	"testing"

	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/sarif"
)

func sampleIssues() []analyzer.Issue {
	return []analyzer.Issue{
		{RuleID: "SEC_TOKEN", Severity: analyzer.Critical, Category: "Security",
			Title: "Hardcoded key", File: "app/Model.php", Line: 7, Recommendation: "Rotate it"},
		{RuleID: "PERF_SELECT_STAR", Severity: analyzer.Medium, Category: "Performance",
			Title: "SELECT *", File: "app/Model.php", Line: 20, Recommendation: "Select columns"},
		{RuleID: "DEP_CVE", Severity: analyzer.High, Category: "Dependencies",
			Title: "pkg@1.0 — GHSA-x", File: "composer.lock", Line: 0, Recommendation: "Upgrade"},
	}
}

func TestSARIFGenerate(t *testing.T) {
	data, err := sarif.Generate(sampleIssues(), "0.9.0")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Must be valid JSON with the expected SARIF shape.
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "Observer" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d, want 3 (one per distinct ruleId)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}

	// Critical maps to error level with a high security-severity.
	for _, r := range run.Results {
		if r.RuleID == "SEC_TOKEN" {
			if r.Level != "error" {
				t.Errorf("SEC_TOKEN level = %q, want error", r.Level)
			}
			if loc := r.Locations[0].PhysicalLocation; loc.ArtifactLocation.URI != "app/Model.php" ||
				loc.Region == nil || loc.Region.StartLine != 7 {
				t.Errorf("SEC_TOKEN location wrong: %+v", loc)
			}
		}
		// CVE has line 0 -> region omitted.
		if r.RuleID == "DEP_CVE" && r.Locations[0].PhysicalLocation.Region != nil {
			t.Error("DEP_CVE should have no region (line 0)")
		}
	}
}
