package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/aipda/observer/internal/ai"
)

func sampleInput() ai.Input {
	return ai.Input{
		ProjectName: "booking-system",
		Stack:       []string{"PHP", "CodeIgniter 3", "MySQL"},
		Findings: []ai.Finding{
			{Source: "static", Severity: "Critical", Category: "Security",
				Title: "Hardcoded Stripe live secret key", Location: "BookingModel.php:7",
				Recommendation: "Rotate the key and load it from the environment."},
			{Source: "log", Severity: "High", Category: "Database",
				Title: "Lock wait timeout", Count: 250, Cause: "Long-running transactions."},
			{Source: "static", Severity: "Medium", Category: "Performance",
				Title: "SELECT * query", Location: "BookingModel.php:20"},
		},
	}
}

func TestLocalReport(t *testing.T) {
	e := &ai.Explainer{} // nil provider -> local mode
	rep, err := e.Explain(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("explain failed: %v", err)
	}
	if !strings.Contains(rep.Provider, "local") {
		t.Errorf("Provider = %q, want local mode", rep.Provider)
	}
	if len(rep.Insights) != 3 {
		t.Fatalf("insights = %d, want 3", len(rep.Insights))
	}
	// Critical must sort first.
	if rep.Insights[0].Severity != "Critical" {
		t.Errorf("first insight severity = %q, want Critical", rep.Insights[0].Severity)
	}
	// The high-severity log group's known cause must be carried through.
	foundCause := false
	for _, in := range rep.Insights {
		if strings.Contains(in.RootCause, "Long-running transactions") {
			foundCause = true
		}
	}
	if !foundCause {
		t.Error("expected the log finding's cause to appear in an insight")
	}
	if rep.Summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestLocalReportEnriched(t *testing.T) {
	in := ai.Input{
		ProjectName: "demo",
		Findings: []ai.Finding{
			{Source: "static", Severity: "High", Category: "Database",
				Title: "SQL injection", Location: "m.php:12", CWE: "CWE-89"},
		},
	}
	rep, _ := (&ai.Explainer{}).Explain(context.Background(), in)
	if len(rep.Insights) != 1 {
		t.Fatalf("insights = %d, want 1", len(rep.Insights))
	}
	in0 := rep.Insights[0]
	if in0.Exploit == "" || in0.Complexity == "" || in0.Effort == "" || in0.FixExample == "" {
		t.Errorf("CWE-89 insight not enriched: %+v", in0)
	}
	if !strings.Contains(in0.FixExample, "?") { // parameterized-query example
		t.Errorf("expected a parameterized-query fix example, got %q", in0.FixExample)
	}
}
