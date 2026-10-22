// Package auditrun tracks enabled external-engine outcomes for a scan.
package auditrun

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aipda/observer/internal/attest"
)

var supported = map[string]bool{
	"semgrep": true,
	"phpstan": true,
	"bandit":  true,
	"gosec":   true,
	"eslint":  true,
}

// Required is the normalized set supplied through --require-engine.
type Required map[string]bool

// ParseRequired validates a comma-separated required-engine policy.
func ParseRequired(raw string) (Required, error) {
	out := Required{}
	for _, value := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(value))
		if name == "" {
			continue
		}
		if !supported[name] {
			return nil, fmt.Errorf("unsupported required engine %q (supported: bandit, eslint, gosec, phpstan, semgrep)", name)
		}
		out[name] = true
	}
	return out, nil
}

// Names returns required engine names in stable order.
func (r Required) Names() []string {
	out := make([]string, 0, len(r))
	for name := range r {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Has reports whether an engine is mandatory for this scan.
func (r Required) Has(name string) bool { return r[strings.ToLower(name)] }

// Tracker records outcomes in execution order.
type Tracker struct {
	required Required
	outcomes []attest.EngineOutcome
}

func New(required Required) *Tracker {
	return &Tracker{required: required}
}

func (t *Tracker) Record(name, status, detail string) {
	t.record(name, status, detail, t.required.Has(name))
}

// RecordRequired records an enabled phase that is mandatory whenever requested.
func (t *Tracker) RecordRequired(name, status, detail string) {
	t.record(name, status, detail, true)
}

func (t *Tracker) record(name, status, detail string, required bool) {
	name = strings.ToLower(name)
	t.outcomes = append(t.outcomes, attest.EngineOutcome{Name: name, Status: status, Required: required, Detail: detail})
}

func (t *Tracker) Outcomes() []attest.EngineOutcome {
	return append([]attest.EngineOutcome(nil), t.outcomes...)
}

// Incomplete is true when any required engine did not complete.
func (t *Tracker) Incomplete() bool {
	seen := map[string]string{}
	for _, outcome := range t.outcomes {
		seen[outcome.Name] = outcome.Status
		if outcome.Required && outcome.Status != "completed" {
			return true
		}
	}
	for name := range t.required {
		if seen[name] != "completed" {
			return true
		}
	}
	return false
}
