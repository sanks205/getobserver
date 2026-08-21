package server

import (
	"strings"

	"github.com/aipda/observer/internal/bandit"
	"github.com/aipda/observer/internal/detector"
	"github.com/aipda/observer/internal/eslint"
	"github.com/aipda/observer/internal/gosec"
	"github.com/aipda/observer/internal/phpstan"
	"github.com/aipda/observer/internal/semgrep"
)

// EngineSuggestion describes a local engine that is relevant to the scanned
// stack but not installed — shown to the user as an optional accuracy upgrade.
// Fields are exported so the dashboard JSON can serialize them.
type EngineSuggestion struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	Reason     string `json:"reason"`
	AutoConfig bool   `json:"auto_config"` // Observer will create the config file itself (PHPStan)
}

// recommendedEngines returns the local engines that are relevant to the detected
// stack but not available. Each engine's Available() is a cheap PATH/config
// check, so this never blocks and absence is skipped gracefully. None of the
// returned engines are mandatory — the user can always scan built-in only.
func recommendedEngines(root string, tech *detector.TechStack) []EngineSuggestion {
	langs := stackLanguages(tech)
	hasPHP := langs["php"] || hasFramework(tech, "Laravel")
	hasPy := langs["python"]
	hasGo := langs["go"]
	hasJS := langs["javascript"] || langs["typescript"]

	var out []EngineSuggestion

	// PHPStan + Larastan — type-aware null-safety (removes built-in false positives).
	// If the binary is absent, suggest installing it. If it's installed but has no
	// config yet, offer AutoConfig: Observer creates phpstan.neon itself during the
	// scan, so the user gets the accuracy boost with zero setup (no "composer require" nag).
	if hasPHP {
		if !phpstan.BinaryPresent(root) {
			out = append(out, EngineSuggestion{
				Name:    "PHPStan + Larastan",
				Command: "composer require --dev phpstan/phpstan larastan/larastan",
				Reason:  "Laravel/PHP project — type-aware analysis removes null-safety false positives the built-in check produces.",
			})
		} else if !phpstan.ConfigPresent(root) {
			out = append(out, EngineSuggestion{
				Name:       "PHPStan + Larastan",
				AutoConfig: true,
				Command:    "auto-configured by Observer",
				Reason:     "PHPStan is installed — Observer will auto-create phpstan.neon and run type-aware analysis to cut null-safety false positives.",
			})
		}
	}

	// Semgrep — multi-language security/taint (relevant for any project).
	if !semgrep.Available() {
		out = append(out, EngineSuggestion{
			Name:    "Semgrep",
			Command: "pip install semgrep",
			Reason:  "Deeper multi-language security analysis (XSS, SSRF, path traversal, deserialization).",
		})
	}

	if hasPy && !bandit.Available() {
		out = append(out, EngineSuggestion{
			Name:    "Bandit",
			Command: "pip install bandit",
			Reason:  "Python security pattern analysis.",
		})
	}

	if hasGo && !gosec.Available() {
		out = append(out, EngineSuggestion{
			Name:    "gosec",
			Command: "go install github.com/securego/gosec/v2/cmd/gosec@latest",
			Reason:  "Go security analysis.",
		})
	}

	if hasJS && !eslint.Available(root) {
		out = append(out, EngineSuggestion{
			Name:    "ESLint",
			Command: "npm install -g eslint",
			Reason:  "JavaScript/TypeScript lint + security rules.",
		})
	}

	return out
}

func stackLanguages(tech *detector.TechStack) map[string]bool {
	set := map[string]bool{}
	if tech == nil {
		return set
	}
	for _, l := range tech.Languages {
		set[strings.ToLower(l.Name)] = true
	}
	return set
}

func hasFramework(tech *detector.TechStack, name string) bool {
	if tech == nil {
		return false
	}
	for _, f := range tech.Frameworks {
		if strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}
