package doctor

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
)

type Tool struct {
	Name   string
	Status string
	Path   string
}

type Report struct {
	Version         string
	Edition         string
	OS              string
	Arch            string
	OfflineDefault  bool
	NetworkFeatures []string
	OptionalTooling []Tool
}

func Inspect(version, edition string) Report {
	report := Report{
		Version:         version,
		Edition:         edition,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		OfflineDefault:  true,
		NetworkFeatures: []string{"--cve", "--semgrep with auto/registry config", "--ai with OPENAI_API_KEY", "--email", "--slack", "--teams", "--webhook"},
	}
	for _, name := range []string{"git", "semgrep", "bandit", "gosec", "eslint"} {
		tool := Tool{Name: name, Status: "not found"}
		if path, err := exec.LookPath(name); err == nil {
			tool.Status = "available"
			tool.Path = path
		}
		report.OptionalTooling = append(report.OptionalTooling, tool)
	}
	report.OptionalTooling = append(report.OptionalTooling, Tool{
		Name:   "phpstan",
		Status: "project-local; checked during --phpstan scans",
	})
	return report
}

func WriteText(w io.Writer, report Report) {
	fmt.Fprintf(w, "Observer %s (%s)\n", report.Version, report.Edition)
	fmt.Fprintf(w, "Platform: %s/%s\n", report.OS, report.Arch)
	fmt.Fprintln(w, "Built-in analyzer: available (local heuristic rules)")
	fmt.Fprintln(w, "Default network behavior: offline; no telemetry or phone-home")
	fmt.Fprintln(w, "Enforced offline mode: observer analyze <path> --assert-offline")
	fmt.Fprintln(w, "Network-capable opt-ins:")
	for _, feature := range report.NetworkFeatures {
		fmt.Fprintf(w, "  - %s\n", feature)
	}
	fmt.Fprintln(w, "Optional local tools:")
	for _, tool := range report.OptionalTooling {
		if tool.Path == "" {
			fmt.Fprintf(w, "  - %-8s %s\n", tool.Name, tool.Status)
			continue
		}
		fmt.Fprintf(w, "  - %-8s %s (%s)\n", tool.Name, tool.Status, tool.Path)
	}
}
