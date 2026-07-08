// Command observer is the CLI for the AI Production Debugging Assistant.
//
// Phase 1 provides a single subcommand:
//
//	observer analyze <project-path> [--out report.html]
//
// It scans a project directory and generates an HTML project-analysis report.
// Future phases add `analyze-log`, runtime collection, and AI recommendations,
// all routed through this same command dispatcher.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aipda/observer/internal/ai"
	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/bandit"
	"github.com/aipda/observer/internal/baseline"
	"github.com/aipda/observer/internal/deps"
	"github.com/aipda/observer/internal/detector"
	"github.com/aipda/observer/internal/email"
	"github.com/aipda/observer/internal/gosec"
	"github.com/aipda/observer/internal/logger"
	"github.com/aipda/observer/internal/notify"
	"github.com/aipda/observer/internal/phpstan"
	"github.com/aipda/observer/internal/reporter"
	"github.com/aipda/observer/internal/runtime"
	"github.com/aipda/observer/internal/sarif"
	"github.com/aipda/observer/internal/scanner"
	"github.com/aipda/observer/internal/semgrep"
	"github.com/aipda/observer/internal/server"
	"github.com/aipda/observer/internal/storage"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "analyze":
		os.Exit(runAnalyze(os.Args[2:]))
	case "analyze-log":
		os.Exit(runAnalyzeLog(os.Args[2:]))
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("observer %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func runAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	out := fs.String("out", "report.html", "output path for the HTML report")
	runtimePath := fs.String("runtime", "", "path to observer-agent runtime events (JSONL file or directory)")
	logsPath := fs.String("logs", "", "path to application logs to analyze (file or directory)")
	useAI := fs.Bool("ai", false, "generate AI explanations of findings (uses OpenAI if OPENAI_API_KEY is set, else a local heuristic)")
	emailTo := fs.String("email", "", "email the report to these recipients (comma-separated); SMTP_* env vars configure the server")
	categoriesFlag := fs.String("categories", "", "only report these categories (comma-separated; default all): "+strings.Join(analyzer.AllCategories, ", "))
	minSevFlag := fs.String("min-severity", "", "minimum severity to report: Low|Medium|High|Critical (default: all)")
	cveFlag := fs.Bool("cve", false, "scan dependencies for known vulnerabilities via OSV.dev (requires network)")
	semgrepFlag := fs.Bool("semgrep", false, "also run Semgrep if installed, for deeper multi-language detection (auto-skips if absent)")
	phpstanFlag := fs.Bool("phpstan", false, "also run the project's PHPStan if present (vendor/bin/phpstan + phpstan.neon) for deeper PHP analysis")
	banditFlag := fs.Bool("bandit", false, "also run Bandit if installed, for Python security analysis (auto-skips if absent)")
	gosecFlag := fs.Bool("gosec", false, "also run gosec if installed, for Go security analysis (auto-skips if absent)")
	sarifFlag := fs.String("sarif", "", "also write findings as SARIF to this file (for GitHub code scanning / CI)")
	jsonFlag := fs.String("json", "", "also write findings + scores as JSON to this file")
	csvFlag := fs.String("csv", "", "also write findings as CSV (Excel-compatible) to this file")
	disableFlag := fs.String("disable", "", "comma-separated rule IDs to ignore (e.g. PERF_SELECT_STAR,PHP_SUPERGLOBAL_INPUT)")
	slackFlag := fs.String("slack", "", "post a summary to this Slack incoming-webhook URL (or set SLACK_WEBHOOK)")
	teamsFlag := fs.String("teams", "", "post a summary to this Microsoft Teams webhook URL (or set TEAMS_WEBHOOK)")
	webhookFlag := fs.String("webhook", "", "POST the JSON report to this generic webhook URL")
	failOn := fs.String("fail-on", "", "exit non-zero if any finding is at/above this severity: Low|Medium|High|Critical")
	baselineFile := fs.String("baseline", "", "suppress findings recorded in this baseline file (report only new issues)")
	writeBaseline := fs.String("write-baseline", "", "write the current findings to this baseline file and exit-code 0")
	assertOffline := fs.Bool("assert-offline", false, "guarantee no network I/O: refuse network flags (--cve/--email/--slack/--teams/--webhook) and force AI to the local heuristic")

	// Parse flags that precede the project path. flag.Parse stops at the first
	// non-flag token, so we then take that token as the path and re-parse the
	// remainder — this lets the path appear before OR after flags.
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "error: missing project path")
		fmt.Fprintln(os.Stderr, "usage: observer analyze <project-path> [--out report.html]")
		return 1
	}
	target := rest[0]
	if len(rest) > 1 {
		_ = fs.Parse(rest[1:])
	}

	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot access %q: %v\n", target, err)
		return 1
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %q is not a directory\n", target)
		return 1
	}

	// Air-gapped guarantee: fail fast if any network-requiring option was asked
	// for, and force the AI layer to its local (offline) heuristic. Observer is
	// already offline by default — this flag makes that contract enforceable for
	// regulated / air-gapped environments.
	if *assertOffline {
		var netFlags []string
		if *cveFlag {
			netFlags = append(netFlags, "--cve")
		}
		if *emailTo != "" {
			netFlags = append(netFlags, "--email")
		}
		if *slackFlag != "" {
			netFlags = append(netFlags, "--slack")
		}
		if *teamsFlag != "" {
			netFlags = append(netFlags, "--teams")
		}
		if *webhookFlag != "" {
			netFlags = append(netFlags, "--webhook")
		}
		if len(netFlags) > 0 {
			fmt.Fprintf(os.Stderr, "error: --assert-offline forbids network operations, but these were requested: %s\n", strings.Join(netFlags, ", "))
			return 1
		}
		if os.Getenv("OPENAI_API_KEY") != "" {
			_ = os.Unsetenv("OPENAI_API_KEY") // force the AI layer to the local heuristic
			fmt.Println("Offline mode: ignoring OPENAI_API_KEY — AI will use the local heuristic.")
		}
		fmt.Println("Offline mode: no network I/O.")
	}

	// Set OBSERVER_TIMING=1 to print per-phase timing to stderr.
	timing := os.Getenv("OBSERVER_TIMING") != ""
	timed := func(label string, start time.Time) {
		if timing {
			fmt.Fprintf(os.Stderr, "[timing] %-9s %v\n", label+":", time.Since(start))
		}
	}

	fmt.Printf("Scanning %s ...\n", target)
	t0 := time.Now()
	res, err := scanner.Scan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 1
	}
	timed("scan", t0)

	// Phase 2 — technology detection. A detection failure should not abort the
	// scan report, so we warn and continue with a nil stack.
	t1 := time.Now()
	tech, err := detector.Detect(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: technology detection failed: %v\n", err)
		tech = nil
	}
	timed("detect", t1)

	// Phase 3 — static analysis. Non-fatal on error.
	t2 := time.Now()
	analysis, err := analyzer.Analyze(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: static analysis failed: %v\n", err)
		analysis = nil
	}
	timed("analyze", t2)

	// Phase 12 — dependency CVE scan (opt-in via --cve; network). Findings are
	// merged into the Dependencies category so filters and the report cover them.
	if *cveFlag && analysis != nil {
		if rep, err := deps.Scan(target, deps.NewClient()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: CVE scan failed: %v\n", err)
		} else {
			var issues []analyzer.Issue
			for _, v := range rep.Vulns {
				issues = append(issues, analyzer.Issue{
					RuleID: "DEP_CVE", Severity: analyzer.Severity(v.Severity), Category: "Dependencies",
					Title: fmt.Sprintf("%s@%s — %s", v.Package, v.Version, v.ID), File: v.Source,
					Explanation:    orDefault(v.Summary, "Known vulnerability in a dependency."),
					Recommendation: fmt.Sprintf("Review advisory %s and upgrade %s.", v.ID, v.Package),
				})
			}
			analysis.AddIssues(issues...)
			fmt.Fprintf(os.Stderr, "CVE scan: %d dependencies checked, %d vulnerability(ies) found\n", rep.DepsScanned, len(rep.Vulns))
		}
	}

	// Theme 1 — optional Semgrep engine (opt-in via --semgrep; auto-skips if not installed).
	if *semgrepFlag && analysis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		findings, err := semgrep.Scan(ctx, target, os.Getenv("SEMGREP_CONFIG"))
		cancel()
		switch {
		case errors.Is(err, semgrep.ErrNotAvailable):
			fmt.Fprintln(os.Stderr, "note: --semgrep set but semgrep is not installed; skipping (see https://semgrep.dev)")
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: semgrep run failed: %v\n", err)
		default:
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the Semgrep finding and remediate.",
					CWE: f.CWE, OWASP: f.OWASP,
				})
			}
			analysis.AddIssues(issues...)
			fmt.Fprintf(os.Stderr, "Semgrep: %d additional finding(s)\n", len(issues))
		}
	}

	// Theme 1 — optional PHPStan engine (opt-in via --phpstan; uses the project's
	// own PHPStan + config; auto-skips if not present).
	if *phpstanFlag && analysis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		findings, err := phpstan.Scan(ctx, target)
		cancel()
		switch {
		case errors.Is(err, phpstan.ErrNotAvailable):
			fmt.Fprintln(os.Stderr, "note: --phpstan set but PHPStan isn't installed in the project (vendor/bin/phpstan); skipping (see https://phpstan.org)")
		case errors.Is(err, phpstan.ErrNoConfig):
			fmt.Fprintln(os.Stderr, "note: --phpstan set but no phpstan.neon(.dist) config found in the project; skipping")
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: phpstan run failed: %v\n", err)
		default:
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line,
					Explanation: f.Message, Recommendation: "Review the PHPStan finding and fix the reported issue.",
				})
			}
			analysis.AddIssues(issues...)
			fmt.Fprintf(os.Stderr, "PHPStan: %d additional finding(s)\n", len(issues))
		}
	}

	// Theme 1 — optional Bandit engine (opt-in via --bandit; Python security; auto-skips if not installed).
	if *banditFlag && analysis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		findings, err := bandit.Scan(ctx, target)
		cancel()
		switch {
		case errors.Is(err, bandit.ErrNotAvailable):
			fmt.Fprintln(os.Stderr, "note: --bandit set but Bandit isn't installed; skipping (pip install bandit)")
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: bandit run failed: %v\n", err)
		default:
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the Bandit finding and remediate.",
					CWE: f.CWE,
				})
			}
			analysis.AddIssues(issues...)
			fmt.Fprintf(os.Stderr, "Bandit: %d additional finding(s)\n", len(issues))
		}
	}

	// Theme 1 — optional gosec engine (opt-in via --gosec; Go security; auto-skips if not installed).
	if *gosecFlag && analysis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		findings, err := gosec.Scan(ctx, target)
		cancel()
		switch {
		case errors.Is(err, gosec.ErrNotAvailable):
			fmt.Fprintln(os.Stderr, "note: --gosec set but gosec isn't installed; skipping (https://github.com/securego/gosec)")
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: gosec run failed: %v\n", err)
		default:
			var issues []analyzer.Issue
			for _, f := range findings {
				issues = append(issues, analyzer.Issue{
					RuleID: f.RuleID, Severity: analyzer.Severity(f.Severity), Category: f.Category,
					Title: f.Title, File: f.File, Line: f.Line, Snippet: f.Snippet,
					Explanation: f.Message, Recommendation: "Review the gosec finding and remediate.",
					CWE: f.CWE,
				})
			}
			analysis.AddIssues(issues...)
			fmt.Fprintf(os.Stderr, "gosec: %d additional finding(s)\n", len(issues))
		}
	}

	// Apply the chosen scan scope (categories + minimum severity) before the
	// findings flow into AI, console, and the report.
	if analysis != nil && (*categoriesFlag != "" || *minSevFlag != "") {
		allowed := map[string]bool{}
		for _, c := range strings.Split(*categoriesFlag, ",") {
			if c = strings.TrimSpace(c); c != "" {
				allowed[c] = true
			}
		}
		analysis = analyzer.Filter(analysis, allowed, analyzer.ParseSeverity(*minSevFlag))
	}

	// Theme 4 — per-rule ignore (suppress specific rule IDs entirely).
	if analysis != nil && *disableFlag != "" {
		disabled := map[string]bool{}
		for _, id := range strings.Split(*disableFlag, ",") {
			if id = strings.TrimSpace(id); id != "" {
				disabled[id] = true
			}
		}
		if len(disabled) > 0 {
			analysis = analysis.Keep(func(is analyzer.Issue) bool { return !disabled[is.RuleID] })
		}
	}

	// Phase 13 — baseline suppression ("report only new issues").
	baselineApplied, baselineSuppressed, baselineNew := false, 0, 0
	if analysis != nil && *baselineFile != "" {
		if set, err := baseline.Load(*baselineFile); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not load baseline: %v\n", err)
		} else {
			before := len(analysis.Issues)
			analysis = baseline.Apply(analysis, set)
			baselineApplied = true
			baselineSuppressed = before - len(analysis.Issues)
			baselineNew = len(analysis.Issues)
			fmt.Printf("Baseline applied: suppressed %d known finding(s), %d new\n", baselineSuppressed, baselineNew)
		}
	}

	// Phase 13 — compute the quality-gate result once (reused for the report
	// banner and the exit code).
	gateEnabled := *failOn != ""
	gateFailCount := 0
	if gateEnabled && analysis != nil {
		gateFailCount = analyzer.CountAtLeast(analysis, analyzer.ParseSeverity(*failOn))
	}
	scanMs := time.Since(t0).Milliseconds()

	// Phase 4 — runtime errors captured by observer-agent (opt-in via --runtime).
	var rtSummary *runtime.Summary
	if *runtimePath != "" {
		events, err := runtime.Load(*runtimePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not load runtime events: %v\n", err)
		} else {
			rtSummary = runtime.Summarize(events)
		}
	}

	// Phase 5 — application log analysis (opt-in via --logs).
	var logSummary *logger.Summary
	if *logsPath != "" {
		logSummary, err = logger.Analyze(*logsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not analyze logs: %v\n", err)
			logSummary = nil
		}
	}

	// Phase 6 — AI explanation of the collected findings (opt-in via --ai).
	var aiReport *ai.Report
	if *useAI {
		aiReport = runAI(res, tech, analysis, rtSummary, logSummary)
	}

	printSummary(res, tech)
	printIssues(analysis)
	printRuntime(rtSummary)
	printLogs(logSummary)
	printAI(aiReport)

	outPath, _ := filepath.Abs(*out)
	data := reporter.Data{
		Scan: res, Tech: tech, Analysis: analysis, Runtime: rtSummary, Logs: logSummary,
		AI: aiReport, DurationMs: scanMs,
		BaselineApplied: baselineApplied, BaselineSuppressed: baselineSuppressed, BaselineNew: baselineNew,
		GateEnabled: gateEnabled, GateThreshold: *failOn, GateFailCount: gateFailCount,
	}
	if err := reporter.GenerateHTML(data, *out); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write report: %v\n", err)
		return 1
	}
	fmt.Printf("\nReport written to %s\n", outPath)

	// Phase 13 — SARIF output for GitHub code scanning / CI.
	if *sarifFlag != "" && analysis != nil {
		if data, err := sarif.Generate(analysis.Issues, version); err != nil {
			fmt.Fprintf(os.Stderr, "warning: SARIF generation failed: %v\n", err)
		} else if err := os.WriteFile(*sarifFlag, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: writing SARIF failed: %v\n", err)
		} else {
			fmt.Printf("SARIF written to %s\n", *sarifFlag)
		}
	}

	// Phase 13.5/Theme 5 — JSON and CSV (Excel-compatible) exports.
	if *jsonFlag != "" {
		if err := reporter.GenerateJSON(data, *jsonFlag); err != nil {
			fmt.Fprintf(os.Stderr, "warning: JSON export failed: %v\n", err)
		} else {
			fmt.Printf("JSON written to %s\n", *jsonFlag)
		}
	}
	if *csvFlag != "" {
		if err := reporter.GenerateCSV(data, *csvFlag); err != nil {
			fmt.Fprintf(os.Stderr, "warning: CSV export failed: %v\n", err)
		} else {
			fmt.Printf("CSV written to %s\n", *csvFlag)
		}
	}

	// Theme 2 polish — Slack / Teams / generic webhook notifications (opt-in).
	sendNotifications(data, analysis,
		orDefault(*slackFlag, os.Getenv("SLACK_WEBHOOK")),
		orDefault(*teamsFlag, os.Getenv("TEAMS_WEBHOOK")),
		*webhookFlag)

	// Phase 13 — write a baseline of the current findings (setup step; never fails the gate).
	if *writeBaseline != "" && analysis != nil {
		if n, err := baseline.Write(*writeBaseline, analysis.Issues); err != nil {
			fmt.Fprintf(os.Stderr, "warning: writing baseline failed: %v\n", err)
		} else {
			fmt.Printf("Baseline written to %s (%d finding(s))\n", *writeBaseline, n)
		}
		return 0
	}

	// Phase 8 — email the report (opt-in via --email).
	if *emailTo != "" {
		if err := emailReport(*emailTo, outPath, res, analysis, aiReport); err != nil {
			fmt.Fprintf(os.Stderr, "warning: email not sent: %v\n", err)
		}
	}

	// Phase 13 — CI quality gate (reuses the count computed above).
	if gateEnabled && gateFailCount > 0 {
		fmt.Fprintf(os.Stderr, "Quality gate failed: %d finding(s) at or above %s severity\n", gateFailCount, *failOn)
		return 2
	}
	return 0
}

// emailReport composes a summary, attaches the HTML report, and sends it (or
// writes a .eml in dry-run mode). SMTP settings come from SMTP_* env vars.
func emailReport(recipients, reportPath string, res *scanner.Result, a *analyzer.Result, aiRep *ai.Report) error {
	cfg := email.ConfigFromEnv()
	cfg.To = email.ParseRecipients(recipients)
	if cfg.DryRun {
		cfg.DryRunPath = reportPath + ".eml"
	}

	body, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	subject, htmlBody := emailSummary(res, a, aiRep)

	msg := email.Message{
		Subject:  subject,
		HTMLBody: htmlBody,
		Attachment: &email.Attachment{
			Filename: filepath.Base(reportPath),
			Data:     body,
			MIME:     "text/html",
		},
	}
	if err := email.Send(cfg, msg); err != nil {
		return err
	}
	if cfg.DryRun {
		fmt.Printf("Email composed (dry-run) -> %s\n", cfg.DryRunPath)
	} else {
		fmt.Printf("Report emailed to %s\n", strings.Join(cfg.To, ", "))
	}
	return nil
}

// emailSummary builds the subject and concise HTML body for the email.
func emailSummary(res *scanner.Result, a *analyzer.Result, aiRep *ai.Report) (subject, htmlBody string) {
	var total, crit, high int
	if a != nil {
		total = len(a.Issues)
		crit = a.BySeverity[analyzer.Critical]
		high = a.BySeverity[analyzer.High]
	}
	subject = fmt.Sprintf("Observer report: %s — %d issue(s), %d critical, %d high", res.ProjectName, total, crit, high)

	var b strings.Builder
	b.WriteString("<h2>Observer — Production Health Report</h2>")
	b.WriteString(fmt.Sprintf("<p><strong>Project:</strong> %s<br><strong>Language:</strong> %s</p>", res.ProjectName, res.DominantLang))
	b.WriteString(fmt.Sprintf("<p><strong>Findings:</strong> %d total — %d critical, %d high</p>", total, crit, high))
	if aiRep != nil && aiRep.Summary != "" {
		b.WriteString("<p><strong>Summary:</strong> " + aiRep.Summary + "</p>")
	}
	if a != nil && len(a.Issues) > 0 {
		b.WriteString("<p><strong>Top issues:</strong></p><ul>")
		for i, is := range a.Issues {
			if i >= 5 {
				break
			}
			b.WriteString(fmt.Sprintf("<li>[%s] %s — %s:%d</li>", is.Severity, is.Title, is.File, is.Line))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("<p>The full interactive report is attached.</p>")
	return subject, b.String()
}

func printSummary(res *scanner.Result, tech *detector.TechStack) {
	fmt.Printf("\nProject:   %s\n", res.ProjectName)
	fmt.Printf("Language:  %s\n", res.DominantLang)

	if tech != nil {
		printFindings("Framework", tech.Frameworks)
		printFindings("Database", tech.Databases)
		printFindings("Infra", tech.Infrastructure)
	}

	fmt.Printf("\nFiles:       %d\n", res.TotalFiles)
	fmt.Printf("Directories: %d\n", res.TotalDirs)
	if len(res.Categories) > 0 {
		fmt.Println("\nCode structure:")
		for _, c := range []scanner.Category{
			scanner.CategoryController, scanner.CategoryModel, scanner.CategoryService,
			scanner.CategoryView, scanner.CategoryMigration, scanner.CategoryConfig, scanner.CategoryTest,
		} {
			if n, ok := res.Categories[c]; ok {
				fmt.Printf("  %-12s %d\n", string(c)+":", n)
			}
		}
	}
}

// consoleIssueLimit caps how many findings are listed on the console; the full
// set is always written to the HTML report.
const consoleIssueLimit = 25

// printIssues prints the static-analysis summary and a capped list of findings.
func printIssues(a *analyzer.Result) {
	if a == nil {
		return
	}
	secScore, secGrade := analyzer.SecurityScore(a)
	hScore, hGrade := analyzer.HealthScore(a)
	fmt.Printf("\nSecurity score: %d/100 (%s)   Code health: %d/100 (%s)\n", secScore, secGrade, hScore, hGrade)
	mins := analyzer.RemediationMinutes(a)
	fmt.Printf("Static analysis: %d issue(s) in %d source file(s)   Est. fix effort: ~%dh %dm\n",
		len(a.Issues), a.FilesScanned, mins/60, mins%60)
	if len(a.Issues) == 0 {
		return
	}
	for _, s := range []analyzer.Severity{analyzer.Critical, analyzer.High, analyzer.Medium, analyzer.Low} {
		if n := a.BySeverity[s]; n > 0 {
			fmt.Printf("  %-9s %d\n", string(s)+":", n)
		}
	}
	fmt.Println()
	for i, is := range a.Issues {
		if i >= consoleIssueLimit {
			fmt.Printf("  ... and %d more (see HTML report)\n", len(a.Issues)-consoleIssueLimit)
			break
		}
		fmt.Printf("  [%-8s] %s:%d  %s\n", is.Severity, is.File, is.Line, is.Title)
	}
}

// maxAIFindings caps how many findings are sent to the AI layer, keeping the
// prompt small. Findings are pre-sorted by severity so the most important ones
// are kept.
const maxAIFindings = 40

// runAI adapts findings from every source into ai.Finding, selects a provider
// (OpenAI when OPENAI_API_KEY is set, otherwise the local heuristic), and
// returns an explanation report. It always returns a usable report: on any
// provider error it falls back to the local mode.
func runAI(res *scanner.Result, tech *detector.TechStack, a *analyzer.Result,
	rt *runtime.Summary, logs *logger.Summary) *ai.Report {

	in := ai.Input{
		ProjectName: res.ProjectName,
		Stack:       stackNames(tech),
		Findings:    gatherFindings(a, rt, logs),
	}

	var provider ai.Provider
	if key := os.Getenv("OPENAI_API_KEY"); key != "" && os.Getenv("OBSERVER_AI_PROVIDER") != "local" {
		provider = ai.NewOpenAI(key, os.Getenv("OPENAI_MODEL"), os.Getenv("OPENAI_BASE_URL"))
	}

	explainer := &ai.Explainer{Provider: provider}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	rep, err := explainer.Explain(ctx, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: AI provider failed (%v); using local heuristic\n", err)
		return ai.LocalReport(in)
	}
	return rep
}

// gatherFindings normalizes findings from each source into ai.Finding.
func gatherFindings(a *analyzer.Result, rt *runtime.Summary, logs *logger.Summary) []ai.Finding {
	var out []ai.Finding

	if a != nil {
		limit := len(a.Issues)
		if limit > 20 {
			limit = 20 // issues are severity-sorted; keep the top ones
		}
		for _, is := range a.Issues[:limit] {
			cwe := is.CWE
			if cwe == "" {
				cwe = analyzer.CWEFor(is.RuleID)
			}
			out = append(out, ai.Finding{
				Source: "static", Severity: string(is.Severity), Category: is.Category,
				Title: is.Title, Location: fmt.Sprintf("%s:%d", is.File, is.Line),
				Detail: is.Explanation, Recommendation: is.Recommendation, CWE: cwe,
			})
		}
	}
	if rt != nil {
		for _, g := range rt.Groups {
			loc := g.File
			if g.Line > 0 {
				loc = fmt.Sprintf("%s:%d", g.File, g.Line)
			}
			out = append(out, ai.Finding{
				Source: "runtime", Severity: mapRuntimeSeverity(g.Severity), Category: "Runtime",
				Title: g.Type, Location: loc, Detail: g.LastMessage, Count: g.Count,
			})
		}
	}
	if logs != nil {
		for _, g := range logs.Groups {
			out = append(out, ai.Finding{
				Source: "log", Severity: mapLogSeverity(g.Level), Category: g.Category,
				Title: g.Sample, Detail: g.Sample, Cause: g.Cause, Count: g.Count,
			})
		}
	}

	if len(out) > maxAIFindings {
		out = out[:maxAIFindings]
	}
	return out
}

func stackNames(tech *detector.TechStack) []string {
	if tech == nil {
		return nil
	}
	var names []string
	add := func(fs []detector.Finding) {
		for _, f := range fs {
			names = append(names, f.Name)
		}
	}
	add(tech.Languages)
	add(tech.Frameworks)
	add(tech.Databases)
	add(tech.Infrastructure)
	return names
}

func mapRuntimeSeverity(s string) string {
	switch s {
	case "fatal":
		return "Critical"
	case "error":
		return "High"
	case "warning":
		return "Medium"
	}
	return "Medium"
}

func mapLogSeverity(level string) string {
	switch level {
	case "EMERGENCY", "ALERT", "CRITICAL", "FATAL":
		return "Critical"
	case "ERROR", "EXCEPTION":
		return "High"
	case "WARNING":
		return "Medium"
	}
	return "Low"
}

// printAI prints a brief AI summary and the suggested fix priority.
func printAI(rep *ai.Report) {
	if rep == nil {
		return
	}
	fmt.Printf("\nAI analysis (%s):\n", rep.Provider)
	fmt.Printf("  %s\n", rep.Summary)
	if len(rep.Priorities) > 0 {
		fmt.Println("  Suggested fix priority:")
		for i, p := range rep.Priorities {
			fmt.Printf("    %d. %s\n", i+1, p)
		}
	}
}

// runServe implements `observer serve`: start the local web dashboard.
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:7777", "address to listen on")
	dataDir := fs.String("data", "", "directory to store scans (default: user config dir)")
	_ = fs.Parse(args)

	store, err := storage.New(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open data store: %v\n", err)
		return 1
	}
	srv := server.New(store)

	fmt.Printf("Observer dashboard running at http://%s\n", *addr)
	fmt.Printf("Storing scans in %s\n", store.Dir())
	fmt.Println("Press Ctrl+C to stop.")

	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		fmt.Fprintf(os.Stderr, "error: server stopped: %v\n", err)
		return 1
	}
	return 0
}

// runAnalyzeLog implements `observer analyze-log <path>`: parse application
// logs and print a summary of the most common errors.
func runAnalyzeLog(args []string) int {
	fs := flag.NewFlagSet("analyze-log", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: missing log path")
		fmt.Fprintln(os.Stderr, "usage: observer analyze-log <file-or-directory>")
		return 1
	}
	target := fs.Arg(0)

	if _, err := os.Stat(target); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot access %q: %v\n", target, err)
		return 1
	}

	fmt.Printf("Analyzing logs in %s ...\n", target)
	summary, err := logger.Analyze(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: log analysis failed: %v\n", err)
		return 1
	}
	printLogs(summary)
	return 0
}

// printLogs prints the log-analysis summary in the spec's "most common issue"
// style, followed by the next most frequent issues.
func printLogs(s *logger.Summary) {
	if s == nil {
		return
	}
	fmt.Printf("\nLog analysis: %d error line(s) across %d file(s)\n", s.TotalErrors, s.FilesParsed)
	if len(s.Groups) == 0 {
		fmt.Println("  No error-level entries found.")
		return
	}

	top := s.Groups[0]
	fmt.Printf("\nMost common issue: %s\n", top.Sample)
	fmt.Printf("Occurrences:       %d\n", top.Count)
	if top.Cause != "" {
		fmt.Printf("Possible cause:    %s\n", top.Cause)
	}

	if len(s.Groups) > 1 {
		fmt.Println("\nOther frequent issues:")
		limit := 10
		for i, g := range s.Groups[1:] {
			if i >= limit {
				fmt.Printf("  ... and %d more (see HTML report)\n", len(s.Groups)-1-limit)
				break
			}
			fmt.Printf("  %5dx [%s/%s] %s\n", g.Count, g.Level, g.Category, g.Sample)
		}
	}
}

// sendNotifications posts a scan summary to any configured endpoints. Failures
// warn but never abort.
func sendNotifications(data reporter.Data, a *analyzer.Result, slackURL, teamsURL, webhookURL string) {
	if slackURL == "" && teamsURL == "" && webhookURL == "" {
		return
	}
	sum := buildNotifySummary(data, a)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if slackURL != "" {
		post("Slack", ctx, slackURL, notify.SlackPayload(sum))
	}
	if teamsURL != "" {
		post("Teams", ctx, teamsURL, notify.TeamsPayload(sum))
	}
	if webhookURL != "" {
		if b, err := reporter.JSONBytes(data); err != nil {
			fmt.Fprintf(os.Stderr, "warning: webhook payload build failed: %v\n", err)
		} else {
			post("webhook", ctx, webhookURL, b)
		}
	}
}

func post(name string, ctx context.Context, url string, payload []byte) {
	if err := notify.Post(ctx, url, payload); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s notification failed: %v\n", name, err)
	} else {
		fmt.Printf("Posted summary to %s\n", name)
	}
}

func buildNotifySummary(data reporter.Data, a *analyzer.Result) notify.Summary {
	s := notify.Summary{Project: data.Scan.ProjectName}
	if a != nil {
		s.SecurityScore, s.SecurityGrade = analyzer.SecurityScore(a)
		s.HealthScore, s.HealthGrade = analyzer.HealthScore(a)
		s.Total = len(a.Issues)
		s.Critical = a.BySeverity[analyzer.Critical]
		s.High = a.BySeverity[analyzer.High]
		s.Medium = a.BySeverity[analyzer.Medium]
		s.Low = a.BySeverity[analyzer.Low]
		for i, is := range a.Issues {
			if i >= 5 {
				break
			}
			s.TopIssues = append(s.TopIssues, fmt.Sprintf("[%s] %s — %s:%d", is.Severity, is.Title, is.File, is.Line))
		}
	}
	return s
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// printRuntime prints a summary of captured runtime errors.
func printRuntime(s *runtime.Summary) {
	if s == nil {
		return
	}
	fmt.Printf("\nRuntime errors: %d event(s), %d distinct signature(s)\n", s.Total, len(s.Groups))
	limit := 10
	for i, g := range s.Groups {
		if i >= limit {
			fmt.Printf("  ... and %d more (see HTML report)\n", len(s.Groups)-limit)
			break
		}
		loc := g.File
		if g.Line > 0 {
			loc = fmt.Sprintf("%s:%d", g.File, g.Line)
		}
		fmt.Printf("  %4dx  %s  %s\n", g.Count, g.Type, loc)
	}
}

// printFindings prints one labeled line per detected technology, e.g.
//
//	Framework: CodeIgniter 3 3.1.11 [High]
func printFindings(label string, findings []detector.Finding) {
	for _, f := range findings {
		ver := ""
		if f.Version != "" {
			ver = " " + f.Version
		}
		fmt.Printf("%-10s %s%s [%s]\n", label+":", f.Name, ver, f.Confidence)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `observer %s — AI Production Debugging Assistant

Usage:
  observer analyze <project-path> [flags]   Scan a project, emit an HTML report
      --out <file>        output path for the HTML report (default report.html)
      --runtime <path>    include observer-agent runtime events (JSONL file or dir)
      --logs <path>       include application log analysis (file or dir)
      --ai                add AI explanations (OpenAI if OPENAI_API_KEY set, else local heuristic)
      --email <to>        email the report (comma-separated); configure via SMTP_* env vars
      --categories <list> only report these categories (comma-separated; default all)
      --min-severity <s>  minimum severity to report: Low|Medium|High|Critical (default all)
      --disable <rules>   comma-separated rule IDs to ignore entirely
      --slack <url>       post a summary to a Slack incoming webhook (or SLACK_WEBHOOK env)
      --teams <url>       post a summary to a Microsoft Teams webhook (or TEAMS_WEBHOOK env)
      --webhook <url>     POST the JSON report to a generic webhook
      --cve               scan dependencies for known vulnerabilities (OSV.dev; needs network)
      --semgrep           also run Semgrep if installed (deeper, multi-language detection)
      --phpstan           also run the project's PHPStan (vendor/bin/phpstan + phpstan.neon)
      --bandit            also run Bandit if installed (Python security analysis)
      --gosec             also run gosec if installed (Go security analysis)
      --sarif <file>      also write findings as SARIF (GitHub code scanning / CI)
      --json <file>       also write findings + scores as JSON
      --csv <file>        also write findings as CSV (opens in Excel)
      --fail-on <sev>     exit non-zero if any finding >= severity (CI quality gate)
      --baseline <file>   suppress known findings; report only new issues
      --write-baseline <file>  record current findings as the baseline, then exit
      --assert-offline    guarantee no network I/O (refuse --cve/--email/--slack/--teams/--webhook; AI stays local)

  observer analyze-log <path>               Analyze application logs, print a summary
  observer serve [--addr 127.0.0.1:7777]    Start the local web dashboard
  observer version                          Print version
  observer help                             Show this help

Examples:
  observer analyze ./examples/php-demo --out report.html
  observer analyze ./project --logs ./application/logs --runtime ./runtime.jsonl
  observer analyze-log ./application/logs
`, version)
}
