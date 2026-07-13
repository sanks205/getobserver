// Package reporter renders scan/analysis results into output artifacts.
//
// Phase 1 supports a self-contained HTML report. The template is embedded into
// the binary so the `observer` executable stays a single portable file with no
// runtime asset dependencies. Later phases add the richer multi-section report
// (executive summary, security findings, AI recommendations) described in
// Phase 7.
package reporter

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aipda/observer/internal/ai"
	"github.com/aipda/observer/internal/analyzer"
	"github.com/aipda/observer/internal/compliance"
	"github.com/aipda/observer/internal/detector"
	"github.com/aipda/observer/internal/logger"
	"github.com/aipda/observer/internal/runtime"
	"github.com/aipda/observer/internal/scanner"
)

//go:embed templates/report.html.tmpl
var reportTemplate string

// HTMLModel is the view model passed to the report template. Keeping a distinct
// view model (rather than rendering the scanner.Result directly) decouples the
// presentation layer from internal data structures.
type HTMLModel struct {
	ProjectName string
	RootPath    string
	GeneratedAt string
	ScanInfo    string // e.g. "Scanned 1157 files in 0.53s"
	Language    string
	Markers     []string

	// Phase 13 banners.
	BaselineApplied    bool
	BaselineSuppressed int
	BaselineNew        int
	GateEnabled        bool
	GatePassed         bool
	GateThreshold      string
	GateFailCount      int
	TotalFiles         int
	TotalDirs          int
	Categories         []kv
	TopExtensions      []kv

	// Phase 2 technology detection.
	Frameworks     []techItem
	Databases      []techItem
	Infrastructure []techItem

	// Phase 3 static analysis.
	FilesScanned        int
	TotalIssues         int
	SecScore            int
	SecGrade            string
	SecurityRating      string // standards-aligned A–E (worst security severity present)
	SecurityRatingBasis string // the worst severity behind the rating (e.g. "High")
	HealthScore         int
	HealthGrade         string
	RemediationEffort   string
	IssueSummary        []sevCount
	Issues              []issueItem
	IssueGroups         []issueGroup // findings grouped by rule (collapses duplicates)
	TopPriorities       []issueGroup // highest-severity groups for the "Fix these first" list
	FindingCategories   []string
	CriticalCount       int
	SecurityCount       int
	PerformanceCount    int
	IssuesCapped        bool

	// Phase 4 runtime errors.
	HasRuntime         bool
	TotalRuntimeEvents int
	RuntimeGroups      []runtimeGroupItem

	// Phase 5 log analysis.
	HasLogs        bool
	LogFilesParsed int
	TotalLogErrors int
	LogGroups      []logGroupItem

	// Phase 6 AI analysis.
	HasAI        bool
	AIProvider   string
	AISummary    string
	AIInsights   []aiInsightItem
	AIPriorities []string

	// Theme 3 compliance & standards.
	HasCompliance bool
	OWASPRows     []compliance.OWASPRow
	FrameworkRows []compliance.FrameworkRow
	CWERows       []compliance.CWERow
}

type kv struct {
	Key   string
	Value int
}

// techItem is the view model for a detected technology.
type techItem struct {
	Name       string
	Version    string
	Confidence string
	Evidence   string
}

type sevCount struct {
	Severity string
	Count    int
}

// issueItem is the view model for a static-analysis finding.
type issueItem struct {
	Severity       string
	Category       string
	Location       string
	Title          string
	Snippet        string
	Explanation    string
	Recommendation string
	CVSS           string // indicative CVSS-style score
	CWE            string
	OWASP          string
	CWELink        template.URL // link to the CWE definition
	OWASPLink      template.URL // link to the OWASP Top 10 category
	Link           template.URL // vscode:// deep link to the source location
	HasLink        bool
	FixExample     string // generic before→after fix, shown for every finding (offline, no --ai needed)
}

// maxReportIssues caps how many findings are rendered into the (client-side
// filterable) findings table, keeping the HTML a sane size on large projects.
const maxReportIssues = 2000

// editorLink builds a vscode:// deep link to file:line. file may be absolute
// (runtime events) or relative to the scanned root (static findings).
func editorLink(rootAbs, file string, line int) (template.URL, bool) {
	if file == "" {
		return "", false
	}
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(rootAbs, p)
	}
	p = strings.ReplaceAll(filepath.ToSlash(p), " ", "%20")
	u := "vscode://file/" + p
	if line > 0 {
		u += fmt.Sprintf(":%d", line)
	}
	// Safe: built from filesystem paths with spaces escaped, not user markup.
	return template.URL(u), true
}

// runtimeGroupItem is the view model for a grouped runtime error.
type runtimeGroupItem struct {
	Type     string
	Count    int
	Location string
	LastSeen string
	Message  string
	Link     template.URL
	HasLink  bool
}

// logGroupItem is the view model for a grouped log error.
type logGroupItem struct {
	Count    int
	Level    string
	Category string
	Sample   string
	LastSeen string
	Cause    string
}

// aiInsightItem is the view model for one AI insight.
type aiInsightItem struct {
	Title      string
	Severity   string
	Problem    string
	RootCause  string
	Impact     string
	Suggestion string
	Exploit    string
	FixExample string
	Complexity string
	Effort     string
}

// Data bundles every input the report renders. Any field except Scan may be
// nil; the corresponding section then renders as empty.
type Data struct {
	Scan     *scanner.Result
	Tech     *detector.TechStack
	Analysis *analyzer.Result
	Runtime  *runtime.Summary
	Logs     *logger.Summary
	AI       *ai.Report

	// DurationMs is the wall-clock scan time in milliseconds (0 = not measured).
	DurationMs int64

	// Phase 13 status banners (set by the CLI).
	BaselineApplied    bool
	BaselineSuppressed int
	BaselineNew        int
	GateEnabled        bool
	GateThreshold      string
	GateFailCount      int
}

// GenerateHTML renders the report and writes it to outPath.
func GenerateHTML(d Data, outPath string) error {
	html, err := RenderHTML(d)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(html), 0o644)
}

// RenderHTML renders the report to an HTML string. Used by both the CLI (which
// writes it to a file) and the dashboard server (which serves it directly).
func RenderHTML(d Data) (string, error) {
	res := d.Scan
	tech := d.Tech
	analysis := d.Analysis
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		// dict builds a map from alternating key/value pairs so a sub-template
		// can be invoked with multiple named arguments.
		"dict": func(pairs ...any) map[string]any {
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i+1 < len(pairs); i += 2 {
				key, _ := pairs[i].(string)
				m[key] = pairs[i+1]
			}
			return m
		},
	}).Parse(reportTemplate)
	if err != nil {
		return "", err
	}

	model := HTMLModel{
		ProjectName:   res.ProjectName,
		RootPath:      res.RootPath,
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Language:      res.DominantLang,
		Markers:       res.Markers,
		TotalFiles:    res.TotalFiles,
		TotalDirs:     res.TotalDirs,
		Categories:    sortedCategories(res.Categories),
		TopExtensions: topExtensions(res.FilesByExt, 10),
	}
	if tech != nil {
		model.Frameworks = toItems(tech.Frameworks)
		model.Databases = toItems(tech.Databases)
		model.Infrastructure = toItems(tech.Infrastructure)
		if lang := primaryLanguage(tech); lang != "" {
			model.Language = lang
		}
	}
	if analysis != nil {
		model.FilesScanned = analysis.FilesScanned
		model.ScanInfo = scanInfo(analysis.FilesScanned, d.DurationMs)
		model.SecScore, model.SecGrade = analyzer.SecurityScore(analysis)
		model.SecurityRating, model.SecurityRatingBasis = analyzer.SecurityRating(analysis)
		model.HealthScore, model.HealthGrade = analyzer.HealthScore(analysis)
		model.RemediationEffort = formatEffort(analyzer.RemediationMinutes(analysis))
		model.TotalIssues = len(analysis.Issues)
		model.IssueSummary = issueSummary(analysis.BySeverity)
		model.Issues = toIssueItems(res.RootPath, analysis.Issues)
		if len(model.Issues) > maxReportIssues {
			model.Issues = model.Issues[:maxReportIssues]
			model.IssuesCapped = true
		}
		model.CriticalCount = analysis.BySeverity[analyzer.Critical] + analysis.BySeverity[analyzer.High]
		model.SecurityCount = analysis.ByCategory["Security"]
		model.PerformanceCount = analysis.ByCategory["Performance"]
		model.FindingCategories = sortedKeys(analysis.ByCategory)
		model.IssueGroups = groupIssues(res.RootPath, analysis.Issues)
		model.TopPriorities = topPriorities(model.IssueGroups, 6)

		comp := compliance.Build(analysis.Issues)
		model.HasCompliance = true
		model.OWASPRows = comp.OWASP
		model.FrameworkRows = comp.Frameworks
		model.CWERows = comp.CWE
	}
	if d.Runtime != nil {
		model.HasRuntime = true
		model.TotalRuntimeEvents = d.Runtime.Total
		model.RuntimeGroups = toRuntimeItems(res.RootPath, d.Runtime.Groups)
	}
	if d.Logs != nil {
		model.HasLogs = true
		model.LogFilesParsed = d.Logs.FilesParsed
		model.TotalLogErrors = d.Logs.TotalErrors
		model.LogGroups = toLogItems(d.Logs.Groups)
	}
	model.BaselineApplied = d.BaselineApplied
	model.BaselineSuppressed = d.BaselineSuppressed
	model.BaselineNew = d.BaselineNew
	model.GateEnabled = d.GateEnabled
	model.GateThreshold = d.GateThreshold
	model.GateFailCount = d.GateFailCount
	model.GatePassed = d.GateFailCount == 0
	if d.AI != nil {
		model.HasAI = true
		model.AIProvider = d.AI.Provider
		model.AISummary = d.AI.Summary
		model.AIPriorities = d.AI.Priorities
		for _, in := range d.AI.Insights {
			model.AIInsights = append(model.AIInsights, aiInsightItem{
				Title: in.Title, Severity: in.Severity, Problem: in.Problem,
				RootCause: in.RootCause, Impact: in.Impact, Suggestion: in.Suggestion,
				Exploit: in.Exploit, FixExample: in.FixExample, Complexity: in.Complexity, Effort: in.Effort,
			})
		}
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, model); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func toItems(findings []detector.Finding) []techItem {
	out := make([]techItem, 0, len(findings))
	for _, f := range findings {
		out = append(out, techItem{
			Name:       f.Name,
			Version:    f.Version,
			Confidence: string(f.Confidence),
			Evidence:   strings.Join(f.Evidence, "; "),
		})
	}
	return out
}

// primaryLanguage returns the first detected language name, if any.
func primaryLanguage(tech *detector.TechStack) string {
	if len(tech.Languages) > 0 {
		return tech.Languages[0].Name
	}
	return ""
}

// severityOrder lists severities high-to-low for stable summary display.
var severityOrder = []analyzer.Severity{analyzer.Critical, analyzer.High, analyzer.Medium, analyzer.Low}

func issueSummary(bySev map[analyzer.Severity]int) []sevCount {
	out := make([]sevCount, 0, len(severityOrder))
	for _, s := range severityOrder {
		if n := bySev[s]; n > 0 {
			out = append(out, sevCount{Severity: string(s), Count: n})
		}
	}
	return out
}

func toRuntimeItems(rootAbs string, groups []runtime.Group) []runtimeGroupItem {
	out := make([]runtimeGroupItem, 0, len(groups))
	for _, g := range groups {
		loc := g.File
		if g.Line > 0 {
			loc = fmt.Sprintf("%s:%d", g.File, g.Line)
		}
		link, hasLink := editorLink(rootAbs, g.File, g.Line)
		out = append(out, runtimeGroupItem{
			Type:     g.Type,
			Count:    g.Count,
			Location: loc,
			LastSeen: g.LastSeen,
			Message:  g.LastMessage,
			Link:     link,
			HasLink:  hasLink,
		})
	}
	return out
}

// formatEffort renders an estimated-effort minute count as "~Xh Ym" / "~Xm".
func formatEffort(minutes int) string {
	if minutes <= 0 {
		return "none"
	}
	if minutes < 60 {
		return fmt.Sprintf("~%dm", minutes)
	}
	h, m := minutes/60, minutes%60
	if m == 0 {
		return fmt.Sprintf("~%dh", h)
	}
	return fmt.Sprintf("~%dh %dm", h, m)
}

// scanInfo formats the "Scanned N files in Xs" line for the report header.
func scanInfo(files int, durationMs int64) string {
	if files == 0 && durationMs == 0 {
		return ""
	}
	dur := fmt.Sprintf("%d ms", durationMs)
	if durationMs >= 1000 {
		dur = fmt.Sprintf("%.2f s", float64(durationMs)/1000)
	}
	return fmt.Sprintf("Scanned %d source file(s) in %s", files, dur)
}

// cweURL links a "CWE-89" tag to its official MITRE definition page.
func cweURL(cwe string) template.URL {
	num := strings.TrimPrefix(cwe, "CWE-")
	if num == "" || num == cwe {
		return ""
	}
	return template.URL("https://cwe.mitre.org/data/definitions/" + num + ".html")
}

// owaspURL links an "A03:2021 Injection" tag to its OWASP Top 10 page. OWASP
// slugs replace ':' with '_' and spaces with '_' (e.g. A03_2021-Injection).
func owaspURL(owasp string) template.URL {
	if owasp == "" {
		return ""
	}
	parts := strings.SplitN(owasp, " ", 2)
	if len(parts) != 2 {
		return template.URL("https://owasp.org/Top10/")
	}
	code := strings.ReplaceAll(parts[0], ":", "_")  // A03:2021 -> A03_2021
	title := strings.ReplaceAll(parts[1], " ", "_") // Injection / Broken_Access_Control
	return template.URL("https://owasp.org/Top10/" + code + "-" + title + "/")
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sortedKeys returns the map keys sorted alphabetically.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func toLogItems(groups []logger.Group) []logGroupItem {
	out := make([]logGroupItem, 0, len(groups))
	for _, g := range groups {
		out = append(out, logGroupItem{
			Count:    g.Count,
			Level:    g.Level,
			Category: g.Category,
			Sample:   g.Sample,
			LastSeen: g.LastSeen,
			Cause:    g.Cause,
		})
	}
	return out
}

func toIssueItems(rootAbs string, issues []analyzer.Issue) []issueItem {
	out := make([]issueItem, 0, len(issues))
	for _, is := range issues {
		link, hasLink := editorLink(rootAbs, is.File, is.Line)
		cwe := firstNonEmpty(is.CWE, analyzer.CWEFor(is.RuleID))
		owasp := firstNonEmpty(is.OWASP, analyzer.OWASPFor(is.RuleID))
		out = append(out, issueItem{
			Severity:       string(is.Severity),
			Category:       is.Category,
			Location:       fmt.Sprintf("%s:%d", is.File, is.Line),
			Title:          is.Title,
			Snippet:        is.Snippet,
			Explanation:    is.Explanation,
			Recommendation: is.Recommendation,
			CVSS:           analyzer.CVSS(is.Severity),
			CWE:            cwe,
			OWASP:          owasp,
			CWELink:        cweURL(cwe),
			OWASPLink:      owaspURL(owasp),
			Link:           link,
			HasLink:        hasLink,
			FixExample:     ai.GenericFix(cwe, is.Category),
		})
	}
	return out
}

// issueOccurrence is one location where a grouped finding appears.
type issueOccurrence struct {
	Location string
	Link     template.URL
	HasLink  bool
	Snippet  string
}

// issueGroup collapses all occurrences of the same rule into one entry, so a
// report on a large codebase shows dozens of issue *types* rather than thousands
// of near-identical rows.
type issueGroup struct {
	Severity       string
	Category       string
	Title          string
	RuleID         string
	CVSS           string
	CWE            string
	OWASP          string
	CWELink        template.URL
	OWASPLink      template.URL
	Explanation    string
	Recommendation string
	FixExample     string
	Count          int // total occurrences (may exceed len(Occurrences))
	Occurrences    []issueOccurrence
	ExtraCount     int // occurrences beyond the per-group display cap
}

// maxOccurrencesPerGroup bounds how many locations are rendered per group so the
// HTML stays a sane size even when one rule fires thousands of times.
const maxOccurrencesPerGroup = 100

func sevRank(s string) int {
	switch s {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	}
	return 0
}

// groupIssues buckets issues by rule (falling back to title), sorted by severity
// then frequency. Occurrences per group are capped; the overflow is counted.
func groupIssues(rootAbs string, issues []analyzer.Issue) []issueGroup {
	byKey := map[string]*issueGroup{}
	order := make([]string, 0)
	for _, is := range issues {
		key := is.RuleID
		if key == "" {
			key = is.Title
		}
		g := byKey[key]
		if g == nil {
			cwe := firstNonEmpty(is.CWE, analyzer.CWEFor(is.RuleID))
			owasp := firstNonEmpty(is.OWASP, analyzer.OWASPFor(is.RuleID))
			g = &issueGroup{
				Severity: string(is.Severity), Category: is.Category, Title: is.Title,
				RuleID: is.RuleID, CVSS: analyzer.CVSS(is.Severity),
				CWE: cwe, OWASP: owasp, CWELink: cweURL(cwe), OWASPLink: owaspURL(owasp),
				Explanation: is.Explanation, Recommendation: is.Recommendation,
				FixExample: ai.GenericFix(cwe, is.Category),
			}
			byKey[key] = g
			order = append(order, key)
		}
		g.Count++
		if sevRank(string(is.Severity)) > sevRank(g.Severity) {
			g.Severity = string(is.Severity)
			g.CVSS = analyzer.CVSS(is.Severity)
		}
		if len(g.Occurrences) < maxOccurrencesPerGroup {
			link, hasLink := editorLink(rootAbs, is.File, is.Line)
			g.Occurrences = append(g.Occurrences, issueOccurrence{
				Location: fmt.Sprintf("%s:%d", is.File, is.Line),
				Link:     link, HasLink: hasLink, Snippet: is.Snippet,
			})
		} else {
			g.ExtraCount++
		}
	}
	groups := make([]issueGroup, 0, len(order))
	for _, k := range order {
		groups = append(groups, *byKey[k])
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if ri, rj := sevRank(groups[i].Severity), sevRank(groups[j].Severity); ri != rj {
			return ri > rj
		}
		return groups[i].Count > groups[j].Count
	})
	return groups
}

// topPriorities returns up to n highest-severity Critical/High groups for the
// "Fix these first" list. Input is assumed already severity-sorted.
func topPriorities(groups []issueGroup, n int) []issueGroup {
	out := make([]issueGroup, 0, n)
	for _, g := range groups {
		if g.Severity == "Critical" || g.Severity == "High" {
			out = append(out, g)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}

func sortedCategories(m map[scanner.Category]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{Key: string(k), Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	return out
}

func topExtensions(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if len(out) > n {
		out = out[:n]
	}
	return out
}
