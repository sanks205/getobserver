// Package analyzer performs lightweight static code analysis (Phase 3).
//
// It is intentionally narrow: it does not aim to replace SonarQube or a real
// SAST engine. Instead it flags a curated set of practical, high-signal
// production issues — exposed secrets, SQL built by string concatenation,
// empty catch blocks, dangerous configuration, and a few performance and
// dependency smells — each with a severity, location, explanation, and
// recommendation.
//
// Detection is heuristic (regex + a handful of multi-line scanners). Findings
// are framed as *possible* problems for a human to confirm, not proven bugs.
package analyzer

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/aipda/observer/internal/scanner"
)

// Severity classifies the urgency of an issue.
type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
)

func severityRank(s Severity) int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// ruleMeta maps a rule ID to its CWE identifier and OWASP Top 10 (2021)
// category, so findings can be labeled for security/compliance audiences.
// Empty values mean "not security-classified" (e.g. performance rules).
var ruleMeta = map[string]struct{ CWE, OWASP string }{
	"SEC_TOKEN":                {"CWE-798", "A07:2021 Identification and Authentication Failures"},
	"SEC_HARDCODED_CREDENTIAL": {"CWE-798", "A07:2021 Identification and Authentication Failures"},
	"DB_RAW_SQL_CONCAT":        {"CWE-89", "A03:2021 Injection"},
	"PHP_DANGEROUS_EXEC":       {"CWE-78", "A03:2021 Injection"},
	"JS_EVAL":                  {"CWE-95", "A03:2021 Injection"},
	"PHP_SUPERGLOBAL_INPUT":    {"CWE-20", "A03:2021 Injection"},
	"SEC_WEAK_HASH":            {"CWE-327", "A02:2021 Cryptographic Failures"},
	"CFG_DISPLAY_ERRORS":       {"CWE-209", "A05:2021 Security Misconfiguration"},
	"CFG_DB_DEBUG":             {"CWE-209", "A05:2021 Security Misconfiguration"},
	"ERR_EMPTY_CATCH":          {"CWE-755", "A09:2021 Security Logging and Monitoring Failures"},
	"NPE_NULLABLE_CHAIN":       {"CWE-476", ""},
	"DEP_EOL_PHP":              {"CWE-1104", "A06:2021 Vulnerable and Outdated Components"},
	"DEP_UNPINNED":             {"CWE-1104", "A06:2021 Vulnerable and Outdated Components"},
	"DEP_CVE":                  {"CWE-1395", "A06:2021 Vulnerable and Outdated Components"},
	"XSS_REFLECTED":            {"CWE-79", "A03:2021 Injection"},
	"SEC_PATH_TRAVERSAL":       {"CWE-22", "A01:2021 Broken Access Control"},
	"SEC_SSRF":                 {"CWE-918", "A10:2021 Server-Side Request Forgery (SSRF)"},
	"SEC_INSECURE_DESERIALIZE": {"CWE-502", "A08:2021 Software and Data Integrity Failures"},
	"SEC_TLS_VERIFY_DISABLED":  {"CWE-295", "A05:2021 Security Misconfiguration"},
	"JS_DANGEROUS_INNERHTML":   {"CWE-79", "A03:2021 Injection"},
	"JS_DOM_XSS":               {"CWE-79", "A03:2021 Injection"},
	"JS_CHILD_PROCESS":         {"CWE-78", "A03:2021 Injection"},
	"PY_EVAL_EXEC":             {"CWE-95", "A03:2021 Injection"},
	"PY_OS_SYSTEM":             {"CWE-78", "A03:2021 Injection"},
	"PY_SUBPROCESS_SHELL":      {"CWE-78", "A03:2021 Injection"},
	"PY_PICKLE":                {"CWE-502", "A08:2021 Software and Data Integrity Failures"},
	"PY_YAML_LOAD":             {"CWE-502", "A08:2021 Software and Data Integrity Failures"},
	"PY_TLS_VERIFY_DISABLED":   {"CWE-295", "A05:2021 Security Misconfiguration"},
	"JAVA_RUNTIME_EXEC":        {"CWE-78", "A03:2021 Injection"},
	"JAVA_SQL_CONCAT":          {"CWE-89", "A03:2021 Injection"},
	"JAVA_DESERIALIZE":         {"CWE-502", "A08:2021 Software and Data Integrity Failures"},
	"JAVA_WEAK_HASH":           {"CWE-327", "A02:2021 Cryptographic Failures"},
	"RUBY_EVAL":                {"CWE-95", "A03:2021 Injection"},
	"RUBY_SYSTEM_EXEC":         {"CWE-78", "A03:2021 Injection"},
	"RUBY_YAML_LOAD":           {"CWE-502", "A08:2021 Software and Data Integrity Failures"},
	"RUBY_MARSHAL":             {"CWE-502", "A08:2021 Software and Data Integrity Failures"},
}

// CVSS returns an indicative CVSS-style base score (0–10) derived from
// severity. It is a representative bucket value for display/parity, NOT a
// vector-computed CVSS score.
func CVSS(s Severity) string {
	switch s {
	case Critical:
		return "9.5"
	case High:
		return "8.0"
	case Medium:
		return "5.0"
	case Low:
		return "2.0"
	}
	return "0.0"
}

// effortMinutes is the estimated fix effort for one finding, by severity.
func effortMinutes(s Severity) int {
	switch s {
	case Critical:
		return 60
	case High:
		return 30
	case Medium:
		return 15
	case Low:
		return 5
	}
	return 10
}

// RemediationMinutes estimates the total fix effort ("technical debt") across
// all findings, in minutes.
func RemediationMinutes(r *Result) int {
	if r == nil {
		return 0
	}
	total := 0
	for _, is := range r.Issues {
		total += effortMinutes(is.Severity)
	}
	return total
}

// CWEFor returns the CWE id for a rule (empty if none).
func CWEFor(ruleID string) string { return ruleMeta[ruleID].CWE }

// OWASPFor returns the OWASP Top 10 category for a rule (empty if none).
func OWASPFor(ruleID string) string { return ruleMeta[ruleID].OWASP }

// Score computes a 0–100 security score and a letter grade.
//
// It is *density-based* (severity-weighted findings per file) rather than an
// absolute penalty sum, so the score stays meaningful and comparable across
// projects of any size — a large codebase isn't automatically zero. Because a
// single hardcoded secret is serious regardless of size, the presence of any
// Critical finding caps the grade at C.
func Score(r *Result) (int, string) {
	if r == nil || len(r.Issues) == 0 {
		return 100, "A"
	}
	files := r.FilesScanned
	if files < 1 {
		files = 1
	}
	weighted := float64(r.BySeverity[Critical])*15 + float64(r.BySeverity[High])*5 +
		float64(r.BySeverity[Medium])*1 + float64(r.BySeverity[Low])*0.2
	density := weighted / float64(files)

	// Diminishing-returns curve: density 0 -> 100, rising density -> approaches 0,
	// never flooring abruptly.
	score := int(100.0/(1.0+density) + 0.5)

	if r.BySeverity[Critical] > 0 && score > 79 {
		score = 79 // you can't be "A/B" with a hardcoded secret or similar Critical
	}
	if score < 1 {
		score = 1
	}
	return score, grade(score)
}

// securityCategories are the finding categories that count toward the Security
// score (vulnerabilities, secrets, injection, dependency CVEs, dangerous
// configuration). Everything else counts toward Code Health.
var securityCategories = map[string]bool{
	"Security": true, "Database": true, "Dependencies": true, "Configuration": true,
}

// SecurityScore scores only the security-relevant findings.
func SecurityScore(r *Result) (int, string) {
	if r == nil {
		return 100, "A"
	}
	return Score(r.Keep(func(is Issue) bool { return securityCategories[is.Category] }))
}

// HealthScore scores the code-health findings (performance, error handling, …).
func HealthScore(r *Result) (int, string) {
	if r == nil {
		return 100, "A"
	}
	return Score(r.Keep(func(is Issue) bool { return !securityCategories[is.Category] }))
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// AllCategories lists the issue categories the analyzer can produce, for use in
// the dashboard checkboxes and CLI help.
var AllCategories = []string{
	"Security", "Database", "Error Handling", "Performance", "Configuration", "Dependencies",
}

// ParseSeverity maps a string (case-insensitive) to a Severity; anything
// unrecognized (or empty) is treated as Low so that "minimum = Low" includes all.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return Critical
	case "high":
		return High
	case "medium":
		return Medium
	default:
		return Low
	}
}

// Filter returns a copy of r keeping only issues whose category is in allowed
// (an empty/nil set means all categories) and whose severity is at or above
// minSeverity. Severity and category counts are recomputed. FilesScanned is
// preserved. This is how the customer's scan-scope choices are applied.
func Filter(r *Result, allowed map[string]bool, minSeverity Severity) *Result {
	if r == nil {
		return nil
	}
	out := &Result{
		FilesScanned: r.FilesScanned,
		BySeverity:   map[Severity]int{},
		ByCategory:   map[string]int{},
	}
	minRank := severityRank(minSeverity)
	for _, is := range r.Issues {
		if len(allowed) > 0 && !allowed[is.Category] {
			continue
		}
		if severityRank(is.Severity) < minRank {
			continue
		}
		out.Issues = append(out.Issues, is)
		out.BySeverity[is.Severity]++
		out.ByCategory[is.Category]++
	}
	return out
}

// Issue is a single finding. It carries everything needed to render the report
// row described in the spec: severity, file, line, problem, explanation, fix.
type Issue struct {
	RuleID         string
	Severity       Severity
	Category       string // Security, Database, Error Handling, Configuration, Dependencies, Performance
	Title          string
	File           string // path relative to the scanned root
	Line           int
	Snippet        string
	Explanation    string
	Recommendation string
	// CWE/OWASP may be set directly by external engines (e.g. Semgrep). For
	// built-in rules these stay empty and consumers fall back to ruleMeta.
	CWE   string
	OWASP string
}

// Result aggregates all findings for a project.
type Result struct {
	Issues       []Issue
	FilesScanned int
	BySeverity   map[Severity]int
	ByCategory   map[string]int
}

// Analysis tuning constants.
const (
	maxFileBytes = 2 * 1024 * 1024 // skip files larger than this
	maxLineLen   = 500             // skip very long lines (minified assets)
)

// sourceExts are the file types we run code rules against.
var sourceExts = map[string]bool{
	".php": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".py": true, ".java": true, ".rb": true, ".go": true,
}

// vendoredDirs hold third-party / built front-end code. Analyzing them produces
// noise (false positives in minified libraries) with no actionable value, so we
// skip them in addition to scanner.IsIgnoredDir. First-party app code is the
// target of static analysis.
var vendoredDirs = map[string]bool{
	"assets":           true,
	"bower_components": true,
	"vendors":          true,
	"third_party":      true,
	"third-party":      true,
}

// minifiedFile matches bundled/minified JavaScript that should not be analyzed.
var minifiedFile = regexp.MustCompile(`(?i)(\.min\.js|\.bundle\.js|-min\.js)$`)

// isFrameworkCore reports whether a directory is a vendored framework core that
// should be skipped. Currently it recognizes CodeIgniter's "system" directory
// (identified by core/CodeIgniter.php) so we analyze the user's application
// code, not the framework itself. The check is content-based, so it never
// skips an unrelated directory that merely happens to be named "system".
func isFrameworkCore(dir, name string) bool {
	if name != "system" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "core", "CodeIgniter.php"))
	return err == nil
}

// job is one unit of analysis work: a source file or a dependency manifest.
type job struct {
	path     string
	rel      string
	ext      string
	manifest string // basename if this is a dependency manifest, else ""
}

// Analyze walks the project rooted at root, applies all rules, and returns the
// aggregated findings sorted by severity (then file, then line).
//
// Files are independent, so analysis runs concurrently across a worker pool
// (one worker per CPU). Results are written to a per-job slot so the final
// output is deterministic regardless of completion order.
func Analyze(root string) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, err
	}

	jobs, err := collectJobs(abs)
	if err != nil {
		return nil, err
	}

	res := &Result{
		BySeverity: map[Severity]int{},
		ByCategory: map[string]int{},
	}

	results := make([][]Issue, len(jobs))
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	idx := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				results[i] = processJob(jobs[i])
			}
		}()
	}
	for i := range jobs {
		idx <- i
	}
	close(idx)
	wg.Wait()

	for i, j := range jobs {
		if j.manifest == "" {
			res.FilesScanned++
		}
		res.add(results[i]...)
	}
	sortIssues(res.Issues)
	return res, nil
}

// collectJobs walks the tree once and returns the files to analyze, skipping
// ignored/vendored directories, framework cores, and minified bundles.
func collectJobs(abs string) ([]job, error) {
	var jobs []job
	err := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if p != abs && (scanner.IsIgnoredDir(d.Name()) || vendoredDirs[name] || isFrameworkCore(p, name)) {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		rel := relPath(abs, p)
		if name == "composer.json" || name == "package.json" {
			jobs = append(jobs, job{path: p, rel: rel, manifest: name})
			return nil
		}
		if minifiedFile.MatchString(name) {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		if sourceExts[ext] {
			jobs = append(jobs, job{path: p, rel: rel, ext: ext})
		}
		return nil
	})
	return jobs, err
}

// processJob analyzes a single job and returns its issues.
func processJob(j job) []Issue {
	if j.manifest != "" {
		if body, ok := readFile(j.path); ok {
			return checkDependencies(j.rel, j.manifest, body)
		}
		return nil
	}
	lines, ok := readLines(j.path)
	if !ok {
		return nil
	}
	return analyzeFile(j.rel, j.ext, lines)
}

// analyzeFile runs every code detector over a single file's lines. A code mask
// marks comment/blank lines so rules don't fire inside comments. Secret
// detection is the exception — a leaked credential matters even in a comment —
// so it runs on every line.
func analyzeFile(rel, ext string, lines []string) []Issue {
	mask := computeCodeMask(lines, ext)
	var issues []Issue
	for i, line := range lines {
		if len(line) > maxLineLen {
			continue
		}
		ctx := lineCtx{rel: rel, ext: ext, lineNo: i + 1, line: line, lower: strings.ToLower(line)}
		// Secrets run on the raw line — a leaked credential matters even in a comment.
		issues = append(issues, detectSecret(ctx)...)
		if !mask[i] {
			continue
		}
		// For code rules, strip any trailing line comment so trigger words inside a
		// comment (e.g. `x = f()  // avoid eval()`) don't cause false positives.
		code := stripTrailingComment(line, ext)
		cctx := lineCtx{rel: rel, ext: ext, lineNo: i + 1, line: code, lower: strings.ToLower(code)}
		issues = append(issues, runLineRules(cctx)...)
		issues = append(issues, detectRawSQL(cctx)...)
		issues = append(issues, detectNullRefChain(cctx)...)
		issues = append(issues, detectXSS(cctx)...)
	}
	issues = append(issues, detectEmptyCatch(rel, ext, lines, mask)...)
	return issues
}

// computeCodeMask returns, for each line, whether it is "code" (true) versus a
// blank line or comment (false). It tracks /* ... */ block comments — which is
// what eliminates false positives from CodeIgniter's "| ..." doc blocks.
func computeCodeMask(lines []string, ext string) []bool {
	mask := make([]bool, len(lines))
	inBlock := false
	hash := ext == ".php" || ext == ".py" || ext == ".rb"
	for i, line := range lines {
		if inBlock {
			mask[i] = false
			if strings.Contains(line, "*/") {
				inBlock = false
			}
			continue
		}
		t := strings.TrimSpace(line)
		switch {
		case t == "",
			strings.HasPrefix(t, "//"), strings.HasPrefix(t, "/*"),
			strings.HasPrefix(t, "*"), strings.HasPrefix(t, "<!--"):
			mask[i] = false
		case hash && strings.HasPrefix(t, "#"):
			mask[i] = false
		default:
			mask[i] = true
		}
		if o := strings.LastIndex(line, "/*"); o >= 0 && !strings.Contains(line[o:], "*/") {
			inBlock = true
		}
	}
	return mask
}

// stripTrailingComment removes a trailing line comment ("//" for all code; "#"
// for PHP/Python/Ruby) from a code line, without touching markers that appear
// inside string literals (e.g. "http://…") — so rules match the code, not the
// comment. Block comments are already handled by computeCodeMask.
func stripTrailingComment(line, ext string) string {
	hash := ext == ".php" || ext == ".py" || ext == ".rb"
	var quote byte // 0 when not inside a string literal
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' {
				i++ // skip the escaped character
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return strings.TrimRight(line[:i], " \t")
			}
		case '#':
			if hash {
				// PHP 8 attributes use #[...]; those aren't comments.
				if ext == ".php" && i+1 < len(line) && line[i+1] == '[' {
					continue
				}
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}

// AddIssues appends externally-produced issues (e.g. dependency CVEs), updates
// the severity/category counts, and re-sorts. Used to merge findings from other
// sources into the static-analysis result.
func (r *Result) AddIssues(issues ...Issue) {
	r.add(issues...)
	sortIssues(r.Issues)
}

// Keep returns a copy of r containing only issues for which pred returns true,
// with severity/category counts recomputed. Used for baseline suppression and
// other post-hoc filtering.
func (r *Result) Keep(pred func(Issue) bool) *Result {
	if r == nil {
		return nil
	}
	out := &Result{FilesScanned: r.FilesScanned, BySeverity: map[Severity]int{}, ByCategory: map[string]int{}}
	for _, is := range r.Issues {
		if pred(is) {
			out.add(is)
		}
	}
	sortIssues(out.Issues)
	return out
}

// CountAtLeast returns how many issues are at or above minSeverity. Used by the
// CI quality gate.
func CountAtLeast(r *Result, minSeverity Severity) int {
	if r == nil {
		return 0
	}
	min := severityRank(minSeverity)
	n := 0
	for _, is := range r.Issues {
		if severityRank(is.Severity) >= min {
			n++
		}
	}
	return n
}

func (r *Result) add(issues ...Issue) {
	for _, is := range issues {
		r.Issues = append(r.Issues, is)
		r.BySeverity[is.Severity]++
		r.ByCategory[is.Category]++
	}
}

// lineCtx bundles the per-line information detectors need. lower is the
// lowercased line, computed once so detectors can use cheap strings.Contains
// gates before invoking (relatively expensive) regular expressions.
type lineCtx struct {
	rel    string
	ext    string
	lineNo int
	line   string
	lower  string
}

// anyContains reports whether s contains any of the given (lowercased) subs.
func anyContains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		ri, rj := severityRank(issues[i].Severity), severityRank(issues[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		return issues[i].Line < issues[j].Line
	})
}

// --- file/line IO helpers ---------------------------------------------------

func relPath(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}

// readFile returns the file contents, skipping files that are too large or
// appear to be binary.
func readFile(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxFileBytes {
		return "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	if bytes.IndexByte(b[:min(len(b), 1024)], 0) >= 0 {
		return "", false // binary
	}
	return string(b), true
}

func readLines(path string) ([]string, bool) {
	body, ok := readFile(path)
	if !ok {
		return nil, false
	}
	return strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n"), true
}
