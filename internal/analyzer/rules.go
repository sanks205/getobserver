package analyzer

import (
	"regexp"
	"strconv"
	"strings"
)

// =============================================================================
// Simple line rules (one regex per rule)
// =============================================================================

type lineRule struct {
	id             string
	severity       Severity
	category       string
	title          string
	explanation    string
	recommendation string
	exts           map[string]bool // nil = all source files
	skipComments   bool
	gates          []string // lowercased; regex runs only if the line contains one
	re             *regexp.Regexp
}

var lineRules = []lineRule{
	{
		id: "PHP_DANGEROUS_EXEC", severity: High, category: "Security",
		title:          "Dangerous code/command execution function",
		explanation:    "Functions like eval/exec/system run arbitrary code or shell commands. With any untrusted input they enable remote code execution.",
		recommendation: "Avoid these functions. If unavoidable, never pass user input and use strict allow-lists / escapeshellarg().",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"eval", "exec", "system", "passthru", "proc_open", "popen"},
		re:             regexp.MustCompile(`(?i)\b(eval|exec|shell_exec|system|passthru|proc_open|popen)\s*\(`),
	},
	{
		id: "JS_EVAL", severity: High, category: "Security",
		title:          "Use of eval()",
		explanation:    "eval() executes arbitrary JavaScript and is a common injection vector.",
		recommendation: "Replace eval() with safer alternatives (JSON.parse, function maps, etc.).",
		exts:           map[string]bool{".js": true, ".ts": true, ".jsx": true, ".tsx": true},
		skipComments:   true,
		gates:          []string{"eval"},
		re:             regexp.MustCompile(`\beval\s*\(`),
	},
	{
		id: "PHP_SUPERGLOBAL_INPUT", severity: Low, category: "Security",
		title:          "Unvalidated request input",
		explanation:    "Reading $_GET/$_POST/$_REQUEST directly uses raw, unvalidated user input, which often flows into queries or output.",
		recommendation: "Validate and sanitize input (e.g. filter_input, the framework's input/validation layer) before use.",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"$_get", "$_post", "$_request", "$_cookie"},
		re:             regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE)\s*\[`),
	},
	{
		id: "CFG_DISPLAY_ERRORS", severity: High, category: "Configuration",
		title:          "display_errors enabled",
		explanation:    "Displaying errors in production leaks stack traces, file paths, and query details to end users and attackers.",
		recommendation: "Turn display_errors off in production; log errors to a file instead.",
		skipComments:   true,
		gates:          []string{"display_errors"},
		re:             regexp.MustCompile(`(?i)display_errors.{0,8}(=>|=|,)\s*['"]?(1|true|on)\b`),
	},
	{
		id: "CFG_DB_DEBUG", severity: Medium, category: "Configuration",
		title:          "Database debug mode enabled",
		explanation:    "db_debug = TRUE prints raw SQL errors (including queries) to the response on failure.",
		recommendation: "Disable db_debug in production and rely on application logging.",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"db_debug"},
		re:             regexp.MustCompile(`(?i)db_debug.{0,8}(=>|=)\s*true`),
	},
	{
		id: "PERF_SELECT_STAR", severity: Medium, category: "Performance",
		title:          "SELECT * query",
		explanation:    "Selecting all columns over-fetches data, increases I/O, and breaks when the schema changes.",
		recommendation: "Select only the columns you need.",
		skipComments:   true,
		gates:          []string{"select"},
		re:             regexp.MustCompile(`(?i)select\s+\*\s+from`),
	},
	{
		id: "PERF_LEADING_WILDCARD_LIKE", severity: Low, category: "Performance",
		title:          "Leading-wildcard LIKE",
		explanation:    "A LIKE pattern beginning with '%' cannot use an index, forcing a full scan.",
		recommendation: "Avoid leading wildcards, or use full-text search for substring matching.",
		skipComments:   true,
		gates:          []string{"like"},
		re:             regexp.MustCompile(`(?i)like\s+['"]%`),
	},
	{
		id: "SEC_WEAK_HASH", severity: Medium, category: "Security",
		title:          "Weak hashing of credentials",
		explanation:    "md5/sha1 are fast and unsalted, making password hashes easy to brute-force.",
		recommendation: "Use password_hash()/bcrypt/argon2 for passwords.",
		skipComments:   true,
		gates:          []string{"md5", "sha1"},
		re:             regexp.MustCompile(`(?i)\b(md5|sha1)\s*\([^)]*(pass|pwd|secret|token)`),
	},
	{
		id: "SEC_PATH_TRAVERSAL", severity: High, category: "Security",
		title:          "Unvalidated input in file/include operation (path traversal / LFI)",
		explanation:    "A file or include operation uses unvalidated request input, letting attackers read or execute arbitrary files.",
		recommendation: "Validate against an allow-list of paths; never pass request input directly to file/include functions.",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"$_get", "$_post", "$_request", "$_cookie"},
		// Superglobal must immediately follow the function/keyword (optional
		// paren/quote/space) — matches `include $_GET[...]` and
		// `file_get_contents($_GET[...])` without flagging `$include = $_GET`.
		re: regexp.MustCompile(`(?i)\b(include|include_once|require|require_once|readfile|fopen|file_get_contents)\b[ \t]*\(?[ \t]*['"]?[ \t]*\$_(get|post|request|cookie)\b`),
	},
	{
		id: "SEC_SSRF", severity: High, category: "Security",
		title:          "Possible SSRF (server-side request forgery)",
		explanation:    "A server-side HTTP request is built from unvalidated request input, letting attackers reach internal or arbitrary hosts.",
		recommendation: "Allow-list destinations and validate URLs; never build request targets directly from user input.",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"$_get", "$_post", "$_request"},
		re:             regexp.MustCompile(`(?i)\b(curl_init|curl_setopt|curl_exec)\s*\(\s*[^;]*\$_(get|post|request)`),
	},
	{
		id: "SEC_INSECURE_DESERIALIZE", severity: High, category: "Security",
		title:          "Insecure deserialization of request input",
		explanation:    "unserialize() on attacker-controlled data enables object injection and can lead to remote code execution.",
		recommendation: "Avoid unserialize() on user input; use json_decode(), or pass ['allowed_classes' => false].",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"unserialize"},
		re:             regexp.MustCompile(`(?i)\bunserialize\s*\(\s*[^;]*\$_(get|post|request|cookie)`),
	},
	{
		id: "SEC_TLS_VERIFY_DISABLED", severity: High, category: "Security",
		title:          "TLS/SSL certificate verification disabled",
		explanation:    "Disabling certificate verification exposes outbound HTTPS connections to man-in-the-middle attacks.",
		recommendation: "Enable verification: CURLOPT_SSL_VERIFYPEER=true / Guzzle 'verify'=>true.",
		exts:           map[string]bool{".php": true},
		skipComments:   true,
		gates:          []string{"verify"},
		re:             regexp.MustCompile(`(?i)(curlopt_ssl_verifypeer|curlopt_ssl_verifyhost)\s*(,|=>)\s*(false|0)\b|['"]verify['"]\s*=>\s*(false|0)\b`),
	},

	// --- JavaScript / TypeScript (native, no engine required) ---
	{
		id: "JS_DANGEROUS_INNERHTML", severity: Medium, category: "Security",
		title:          "Unsanitized HTML injection (dangerouslySetInnerHTML)",
		explanation:    "React's dangerouslySetInnerHTML renders raw HTML; with any user-influenced value it enables XSS.",
		recommendation: "Render as text, or sanitize the HTML (e.g. DOMPurify) before injecting it.",
		exts:           map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true},
		skipComments:   true,
		gates:          []string{"dangerouslysetinnerhtml"},
		re:             regexp.MustCompile(`dangerouslySetInnerHTML`),
	},
	{
		id: "JS_DOM_XSS", severity: Medium, category: "Security",
		title:          "Possible DOM XSS (document.write / innerHTML)",
		explanation:    "Writing to document.write() or element.innerHTML with dynamic data can inject scripts into the page.",
		recommendation: "Use textContent, or sanitize input before assigning HTML.",
		exts:           map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true},
		skipComments:   true,
		gates:          []string{"document.write", ".innerhtml"},
		re:             regexp.MustCompile(`(?i)(document\.write\s*\(|\.innerHTML\s*=)`),
	},
	{
		id: "JS_CHILD_PROCESS", severity: Medium, category: "Security",
		title:          "Command execution via child_process",
		explanation:    "child_process exec/spawn runs shell commands; passing untrusted input enables command injection.",
		recommendation: "Avoid shell exec with user input; use execFile with a fixed command + args array, and validate inputs.",
		exts:           map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true},
		skipComments:   true,
		gates:          []string{"child_process"},
		re:             regexp.MustCompile(`child_process`),
	},

	// --- Python (native, no engine required) ---
	{
		id: "PY_EVAL_EXEC", severity: High, category: "Security",
		title:          "Use of eval()/exec()",
		explanation:    "eval()/exec() run arbitrary Python; with any untrusted input they allow code execution.",
		recommendation: "Avoid eval/exec on dynamic data; use ast.literal_eval for data, or explicit parsing.",
		exts:           map[string]bool{".py": true},
		skipComments:   true,
		gates:          []string{"eval", "exec"},
		re:             regexp.MustCompile(`(?i)(^|[^a-z0-9_.])(eval|exec)\s*\(`),
	},
	{
		id: "PY_OS_SYSTEM", severity: High, category: "Security",
		title:          "Shell command via os.system()",
		explanation:    "os.system() runs a command through the shell; untrusted input enables command injection.",
		recommendation: "Use subprocess.run([...], shell=False) with an args list and validated inputs.",
		exts:           map[string]bool{".py": true},
		skipComments:   true,
		gates:          []string{"os.system"},
		re:             regexp.MustCompile(`os\.system\s*\(`),
	},
	{
		id: "PY_SUBPROCESS_SHELL", severity: High, category: "Security",
		title:          "subprocess with shell=True",
		explanation:    "shell=True runs the command through a shell; interpolating input enables command injection.",
		recommendation: "Use shell=False (the default) with an args list; never build shell strings from user input.",
		exts:           map[string]bool{".py": true},
		skipComments:   true,
		gates:          []string{"shell"},
		re:             regexp.MustCompile(`(?i)shell\s*=\s*True`),
	},
	{
		id: "PY_PICKLE", severity: High, category: "Security",
		title:          "Insecure deserialization (pickle)",
		explanation:    "pickle.load/loads on untrusted data can execute arbitrary code during deserialization.",
		recommendation: "Don't unpickle untrusted data; use JSON or another safe serialization format.",
		exts:           map[string]bool{".py": true},
		skipComments:   true,
		gates:          []string{"pickle"},
		re:             regexp.MustCompile(`pickle\.loads?\s*\(`),
	},
	{
		id: "PY_YAML_LOAD", severity: Medium, category: "Security",
		title:          "Unsafe YAML load",
		explanation:    "yaml.load() without SafeLoader can construct arbitrary Python objects from untrusted YAML.",
		recommendation: "Use yaml.safe_load() (or Loader=SafeLoader).",
		exts:           map[string]bool{".py": true},
		skipComments:   true,
		gates:          []string{"yaml.load"},
		re:             regexp.MustCompile(`yaml\.load\s*\(`),
	},
	{
		id: "PY_TLS_VERIFY_DISABLED", severity: Medium, category: "Security",
		title:          "TLS verification disabled (verify=False)",
		explanation:    "requests(..., verify=False) disables certificate validation, enabling man-in-the-middle attacks.",
		recommendation: "Remove verify=False; let the HTTP client validate certificates.",
		exts:           map[string]bool{".py": true},
		skipComments:   true,
		gates:          []string{"verify"},
		re:             regexp.MustCompile(`(?i)verify\s*=\s*False`),
	},

	// --- Java (native, no engine required) ---
	{
		id: "JAVA_RUNTIME_EXEC", severity: High, category: "Security",
		title:          "OS command execution (Runtime.exec / ProcessBuilder)",
		explanation:    "Runtime.exec()/ProcessBuilder run OS commands; passing untrusted input enables command injection.",
		recommendation: "Avoid shell exec with user input; pass a fixed command + argument array and validate inputs.",
		exts:           map[string]bool{".java": true},
		skipComments:   true,
		gates:          []string{"getruntime", "processbuilder"},
		re:             regexp.MustCompile(`(?i)(Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\()`),
	},
	{
		id: "JAVA_SQL_CONCAT", severity: High, category: "Database",
		title:          "SQL built with string concatenation",
		explanation:    "Concatenating variables into a JDBC query string allows SQL injection.",
		recommendation: "Use PreparedStatement with bound parameters instead of string concatenation.",
		exts:           map[string]bool{".java": true},
		skipComments:   true,
		gates:          []string{"execute"},
		re:             regexp.MustCompile(`(?i)\.execute(Query|Update)?\s*\(\s*"[^"]*"\s*\+`),
	},
	{
		id: "JAVA_DESERIALIZE", severity: High, category: "Security",
		title:          "Insecure deserialization (ObjectInputStream)",
		explanation:    "Deserializing untrusted data with ObjectInputStream.readObject() can lead to remote code execution.",
		recommendation: "Avoid Java native deserialization of untrusted input; use a safe format (JSON) or allow-list classes.",
		exts:           map[string]bool{".java": true},
		skipComments:   true,
		gates:          []string{"objectinputstream", "readobject"},
		re:             regexp.MustCompile(`(?i)(new\s+ObjectInputStream|\.readObject\s*\()`),
	},
	{
		id: "JAVA_WEAK_HASH", severity: Medium, category: "Security",
		title:          "Weak hash algorithm (MD5 / SHA-1)",
		explanation:    "MD5 and SHA-1 are broken for security use — unsuitable for signatures or password hashing.",
		recommendation: "Use SHA-256+ for integrity, and bcrypt/argon2/PBKDF2 for passwords.",
		exts:           map[string]bool{".java": true},
		skipComments:   true,
		gates:          []string{"messagedigest"},
		re:             regexp.MustCompile(`(?i)MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"`),
	},

	// --- Ruby (native, no engine required) ---
	{
		id: "RUBY_EVAL", severity: High, category: "Security",
		title:          "Use of eval / instance_eval",
		explanation:    "eval and *_eval on dynamic strings execute arbitrary Ruby, enabling code injection.",
		recommendation: "Avoid eval on untrusted input; use safer constructs (e.g. public_send with an allow-list).",
		exts:           map[string]bool{".rb": true},
		skipComments:   true,
		gates:          []string{"eval"},
		re:             regexp.MustCompile(`(?i)\b(eval|instance_eval|class_eval|module_eval)\s*(\(|"|')`),
	},
	{
		id: "RUBY_SYSTEM_EXEC", severity: High, category: "Security",
		title:          "OS command execution (system / exec / %x)",
		explanation:    "system(), exec() and %x{} run shell commands; interpolating input enables command injection.",
		recommendation: "Pass a command + args (e.g. system('cmd', arg)) and validate inputs; avoid shell strings.",
		exts:           map[string]bool{".rb": true},
		skipComments:   true,
		gates:          []string{"system", "exec", "%x"},
		re:             regexp.MustCompile(`(?i)(\bsystem\s*\(|\bexec\s*\(|%x[\(\{\[])`),
	},
	{
		id: "RUBY_YAML_LOAD", severity: Medium, category: "Security",
		title:          "Unsafe YAML load",
		explanation:    "YAML.load can instantiate arbitrary Ruby objects from untrusted YAML.",
		recommendation: "Use YAML.safe_load.",
		exts:           map[string]bool{".rb": true},
		skipComments:   true,
		gates:          []string{"yaml.load"},
		re:             regexp.MustCompile(`(?i)YAML\.load\s*\(`),
	},
	{
		id: "RUBY_MARSHAL", severity: High, category: "Security",
		title:          "Insecure deserialization (Marshal.load)",
		explanation:    "Marshal.load on untrusted data can execute arbitrary code during deserialization.",
		recommendation: "Never Marshal.load untrusted data; use JSON or another safe format.",
		exts:           map[string]bool{".rb": true},
		skipComments:   true,
		gates:          []string{"marshal.load"},
		re:             regexp.MustCompile(`Marshal\.load\s*\(`),
	},
}

func runLineRules(c lineCtx) []Issue {
	var issues []Issue
	comment := isComment(c.line)
	for _, r := range lineRules {
		if r.exts != nil && !r.exts[c.ext] {
			continue
		}
		if r.skipComments && comment {
			continue
		}
		if len(r.gates) > 0 && !anyContains(c.lower, r.gates...) {
			continue // cheap pre-filter: skip regex when no keyword is present
		}
		if r.re.MatchString(c.line) {
			issues = append(issues, Issue{
				RuleID: r.id, Severity: r.severity, Category: r.category, Title: r.title,
				File: c.rel, Line: c.lineNo, Snippet: snippet(c.line),
				Explanation: r.explanation, Recommendation: r.recommendation,
			})
		}
	}
	return issues
}

// =============================================================================
// Secrets / hardcoded credentials
// =============================================================================

// highEntropyTokens are unambiguous secret formats (provider-specific). gate is
// a lowercased substring that must be present before the regex is evaluated.
var highEntropyTokens = []struct {
	re       *regexp.Regexp
	title    string
	severity Severity
	gate     string
}{
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "Hardcoded AWS access key", Critical, "akia"},
	{regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{10,}\b`), "Hardcoded Stripe live secret key", Critical, "sk_live_"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "Embedded private key", Critical, "private key"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), "Hardcoded Google API key", High, "aiza"},
	{regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`), "Hardcoded GitHub token", High, "ghp_"},
}

// credentialAssign matches a credential-like key assigned a quoted literal,
// capturing the value in group 2.
// Allows an optional closing quote after the key (e.g. 'password' => '...',
// "secret": "...") before the assignment operator.
var credentialAssign = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*(?:=>|=|:)\s*["']([^"']+)["']`)

func detectSecret(c lineCtx) []Issue {
	var issues []Issue

	tokenMatched := false
	for _, t := range highEntropyTokens {
		if !strings.Contains(c.lower, t.gate) {
			continue
		}
		if t.re.MatchString(c.line) {
			tokenMatched = true
			issues = append(issues, Issue{
				RuleID: "SEC_TOKEN", Severity: t.severity, Category: "Security", Title: t.title,
				File: c.rel, Line: c.lineNo, Snippet: snippet(c.line),
				Explanation:    "A live credential is committed in source control. Anyone with repo access (or a leak) can use it.",
				Recommendation: "Revoke and rotate the credential immediately; load secrets from environment variables or a secrets manager.",
			})
		}
	}

	// Skip the generic credential rule when a specific token already matched the
	// same line, to avoid reporting the same literal twice. Cheap gate first.
	if tokenMatched || !anyContains(c.lower, "password", "passwd", "pwd", "secret", "key", "token") {
		return issues
	}
	if m := credentialAssign.FindStringSubmatch(c.line); m != nil {
		if !isPlaceholder(m[2]) {
			issues = append(issues, Issue{
				RuleID: "SEC_HARDCODED_CREDENTIAL", Severity: High, Category: "Security",
				Title: "Hardcoded credential", File: c.rel, Line: c.lineNo, Snippet: snippet(c.line),
				Explanation:    "A password/secret/API key is hardcoded as a literal value, exposing it to anyone reading the code.",
				Recommendation: "Move the value to an environment variable or secrets manager and reference it at runtime.",
			})
		}
	}
	return issues
}

// isPlaceholder reports whether a literal looks like a non-secret (empty,
// example value, env reference, or template variable).
func isPlaceholder(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	if t == "" || len(t) < 4 {
		return true
	}
	if strings.HasPrefix(t, "$") { // interpolated variable, not a literal secret
		return true
	}
	for _, p := range []string{"env(", "getenv", "process.env", "your", "example", "changeme",
		"placeholder", "xxxx", "<", "{{", "%s", "null", "todo", "secret_key_here", "*****"} {
		if strings.Contains(t, p) {
			return true
		}
	}
	return false
}

// =============================================================================
// Raw SQL built via string concatenation (injection risk)
// =============================================================================

// A real SQL statement combines a verb (SELECT/INSERT/...) with a clause
// (FROM/WHERE/...). Requiring both avoids matching ordinary code that merely
// contains a word like "delete" (e.g. a URL path).
var sqlVerb = regexp.MustCompile(`(?i)\b(select|insert|update|delete)\b`)
var sqlClause = regexp.MustCompile(`(?i)\b(from|into|where|values|set|join)\b`)
var sqlConcatVar = regexp.MustCompile(`(\.\s*\$\w+|\$\w+\s*\.|\$\{)`)

func detectRawSQL(c lineCtx) []Issue {
	if c.ext != ".php" && c.ext != ".js" && c.ext != ".ts" && c.ext != ".py" {
		return nil
	}
	// Gate: a real concatenated query needs an SQL verb and a "$" (concatenated
	// variable). Both are cheap byte scans that reject the vast majority of lines.
	if !strings.Contains(c.line, "$") || !anyContains(c.lower, "select", "insert", "update", "delete") {
		return nil
	}
	if sqlVerb.MatchString(c.line) && sqlClause.MatchString(c.line) && sqlConcatVar.MatchString(c.line) {
		return []Issue{{
			RuleID: "DB_RAW_SQL_CONCAT", Severity: High, Category: "Database",
			Title: "SQL built with string concatenation", File: c.rel, Line: c.lineNo, Snippet: snippet(c.line),
			Explanation:    "Interpolating variables directly into a SQL string allows SQL injection if any value is attacker-controlled.",
			Recommendation: "Use parameterized queries / query bindings (prepared statements) instead of concatenation.",
		}}
	}
	return nil
}

// =============================================================================
// Reflected XSS (echoing request input without escaping)
// =============================================================================

var echoSuperglobal = regexp.MustCompile(`(?i)(\becho\b|\bprint\b|<\?=)[^;]*\$_(get|post|request|cookie)\b`)
var xssSafe = regexp.MustCompile(`(?i)(htmlspecialchars|htmlentities|strip_tags|intval|\(int\)|->escape|esc_html|filter_var|urlencode|json_encode)`)

func detectXSS(c lineCtx) []Issue {
	if c.ext != ".php" || !strings.Contains(c.lower, "$_") {
		return nil
	}
	if !echoSuperglobal.MatchString(c.line) || xssSafe.MatchString(c.line) {
		return nil // not an echo of request input, or it's already escaped
	}
	return []Issue{{
		RuleID: "XSS_REFLECTED", Severity: High, Category: "Security",
		Title: "Possible reflected XSS", File: c.rel, Line: c.lineNo, Snippet: snippet(c.line),
		Explanation:    "Request input is echoed to the page without escaping, allowing reflected cross-site scripting.",
		Recommendation: "Escape output with htmlspecialchars() (or template auto-escaping) before rendering user input.",
	}}
}

// =============================================================================
// Possible null reference (chaining off a nullable return)
// =============================================================================

var nullableChain = regexp.MustCompile(`(?i)->\s*(row|first|find|get)\s*\([^)]*\)\s*->`)

func detectNullRefChain(c lineCtx) []Issue {
	if c.ext != ".php" {
		return nil
	}
	if !strings.Contains(c.line, "->") || !anyContains(c.lower, "row", "first", "find", "get") {
		return nil
	}
	if nullableChain.MatchString(c.line) {
		return []Issue{{
			RuleID: "NPE_NULLABLE_CHAIN", Severity: Low, Category: "Error Handling",
			Title: "Possible null reference", File: c.rel, Line: c.lineNo, Snippet: snippet(c.line),
			Explanation:    "Methods like row()/first()/find() return null when no record is found; chaining a call on the result then triggers a fatal error.",
			Recommendation: "Check the result for null before dereferencing it.",
		}}
	}
	return nil
}

// =============================================================================
// Empty catch blocks (multi-line)
// =============================================================================

var catchOpen = regexp.MustCompile(`(?i)\bcatch\b\s*\(`)

// detectEmptyCatch flags catch blocks whose body is empty or contains only
// comments — a common cause of silently swallowed production errors.
func detectEmptyCatch(rel, ext string, lines []string, mask []bool) []Issue {
	if ext != ".php" && ext != ".js" && ext != ".ts" && ext != ".java" {
		return nil
	}
	var issues []Issue
	for i, line := range lines {
		if !mask[i] || !catchOpen.MatchString(line) {
			continue
		}
		brace := strings.Index(line, "{")
		if brace < 0 {
			continue
		}
		// Body that begins on the catch line, e.g. "} catch (E $e) {}".
		rest := strings.TrimSpace(line[brace+1:])
		if rest == "}" || rest == "" {
			if rest == "}" || bodyIsEmpty(lines, i+1) {
				issues = append(issues, emptyCatchIssue(rel, i+1, line))
			}
			continue
		}
	}
	return issues
}

// bodyIsEmpty reports whether the lines starting at index `from` contain only
// blank/comment lines before the closing brace.
func bodyIsEmpty(lines []string, from int) bool {
	for j := from; j < len(lines); j++ {
		t := strings.TrimSpace(lines[j])
		if t == "" || isComment(t) {
			continue
		}
		return t == "}"
	}
	return false
}

func emptyCatchIssue(rel string, line int, snip string) Issue {
	return Issue{
		RuleID: "ERR_EMPTY_CATCH", Severity: High, Category: "Error Handling",
		Title: "Empty catch block", File: rel, Line: line, Snippet: snippet(snip),
		Explanation:    "A catch block that does nothing swallows the exception, hiding production failures and making them impossible to diagnose.",
		Recommendation: "Log the exception (with context) and handle or rethrow it; never silently discard errors.",
	}
}

// =============================================================================
// Dependency checks (manifest-level)
// =============================================================================

var phpRequireVersion = regexp.MustCompile(`"php"\s*:\s*"[^"]*?([0-9]+)\.([0-9]+)`)
var loosePin = regexp.MustCompile(`:\s*"(\*|dev-master|>=0|latest)"`)

func checkDependencies(rel, name, body string) []Issue {
	var issues []Issue

	if name == "composer.json" {
		if m := phpRequireVersion.FindStringSubmatch(body); m != nil {
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			if major < 7 || (major == 7 && minor < 4) {
				issues = append(issues, Issue{
					RuleID: "DEP_EOL_PHP", Severity: Medium, Category: "Dependencies",
					Title: "End-of-life PHP version requirement", File: rel,
					Line: lineOf(body, m[0]), Snippet: strings.TrimSpace(m[0]),
					Explanation:    "Requiring an EOL PHP version (" + m[1] + "." + m[2] + ") means running without security patches.",
					Recommendation: "Raise the minimum PHP requirement to a supported release (8.1+).",
				})
			}
		}
	}

	if loosePin.MatchString(body) {
		issues = append(issues, Issue{
			RuleID: "DEP_UNPINNED", Severity: Medium, Category: "Dependencies",
			Title: "Unpinned dependency version", File: rel,
			Line: lineOf(body, loosePin.FindString(body)), Snippet: strings.TrimSpace(loosePin.FindString(body)),
			Explanation:    "Wildcard / dev / latest version constraints let dependencies change unexpectedly, breaking reproducible builds.",
			Recommendation: "Pin dependencies to explicit version ranges (e.g. ^1.2) and commit a lock file.",
		})
	}
	return issues
}

// =============================================================================
// Shared helpers
// =============================================================================

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "<!--")
}

func snippet(line string) string {
	s := strings.TrimSpace(line)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// lineOf returns the 1-based line number where substr first appears in body.
func lineOf(body, substr string) int {
	idx := strings.Index(body, substr)
	if idx < 0 {
		return 1
	}
	return strings.Count(body[:idx], "\n") + 1
}
