package ai

// remediation holds generic, vulnerability-class-level guidance used to enrich
// insights in local (no-LLM) mode. It is intentionally *generic* — facts about
// the class of issue, not fabricated specifics about the user's code — so it
// honors the rule that the assistant explains rather than invents.
type remediation struct {
	Exploit    string
	Complexity string // Low | Medium | High
	Effort     string
	FixExample string
}

// remByCWE maps a CWE id to remediation guidance for the common classes.
var remByCWE = map[string]remediation{
	"CWE-798": { // hardcoded credentials / secrets
		Exploit:    "Anyone with source/repo access (or via a leak) can use the credential to access the linked service or data.",
		Complexity: "Low", Effort: "~15 min",
		FixExample: "Before: $apiKey = \"sk_live_abc123\";\nAfter:  $apiKey = getenv(\"STRIPE_API_KEY\"); // load from env/secret store, rotate the leaked key",
	},
	"CWE-89": { // SQL injection
		Exploit:    "An attacker submits crafted input (e.g. ' OR '1'='1) to read, modify, or delete database records.",
		Complexity: "Medium", Effort: "~30 min per query",
		FixExample: "Before: $db->query(\"SELECT * FROM users WHERE id = \" . $id);\nAfter:  $db->query(\"SELECT * FROM users WHERE id = ?\", [$id]); // parameterized",
	},
	"CWE-79": { // XSS
		Exploit:    "An attacker supplies a value containing <script>…</script>; it executes in another user's browser (session theft, defacement).",
		Complexity: "Low", Effort: "~15 min",
		FixExample: "Before: echo $_GET['name'];\nAfter:  echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');",
	},
	"CWE-78": { // OS command injection
		Exploit:    "Crafted input is concatenated into a shell command, letting an attacker run arbitrary commands on the server.",
		Complexity: "Medium", Effort: "~30–60 min",
		FixExample: "Before: exec(\"convert \" . $_GET['f']);\nAfter:  exec('convert ' . escapeshellarg($file)); // validate against an allow-list",
	},
	"CWE-95": { // eval injection
		Exploit:    "Attacker-controlled input reaches eval(), executing arbitrary code.",
		Complexity: "Medium", Effort: "~30–60 min",
		FixExample: "Replace eval() with a safe alternative (JSON.parse, a function/lookup map).",
	},
	"CWE-22": { // path traversal / LFI
		Exploit:    "Input like ../../etc/passwd lets an attacker read or include files outside the intended directory.",
		Complexity: "Medium", Effort: "~30 min",
		FixExample: "Before: include $_GET['page'];\nAfter:  $allowed = ['home'=>'home.php']; include $allowed[$_GET['page']] ?? '404.php';",
	},
	"CWE-918": { // SSRF
		Exploit:    "An attacker supplies an internal URL (e.g. http://169.254.169.254/) so the server fetches internal resources/metadata.",
		Complexity: "Medium", Effort: "~1 hour",
		FixExample: "Validate the URL against an allow-list of hosts/schemes before making the request; block private IP ranges.",
	},
	"CWE-502": { // insecure deserialization
		Exploit:    "Crafted serialized input triggers object injection, which can escalate to remote code execution.",
		Complexity: "Medium", Effort: "~1 hour",
		FixExample: "Before: $o = unserialize($_POST['data']);\nAfter:  $o = json_decode($_POST['data'], true); // or unserialize($x, ['allowed_classes' => false])",
	},
	"CWE-295": { // TLS verification disabled
		Exploit:    "With verification off, a man-in-the-middle can present any certificate and intercept/modify the HTTPS traffic.",
		Complexity: "Low", Effort: "~10 min",
		FixExample: "Before: curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\nAfter:  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);",
	},
	"CWE-327": { // weak crypto / hashing
		Exploit:    "md5/sha1 hashes are fast and unsalted, so leaked password hashes can be brute-forced quickly.",
		Complexity: "Medium", Effort: "~30 min",
		FixExample: "Before: $h = md5($password);\nAfter:  $h = password_hash($password, PASSWORD_DEFAULT); // bcrypt/argon2",
	},
	"CWE-352": { // CSRF
		Exploit:    "A malicious page makes an authenticated user's browser submit a forged state-changing request (transfer, password/email change) without their intent.",
		Complexity: "Low", Effort: "~20 min",
		FixExample: "Enable CSRF protection and include the token in every form.\nCodeIgniter: $config['csrf_protection'] = TRUE;\nLaravel:     add the @csrf directive inside each <form>.",
	},
	"CWE-321": { // empty / hardcoded encryption key
		Exploit:    "A missing or hardcoded key lets anyone who knows (or guesses) it forge sessions/tokens or decrypt data.",
		Complexity: "Low", Effort: "~15 min",
		FixExample: "Load a strong, random key from the environment — never commit it.\nBefore: $config['encryption_key'] = '';\nAfter:  $config['encryption_key'] = getenv('APP_KEY'); // 32+ random bytes",
	},
	"CWE-209": { // info exposure via errors / debug
		Exploit:    "Verbose errors leak stack traces, queries, and paths that help an attacker map the system.",
		Complexity: "Low", Effort: "~10 min",
		FixExample: "Disable display_errors / debug in production; log errors to a file instead.",
	},
	"CWE-20": { // improper input validation
		Exploit:    "Unvalidated request input flows into queries, file paths, or output, enabling injection attacks.",
		Complexity: "Low", Effort: "~15 min",
		FixExample: "Validate/sanitize input (filter_input, the framework's validation layer) before use.",
	},
	"CWE-1104": { // outdated / unmaintained components
		Exploit:    "Known CVEs in outdated dependencies are publicly documented and trivially exploitable.",
		Complexity: "Low", Effort: "~15–30 min",
		FixExample: "Upgrade the dependency to a patched version; pin it and commit the lock file.",
	},
	"CWE-1395": { // vulnerable dependency (CVE)
		Exploit:    "The dependency has a published advisory; exploit details are often public.",
		Complexity: "Low", Effort: "~15–30 min",
		FixExample: "Upgrade to the fixed version named in the advisory; re-run the scan to confirm.",
	},
	"CWE-755": { // empty catch / error handling
		Exploit:    "Not directly exploitable, but swallowed exceptions hide failures and security events from monitoring.",
		Complexity: "Low", Effort: "~10 min",
		FixExample: "Log the exception (with context) and handle or rethrow it — never discard it silently.",
	},
	"CWE-476": { // null reference
		Exploit:    "Not directly exploitable; causes runtime fatals/crashes when the nullable value is empty.",
		Complexity: "Low", Effort: "~10 min",
		FixExample: "Check the result for null before dereferencing it.",
	},
}

// remByCategory is the fallback when a finding has no CWE.
var remByCategory = map[string]remediation{
	"Performance": {
		Exploit:    "Not a security issue; degrades performance and scalability under load.",
		Complexity: "Low", Effort: "~15–30 min",
		FixExample: "Select only needed columns / add appropriate indexes / avoid leading-wildcard LIKE.",
	},
	"Error Handling": {
		Exploit:    "Not directly exploitable; hides failures and complicates debugging and monitoring.",
		Complexity: "Low", Effort: "~10–20 min",
		FixExample: "Handle, log, and surface errors; guard nullable values before use.",
	},
	"Runtime": {
		Exploit:    "A real production failure that has already occurred for users.",
		Complexity: "Medium", Effort: "varies",
		FixExample: "Reproduce from the stack trace, fix the root cause, and add a regression test.",
	},
}

// GenericFix returns the built-in, offline before→after remediation example for
// a finding's CWE (falling back to its category). It lets the report show a
// suggested fix for every finding even without --ai; returns "" when there is no
// specific guidance for that class. The guidance is generic (about the issue
// class, not the user's code), so it never fabricates specifics.
func GenericFix(cwe, category string) string {
	return remediationFor(Finding{CWE: cwe, Category: category}).FixExample
}

// remediationFor returns the best-matching guidance for a finding: by CWE first,
// then by category, then a neutral default.
func remediationFor(f Finding) remediation {
	if r, ok := remByCWE[f.CWE]; ok {
		return r
	}
	if r, ok := remByCategory[f.Category]; ok {
		return r
	}
	return remediation{Complexity: "Medium", Effort: "varies"}
}
