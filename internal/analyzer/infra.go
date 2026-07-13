package analyzer

// Infrastructure & configuration scanning (roadmap A2).
//
// Beyond application source, Observer inspects the files that ship an app to
// production — Dockerfiles, docker-compose, Kubernetes manifests, .env files,
// and web-server configs — for high-signal misconfigurations. These findings
// use the "Infrastructure" category (which counts toward the Security score) so
// the report tells the whole-stack story in one pass, no extra flag.
//
// Rules are deliberately conservative (low false-positive) line matches; deeper
// IaC analysis is reserved for the Pro premium packs.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aipda/observer/internal/scanner"
)

type infraKind int

const (
	kindNone infraKind = iota
	kindDockerfile
	kindCompose
	kindK8s
	kindEnv
	kindWebServer
)

type infraRule struct {
	id             string
	severity       Severity
	title          string
	explanation    string
	recommendation string
	cwe            string
	owasp          string
	gates          []string // lowercased; at least one must appear in the line
	re             *regexp.Regexp
}

const infraCategory = "Infrastructure"

var infraRules = map[infraKind][]infraRule{
	kindDockerfile: {
		{
			id: "DOCKER_USER_ROOT", severity: Medium,
			title:          "Dockerfile: container runs as root (USER root)",
			explanation:    "Running the container process as root widens the blast radius of any compromise — a breakout starts with root and a shorter path to the host.",
			recommendation: "Create and switch to a non-root user: RUN adduser -D app && USER app.",
			cwe:            "CWE-250", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"user root"},
			re:    regexp.MustCompile(`(?i)^\s*USER\s+root\s*$`),
		},
		{
			id: "DOCKER_LATEST_TAG", severity: Low,
			title:          "Dockerfile: base image pinned to :latest",
			explanation:    "':latest' is a moving target — builds aren't reproducible and you can silently pull a changed or newly-vulnerable image.",
			recommendation: "Pin the base image to a specific version or digest (e.g. node:20.11-alpine or @sha256:…).",
			cwe:            "CWE-1104", owasp: "A06:2021 Vulnerable and Outdated Components",
			gates: []string{"from"},
			re:    regexp.MustCompile(`(?i)^\s*FROM\s+\S+:latest\b`),
		},
		{
			id: "DOCKER_ADD_REMOTE", severity: Medium,
			title:          "Dockerfile: ADD from a remote URL",
			explanation:    "ADD with an http(s) URL fetches a remote file with no integrity check, so a tampered or MITM'd payload lands in your image.",
			recommendation: "Download with a pinned checksum, then verify it; or vendor the file and COPY it.",
			cwe:            "CWE-494", owasp: "A08:2021 Software and Data Integrity Failures",
			gates: []string{"add "},
			re:    regexp.MustCompile(`(?i)^\s*ADD\s+https?://`),
		},
		{
			id: "DOCKER_CURL_PIPE_SH", severity: Medium,
			title:          "Dockerfile: piping a downloaded script straight into a shell",
			explanation:    "curl|sh (or wget|sh) runs remote code with no verification — a compromised or MITM'd URL executes arbitrary commands at build time.",
			recommendation: "Download to a file, verify a checksum/signature, then execute it.",
			cwe:            "CWE-494", owasp: "A08:2021 Software and Data Integrity Failures",
			gates: []string{"curl", "wget"},
			re:    regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b`),
		},
		{
			id: "DOCKER_SECRET_ENV", severity: High,
			title:          "Dockerfile: hardcoded secret in ENV/ARG",
			explanation:    "Secrets baked into ENV/ARG persist in the image layers and are readable via 'docker history' by anyone who pulls the image.",
			recommendation: "Provide secrets at runtime (env/secret mounts or BuildKit --secret); never bake them into layers.",
			cwe:            "CWE-798", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"password", "secret", "token", "apikey", "api_key", "_key"},
			re:    regexp.MustCompile(`(?i)^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|_KEY)\w*\s*[=\s]\s*["']?[^\s"'$]{4,}`),
		},
	},
	kindCompose: {
		{
			id: "COMPOSE_PRIVILEGED", severity: High,
			title:          "Compose: privileged container",
			explanation:    "'privileged: true' grants almost all host capabilities — a container escape becomes a full host compromise.",
			recommendation: "Remove privileged; grant only the specific cap_add capabilities you actually need.",
			cwe:            "CWE-250", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"privileged"},
			re:    regexp.MustCompile(`(?i)^\s*privileged\s*:\s*true\b`),
		},
		{
			id: "COMPOSE_HOST_NETWORK", severity: Medium,
			title:          "Compose: host network mode",
			explanation:    "network_mode: host removes network isolation — the container shares the host's network stack and can reach or bind host services.",
			recommendation: "Use a bridge/user-defined network and publish only the ports you need.",
			cwe:            "CWE-16", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"network_mode"},
			re:    regexp.MustCompile(`(?i)^\s*network_mode\s*:\s*["']?host\b`),
		},
		{
			id: "COMPOSE_DB_PORT_EXPOSED", severity: Medium,
			title:          "Compose: database port published to the host",
			explanation:    "Publishing a database port (MySQL 3306, Postgres 5432, Mongo 27017, Redis 6379) exposes it on the host interface — frequently reachable from outside by mistake.",
			recommendation: "Don't publish DB ports; let services reach the DB over the internal network. If you must, bind to 127.0.0.1.",
			cwe:            "CWE-668", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"3306", "5432", "27017", "6379"},
			re:    regexp.MustCompile(`^\s*-\s*["']?[0-9.:]*:(3306|5432|27017|6379)["']?\s*$`),
		},
	},
	kindK8s: {
		{
			id: "K8S_PRIVILEGED", severity: High,
			title:          "Kubernetes: privileged container",
			explanation:    "securityContext.privileged: true gives the pod near-host capabilities — a compromise can escape to the node.",
			recommendation: "Set privileged: false; add only the specific capabilities required.",
			cwe:            "CWE-250", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"privileged"},
			re:    regexp.MustCompile(`(?i)^\s*privileged\s*:\s*true\b`),
		},
		{
			id: "K8S_HOSTPATH", severity: Medium,
			title:          "Kubernetes: hostPath volume",
			explanation:    "A hostPath volume mounts a node's filesystem into the pod — a compromised pod can read or tamper with host files.",
			recommendation: "Prefer PVCs/configMaps/secrets; avoid hostPath except for well-justified, read-only cases.",
			cwe:            "CWE-668", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"hostpath"},
			re:    regexp.MustCompile(`(?i)^\s*hostPath\s*:`),
		},
		{
			id: "K8S_LATEST_IMAGE", severity: Low,
			title:          "Kubernetes: image pinned to :latest",
			explanation:    "':latest' makes rollouts non-reproducible and can silently pull a changed or vulnerable image.",
			recommendation: "Pin images to an immutable tag or digest.",
			cwe:            "CWE-1104", owasp: "A06:2021 Vulnerable and Outdated Components",
			gates: []string{"image"},
			re:    regexp.MustCompile(`(?i)^\s*(-\s+)?image\s*:\s*["']?\S+:latest\b`),
		},
	},
	kindEnv: {
		{
			id: "ENV_APP_DEBUG", severity: Medium,
			title:          "Env file: debug mode enabled",
			explanation:    "APP_DEBUG=true (or DEBUG=true) exposes detailed stack traces, environment values, and config to anyone who triggers an error in production.",
			recommendation: "Set APP_DEBUG=false / DEBUG=false in the production environment.",
			cwe:            "CWE-489", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"debug"},
			re:    regexp.MustCompile(`(?i)^\s*(APP_)?DEBUG\s*=\s*(true|1)\b`),
		},
		{
			id: "ENV_SECRET_COMMITTED", severity: High,
			title:          "Env file: hardcoded secret committed to the repo",
			explanation:    "A .env with a real secret value in the codebase leaks that credential to everyone with repo access (and anywhere the repo is mirrored).",
			recommendation: "Remove the value, commit only a .env.example with placeholders, load real secrets from the environment/secret store, and rotate the exposed credential.",
			cwe:            "CWE-798", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"password", "secret", "token", "apikey", "api_key", "_key"},
			re:    regexp.MustCompile(`(?i)^\s*\w*(PASSWORD|SECRET|TOKEN|API_?KEY|_KEY)\w*\s*=\s*["']?[^\s"'#]{6,}`),
		},
	},
	kindWebServer: {
		{
			id: "NGINX_AUTOINDEX", severity: Medium,
			title:          "Web server: directory listing enabled (autoindex on)",
			explanation:    "autoindex on exposes a browsable file listing, revealing files and structure an attacker can mine.",
			recommendation: "Set autoindex off (nginx) and remove it from any location that shouldn't be browsable.",
			cwe:            "CWE-548", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"autoindex"},
			re:    regexp.MustCompile(`(?i)^\s*autoindex\s+on\s*;`),
		},
		{
			id: "APACHE_INDEXES", severity: Medium,
			title:          "Web server: directory listing enabled (Options Indexes)",
			explanation:    "The Apache 'Indexes' option serves a browsable directory listing when no index file is present, exposing files and structure.",
			recommendation: "Remove Indexes from Options (e.g. Options -Indexes).",
			cwe:            "CWE-548", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"indexes"},
			re:    regexp.MustCompile(`(?i)^\s*Options\s+[^#\n]*\bIndexes\b`),
		},
		{
			id: "WEB_SERVER_TOKENS", severity: Low,
			title:          "Web server: version banner exposed",
			explanation:    "Emitting the server version (server_tokens on / ServerTokens Full) hands attackers a head start on matching known CVEs.",
			recommendation: "Set server_tokens off (nginx) or ServerTokens Prod (Apache).",
			cwe:            "CWE-200", owasp: "A05:2021 Security Misconfiguration",
			gates: []string{"server_tokens", "servertokens"},
			re:    regexp.MustCompile(`(?i)^\s*(server_tokens\s+on\s*;|ServerTokens\s+(Full|OS|Major|Minor|Min)\b)`),
		},
		{
			id: "WEB_OLD_TLS", severity: Medium,
			title:          "Web server: obsolete TLS/SSL protocol enabled",
			explanation:    "TLSv1.0/1.1 and SSLv2/3 are broken and enable downgrade/MITM attacks.",
			recommendation: "Allow only TLSv1.2 and TLSv1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;).",
			cwe:            "CWE-327", owasp: "A02:2021 Cryptographic Failures",
			gates: []string{"ssl_protocol", "sslprotocol"},
			re:    regexp.MustCompile(`(?i)(ssl_protocols|SSLProtocol)\b[^#\n]*(SSLv2|SSLv3|TLSv1(\.[01])?\b)`),
		},
	},
}

// scanInfra walks root and applies the infrastructure rules to the config files
// it recognizes, returning the findings and the number of infra files scanned.
func scanInfra(root string) ([]Issue, int) {
	var issues []Issue
	scanned := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if p != root && (scanner.IsIgnoredDir(d.Name()) || vendoredDirs[name] || isFrameworkCore(p, name)) {
				return fs.SkipDir
			}
			return nil
		}
		if info, e := d.Info(); e == nil && info.Size() > 512*1024 {
			return nil // config files are small; skip anything huge
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		content := string(data)
		kind := classifyInfra(p, content)
		rules := infraRules[kind]
		if len(rules) == 0 {
			return nil
		}
		scanned++
		rel := relPath(root, p)
		for i, raw := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			low := strings.ToLower(raw)
			for r := range rules {
				ru := &rules[r]
				if !infraGated(low, ru.gates) || !ru.re.MatchString(raw) {
					continue
				}
				if ru.id == "COMPOSE_DB_PORT_EXPOSED" && (strings.Contains(low, "127.0.0.1") || strings.Contains(low, "localhost")) {
					continue // bound to loopback — not published to the host interface
				}
				if ru.id == "ENV_SECRET_COMMITTED" && isPlaceholderValue(raw) {
					continue
				}
				issues = append(issues, Issue{
					RuleID: ru.id, Severity: ru.severity, Category: infraCategory,
					Title: ru.title, File: rel, Line: i + 1, Snippet: infraSnippet(trimmed),
					Explanation: ru.explanation, Recommendation: ru.recommendation,
					CWE: ru.cwe, OWASP: ru.owasp,
				})
			}
		}
		return nil
	})
	return issues, scanned
}

// classifyInfra determines which infra rule set (if any) applies to a file.
// content is used to tell Kubernetes manifests apart from other YAML.
func classifyInfra(path, content string) infraKind {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile"):
		return kindDockerfile
	case base == "compose.yml" || base == "compose.yaml" ||
		(strings.HasPrefix(base, "docker-compose") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))):
		return kindCompose
	case base == ".env" || strings.HasPrefix(base, ".env"):
		if strings.Contains(base, "example") || strings.Contains(base, "sample") || strings.Contains(base, "dist") || strings.Contains(base, "template") {
			return kindNone // templates hold placeholders, not real secrets
		}
		return kindEnv
	case base == "nginx.conf" || base == ".htaccess" || base == "httpd.conf" || base == "apache2.conf":
		return kindWebServer
	case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
		if strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:") {
			return kindK8s
		}
		return kindNone
	}
	return kindNone
}

func infraGated(lowLine string, gates []string) bool {
	if len(gates) == 0 {
		return true
	}
	for _, g := range gates {
		if strings.Contains(lowLine, g) {
			return true
		}
	}
	return false
}

// isPlaceholderValue reports whether an assignment's value is an obvious
// placeholder (env var reference, empty, or a template token), so we don't flag
// a .env.example-style line as a committed secret.
func isPlaceholderValue(line string) bool {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return true
	}
	v := strings.TrimSpace(line[i+1:])
	v = strings.Trim(v, `"'`)
	if v == "" || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$(") || strings.HasPrefix(v, "<") {
		return true
	}
	low := strings.ToLower(v)
	for _, ph := range []string{"changeme", "change_me", "your_", "your-", "xxx", "placeholder", "example", "todo", "secret_here", "null", "none"} {
		if strings.Contains(low, ph) {
			return true
		}
	}
	return false
}

func infraSnippet(s string) string {
	const max = 160
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
