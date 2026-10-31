# Community Built-in Rule Inventory

Generated from the Go syntax in internal/analyzer/rules.go and internal/analyzer/infra.go for version 0.8.2. Regenerate with go run ./scripts/generate-rule-inventory.go; use -check to detect drift.

**54 distinct built-in analyzer rule IDs:** 29 line rules, 17 infrastructure rules, and 8 specialized checks.

This counts distinct emitted rule IDs, not regex patterns, vulnerabilities, supported frameworks, or guaranteed detections. Multiple token patterns share SEC_TOKEN. OSV CVE findings, external engines, technology detection, log/runtime signals, and private Pro rules are excluded.

A listed file type is eligible input, not full semantic coverage. Severity can vary with context. CWE and OWASP tags are mappings, not certification. See [rating methodology](RATING-METHODOLOGY.md) and the [DVWA reference run](benchmarks/DVWA-v0.8.2.md).

| Rule ID | Check | Scope | Severity | Category | CWE | OWASP | Source |
|---|---|---|---|---|---|---|---|
| APACHE_INDEXES | Web server: directory listing enabled (Options Indexes) | Web-server configuration | Medium | Infrastructure | CWE-548 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L186) |
| CFG_DB_DEBUG | Database debug mode enabled | .php | Medium | Configuration | CWE-209 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/rules.go#L67) |
| CFG_DISPLAY_ERRORS | display_errors enabled | Applicable source files; see implementation | High | Configuration | CWE-209 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/rules.go#L58) |
| COMPOSE_DB_PORT_EXPOSED | Compose: database port published to the host | Compose YAML | Medium | Infrastructure | CWE-668 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L117) |
| COMPOSE_HOST_NETWORK | Compose: host network mode | Compose YAML | Medium | Infrastructure | CWE-16 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L108) |
| COMPOSE_PRIVILEGED | Compose: privileged container | Compose YAML | High | Infrastructure | CWE-250 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L99) |
| DB_RAW_SQL_CONCAT | SQL built with string concatenation | PHP, JS, TS, Python; limited concatenation pattern | High | Database | CWE-89 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L464) |
| DEP_EOL_PHP | End-of-life PHP version requirement | Composer PHP requirement | Medium | Dependencies | CWE-1104 | A06:2021 Vulnerable and Outdated Components | [source](../internal/analyzer/rules.go#L599) |
| DEP_UNPINNED | Unpinned dependency version | Supported dependency manifest checks | Medium | Dependencies | CWE-1104 | A06:2021 Vulnerable and Outdated Components | [source](../internal/analyzer/rules.go#L611) |
| DOCKER_ADD_REMOTE | Dockerfile: ADD from a remote URL | Dockerfile | Medium | Infrastructure | CWE-494 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/infra.go#L70) |
| DOCKER_CURL_PIPE_SH | Dockerfile: piping a downloaded script straight into a shell | Dockerfile | Medium | Infrastructure | CWE-494 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/infra.go#L79) |
| DOCKER_LATEST_TAG | Dockerfile: base image pinned to :latest | Dockerfile | Low | Infrastructure | CWE-1104 | A06:2021 Vulnerable and Outdated Components | [source](../internal/analyzer/infra.go#L61) |
| DOCKER_SECRET_ENV | Dockerfile: hardcoded secret in ENV/ARG | Dockerfile | High | Infrastructure | CWE-798 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L88) |
| DOCKER_USER_ROOT | Dockerfile: container runs as root (USER root) | Dockerfile | Medium | Infrastructure | CWE-250 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L52) |
| ENV_APP_DEBUG | Env file: debug mode enabled | Environment files | Medium | Infrastructure | CWE-489 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L157) |
| ENV_SECRET_COMMITTED | Env file: hardcoded secret committed to the repo | Environment files | High | Infrastructure | CWE-798 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L166) |
| ERR_EMPTY_CATCH | Empty catch block | PHP, JS, TS, Java | High | Error Handling | CWE-755 | A09:2021 Security Logging and Monitoring Failures | [source](../internal/analyzer/rules.go#L576) |
| JAVA_DESERIALIZE | Insecure deserialization (ObjectInputStream) | .java | High | Security | CWE-502 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/rules.go#L263) |
| JAVA_RUNTIME_EXEC | OS command execution (Runtime.exec / ProcessBuilder) | .java | High | Security | CWE-78 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L243) |
| JAVA_SQL_CONCAT | SQL built with string concatenation | .java | High | Database | CWE-89 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L253) |
| JAVA_WEAK_HASH | Weak hash algorithm (MD5 / SHA-1) | .java | Medium | Security | CWE-327 | A02:2021 Cryptographic Failures | [source](../internal/analyzer/rules.go#L273) |
| JS_CHILD_PROCESS | Command execution via child_process | .cjs, .js, .jsx, .mjs, .ts, .tsx | Medium | Security | CWE-78 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L169) |
| JS_DANGEROUS_INNERHTML | Unsanitized HTML injection (dangerouslySetInnerHTML) | .js, .jsx, .ts, .tsx | Medium | Security | CWE-79 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L149) |
| JS_DOM_XSS | Possible DOM XSS (document.write / innerHTML) | .cjs, .js, .jsx, .mjs, .ts, .tsx | Medium | Security | CWE-79 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L159) |
| JS_EVAL | Use of eval() | .js, .jsx, .ts, .tsx | High | Security | CWE-95 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L38) |
| K8S_HOSTPATH | Kubernetes: hostPath volume | Kubernetes YAML | Medium | Infrastructure | CWE-668 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L137) |
| K8S_LATEST_IMAGE | Kubernetes: image pinned to :latest | Kubernetes YAML | Low | Infrastructure | CWE-1104 | A06:2021 Vulnerable and Outdated Components | [source](../internal/analyzer/infra.go#L146) |
| K8S_PRIVILEGED | Kubernetes: privileged container | Kubernetes YAML | High | Infrastructure | CWE-250 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L128) |
| NGINX_AUTOINDEX | Web server: directory listing enabled (autoindex on) | Web-server configuration | Medium | Infrastructure | CWE-548 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L177) |
| NPE_NULLABLE_CHAIN | Possible null reference | PHP | Low | Error Handling | CWE-476 |  | [source](../internal/analyzer/rules.go#L510) |
| PERF_LEADING_WILDCARD_LIKE | Leading-wildcard LIKE | Applicable source files; see implementation | Low | Performance |  |  | [source](../internal/analyzer/rules.go#L86) |
| PERF_SELECT_STAR | SELECT * query | Applicable source files; see implementation | Medium | Performance |  |  | [source](../internal/analyzer/rules.go#L77) |
| PHP_DANGEROUS_EXEC | Dangerous code/command execution function | .php | High | Security | CWE-78 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L28) |
| PHP_SUPERGLOBAL_INPUT | Unvalidated request input | .php | Low | Security | CWE-20 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L48) |
| PY_EVAL_EXEC | Use of eval()/exec() | .py | High | Security | CWE-95 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L181) |
| PY_OS_SYSTEM | Shell command via os.system() | .py | High | Security | CWE-78 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L191) |
| PY_PICKLE | Insecure deserialization (pickle) | .py | High | Security | CWE-502 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/rules.go#L211) |
| PY_SUBPROCESS_SHELL | subprocess with shell=True | .py | High | Security | CWE-78 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L201) |
| PY_TLS_VERIFY_DISABLED | TLS verification disabled (verify=False) | .py | Medium | Security | CWE-295 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/rules.go#L231) |
| PY_YAML_LOAD | Unsafe YAML load | .py | Medium | Security | CWE-502 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/rules.go#L221) |
| RUBY_EVAL | Use of eval / instance_eval | .rb | High | Security | CWE-95 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L285) |
| RUBY_MARSHAL | Insecure deserialization (Marshal.load) | .rb | High | Security | CWE-502 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/rules.go#L315) |
| RUBY_SYSTEM_EXEC | OS command execution (system / exec / %x) | .rb | High | Security | CWE-78 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L295) |
| RUBY_YAML_LOAD | Unsafe YAML load | .rb | Medium | Security | CWE-502 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/rules.go#L305) |
| SEC_HARDCODED_CREDENTIAL | Hardcoded credential | Applicable source files; see implementation | Context-dependent | Security | CWE-798 | A07:2021 Identification and Authentication Failures | [source](../internal/analyzer/rules.go#L402) |
| SEC_INSECURE_DESERIALIZE | Insecure deserialization of request input | .php | High | Security | CWE-502 | A08:2021 Software and Data Integrity Failures | [source](../internal/analyzer/rules.go#L127) |
| SEC_PATH_TRAVERSAL | Unvalidated input in file/include operation (path traversal / LFI) | .php | High | Security | CWE-22 | A01:2021 Broken Access Control | [source](../internal/analyzer/rules.go#L104) |
| SEC_SSRF | Possible SSRF (server-side request forgery) | .php | High | Security | CWE-918 | A10:2021 Server-Side Request Forgery (SSRF) | [source](../internal/analyzer/rules.go#L117) |
| SEC_TLS_VERIFY_DISABLED | TLS/SSL certificate verification disabled | .php | High | Security | CWE-295 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/rules.go#L137) |
| SEC_TOKEN | Known credential/token patterns (multiple patterns share this ID) | Applicable source files; see implementation | Context-dependent | Security | CWE-798 | A07:2021 Identification and Authentication Failures | [source](../internal/analyzer/rules.go#L386) |
| SEC_WEAK_HASH | Weak hashing of credentials | Applicable source files; see implementation | Medium | Security | CWE-327 | A02:2021 Cryptographic Failures | [source](../internal/analyzer/rules.go#L95) |
| WEB_OLD_TLS | Web server: obsolete TLS/SSL protocol enabled | Web-server configuration | Medium | Infrastructure | CWE-327 | A02:2021 Cryptographic Failures | [source](../internal/analyzer/infra.go#L204) |
| WEB_SERVER_TOKENS | Web server: version banner exposed | Web-server configuration | Low | Infrastructure | CWE-200 | A05:2021 Security Misconfiguration | [source](../internal/analyzer/infra.go#L195) |
| XSS_REFLECTED | Possible reflected XSS | PHP | High | Security | CWE-79 | A03:2021 Injection | [source](../internal/analyzer/rules.go#L488) |
