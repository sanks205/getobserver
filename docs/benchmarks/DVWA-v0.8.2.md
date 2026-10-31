# DVWA Reference Scan: Observer Community v0.8.2

This is a reproducible static reference run, not an exhaustive detection benchmark, security certification, or comparison with another tool.

## Inputs and provenance

- Project: [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA).
- Source commit: [a1978a2fed195acd093010af6395f86a281537ca](https://github.com/digininja/DVWA/commit/a1978a2fed195acd093010af6395f86a281537ca).
- Source archive SHA-256: 4bd1cb5dda6bdb889055bf0bcdbaf8fd9562ac358bb61918f3c0cb5199a76258.
- Observer: published Community v0.8.2 Windows x64 binary.
- Binary SHA-256: bb7af3859278099e2f92df3fa4f77b968d29ec8b2d0059930c01e584922f8a6c.
- Run date: 2026-10-31 in Asia/Calcutta; the machine-readable timestamp is UTC.
- Mode: built-in engine only, enforced offline, default exclusions.
- No dependency installation, application startup, exploitation, CVE lookup, external engine, or runtime instrumentation was used.

The source was downloaded as an archive, so Observer's Git provenance is unavailable. The source commit, archive digest, extracted-tree digest, tool digest, exact mode, and normalized finding digest are recorded separately in [summary metadata](dvwa-v0.8.2-summary.json).

The original binary predates later documentation and report-template corrections. This run intentionally uses that published binary for reproducibility.

## Reproduce

Requires Python 3.10+ and a published v0.8.2 binary for the current operating system.

~~~powershell
python scripts/benchmark-dvwa.py --observer C:\path\to\observer_windows_amd64.exe --work-dir C:\observer-dvwa-evidence --fetch
~~~

On macOS/Linux, use the same Python script with an appropriate executable and an absolute work directory outside the Community checkout.

The --fetch option permits downloading the pinned source archive before scanning. Without it, the script requires an existing verified archive. The actual Observer scan uses --assert-offline.

The script verifies the binary against known release digests, verifies the archive, checks extracted files for changes, and writes local raw reports plus sanitized findings and summary data. Do not upload the work directory, target source, or raw HTML.

## Results

The scanner counted 250 project files and analyzed 182 eligible source files. It reported **257 finding occurrences across 9 rule IDs**: 28 High, 34 Medium, and 195 Low.

The Security score was 47/100 (F); Code Health was 96/100 (A), using scoring model 2. These are heuristic outputs, not assessed vulnerability counts.

| Rule ID | Occurrences |
|---|---:|
| CFG_DISPLAY_ERRORS | 1 |
| DB_RAW_SQL_CONCAT | 4 |
| JS_DOM_XSS | 6 |
| JS_EVAL | 2 |
| PERF_SELECT_STAR | 7 |
| PHP_DANGEROUS_EXEC | 18 |
| PHP_SUPERGLOBAL_INPUT | 195 |
| SEC_HARDCODED_CREDENTIAL | 3 |
| SEC_WEAK_HASH | 21 |

The broad request-input rule accounts for 195 of 257 findings. This illustrates why raw occurrence totals must not be used as a detection-quality metric.

[Sanitized finding locations](dvwa-v0.8.2-findings.json) omit code snippets and absolute workstation paths. Its SHA-256 is 670b90b984201263b8c3130e27b0b7a0e22dce2135d0425cb38527728b939ddb.

## Reviewed examples and limitations

The following ten observations were selected by Codex for static source review. They are not independent human validation, a random sample, or complete ground truth. No exploit was executed.

| Pinned source location | Classification | Specific rule | Review basis |
|---|---|---|---|
| [vulnerabilities/exec/source/low.php:10](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/exec/source/low.php#L10) | confirmed-risk-pattern | PHP_DANGEROUS_EXEC | Request-derived target reaches shell execution without an observed guard in this low-level example. |
| [vulnerabilities/api/src/Login.php:10](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/api/src/Login.php#L10) | confirmed-risk-pattern | SEC_HARDCODED_CREDENTIAL | A fixed access-token secret is used in token creation and verification. |
| [vulnerabilities/csrf/source/low.php:12](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/csrf/source/low.php#L12) | confirmed-risk-pattern | SEC_WEAK_HASH | MD5 is used to derive a stored password hash. |
| [vulnerabilities/sqli/help/help.php:11](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/sqli/help/help.php#L11) | false-positive | PHP_DANGEROUS_EXEC | Non-executable HTML prose mentions the file system followed by parentheses; it is not a PHP system call. |
| [setup.php:58](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/setup.php#L58) | context-dependent | PHP_DANGEROUS_EXEC | The shell command is a fixed setup diagnostic; an execution primitive is present, but attacker-controlled command injection is not established. |
| [vulnerabilities/exec/source/impossible.php:22](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/exec/source/impossible.php#L22) | context-dependent | PHP_DANGEROUS_EXEC | Numeric checks and reconstruction precede shell execution. A matched function call alone does not establish exploitability. |
| [vulnerabilities/xss_r/source/impossible.php:9](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/xss_r/source/impossible.php#L9) | context-dependent | PHP_SUPERGLOBAL_INPUT | The input expression is passed to an HTML-escaping function; this generic input signal does not prove XSS. |
| [vulnerabilities/sqli/source/low.php:10](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/sqli/source/low.php#L10) | missed-specific-pattern | DB_RAW_SQL_CONCAT | Untrusted input is interpolated into SQL. The specific SQL rule does not fire; generic input findings elsewhere are not equivalent. |
| [vulnerabilities/xss_r/source/low.php:8](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/xss_r/source/low.php#L8) | missed-specific-pattern | XSS_REFLECTED | Unescaped request input is appended to an HTML buffer. The direct-output XSS rule does not fire; a generic input finding does. |
| [vulnerabilities/sqli/source/impossible.php:16](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/vulnerabilities/sqli/source/impossible.php#L16) | safe-counterpart | DB_RAW_SQL_CONCAT | A parameterized query with integer binding is not reported by this SQL rule; this is not a claim that the whole file is secure. |

A false-positive rate, precision, or recall cannot be calculated from this selected set. The two missed specific patterns are examples, not a complete false-negative count. A generic input warning does not demonstrate detection of SQL injection or XSS.

Review labels and source links are also available as [structured data](dvwa-v0.8.2-review.json).

## Interpretation

This run demonstrates real rule execution and concrete coverage limits. It supports neither a claim of comprehensive DVWA coverage nor a claim of superiority over SAST products.

Before publishing broader accuracy claims, define a labeled corpus, review emitted findings and known missed cases, document uncertainty, and measure each supported language and configuration separately.

No third-party source code is redistributed in these evidence files. Source references point to the original pinned DVWA repository.
