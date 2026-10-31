# Rating and Standards Methodology

Observer reports two different summaries. Neither establishes compliance or proves security.

## Security severity grade: A-E

This is an Observer-defined grade based on the most severe detected finding in the Security, Database, Dependencies, Configuration, or Infrastructure categories.

| Grade | Worst detected security severity |
|---|---|
| A | No security-category findings detected |
| B | Low |
| C | Medium |
| D | High |
| E | Critical |

One Critical finding gives grade E regardless of project size. Grade A means no applicable finding was detected, not that the project is secure.

## Numerical scores and A-F labels

The 0-100 Security and Code Health scores summarize finding density separately:

- Weighted findings = 15 per Critical + 5 per High + 1 per Medium + 0.2 per Low.
- Density = weighted findings divided by eligible source files analyzed, with a minimum denominator of one.
- Score = 100 / (1 + density), rounded to the nearest integer.
- A Critical finding caps the relevant score at 79.
- The nonempty-result score is at least 1; a result with no findings scores 100.
- Letter thresholds: A at 90+, B at 80+, C at 70+, D at 60+, and F below 60. There is no E in this numerical-score scale.

The Security score includes the security-related categories above. Code Health uses the remaining categories. The built-in health score excludes external-engine findings; overall health can include enabled external engines.

The A-E severity grade and the numerical score describe different things. Enabled engines, exclusions, baseline filtering, and changed-code scope affect the inputs. Compare like-for-like configurations.

Source: [analyzer.go](../internal/analyzer/analyzer.go).

## CWE, OWASP, and indicative control mappings

Rules can attach CWE identifiers and OWASP Top 10 (2021) categories. These labels classify a matched pattern; they do not establish exploitability or complete coverage of an OWASP category.

The compliance report also contains indicative PCI-DSS and ISO/IEC 27001 control associations. They are discussion aids, not audited conformance. Insecure design cannot be established by these line rules.

Displayed CVSS-style values are severity-bucket representatives, not independently calculated CVSS vectors.

Source: [compliance.go](../internal/compliance/compliance.go) and the [rule inventory](RULE-INVENTORY.md).

## Evidence limits

A project can receive findings in safe or non-executable text, and vulnerable code can be missed. See the [DVWA reference scan](benchmarks/DVWA-v0.8.2.md). Reports require engineering review; counts, grades, and scores are not vulnerability totals or a universal false-positive rate.
