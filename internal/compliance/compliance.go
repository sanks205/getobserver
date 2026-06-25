// Package compliance maps findings to security standards (Phase 3 / Theme 3).
//
// Observer already tags findings with CWE and OWASP Top 10 categories; this
// package rolls those up into an audit-oriented view: OWASP Top 10 coverage, a
// CWE breakdown, and an indicative mapping to PCI-DSS requirements and ISO/IEC
// 27001 Annex A controls.
//
// The mapping is indicative — it helps teams discuss and evidence compliance.
// It is not a certification and does not guarantee conformance.
package compliance

import (
	"sort"
	"strings"

	"github.com/aipda/observer/internal/analyzer"
)

type owaspCat struct {
	Code       string
	Name       string
	Assessable bool // does Observer have any rule that maps here?
}

// owaspTop10 is the OWASP Top 10 (2021).
var owaspTop10 = []owaspCat{
	{"A01", "Broken Access Control", true},
	{"A02", "Cryptographic Failures", true},
	{"A03", "Injection", true},
	{"A04", "Insecure Design", false}, // design flaws aren't detectable by static rules
	{"A05", "Security Misconfiguration", true},
	{"A06", "Vulnerable and Outdated Components", true},
	{"A07", "Identification and Authentication Failures", true},
	{"A08", "Software and Data Integrity Failures", true},
	{"A09", "Security Logging and Monitoring Failures", true},
	{"A10", "Server-Side Request Forgery (SSRF)", true},
}

type frameworkMap struct {
	Area   string
	PCIDSS string
	ISO    string
}

// owaspToFramework maps each assessable OWASP category to an indicative PCI-DSS
// requirement and ISO/IEC 27001:2022 Annex A control.
var owaspToFramework = map[string]frameworkMap{
	"A01": {"Access control", "Req 7 — Restrict access by need-to-know", "A.8.3 Information access restriction"},
	"A02": {"Cryptography", "Req 3 & 4 — Protect stored & transmitted data", "A.8.24 Use of cryptography"},
	"A03": {"Injection", "Req 6.2.4 — Prevent injection flaws", "A.8.28 Secure coding"},
	"A05": {"Configuration", "Req 2.2 — Secure system configuration", "A.8.9 Configuration management"},
	"A06": {"Dependencies", "Req 6.3.3 — Patch known vulnerabilities", "A.8.8 Mgmt of technical vulnerabilities"},
	"A07": {"Authentication", "Req 8 — Identify & authenticate access", "A.5.17 Authentication information"},
	"A08": {"Data integrity", "Req 6.5 — Change & integrity control", "A.8.28 Secure coding"},
	"A09": {"Logging", "Req 10 — Log & monitor all access", "A.8.15 Logging"},
	"A10": {"SSRF", "Req 6.2.4 — Secure coding practices", "A.8.28 Secure coding"},
}

// OWASPRow is one OWASP Top 10 category's coverage status.
type OWASPRow struct {
	Code   string
	Name   string
	Count  int
	Status string // "Issues found" | "No issues detected" | "Not assessed"
}

// FrameworkRow maps a security area to PCI-DSS / ISO with trigger status.
type FrameworkRow struct {
	Area   string
	OWASP  string
	PCIDSS string
	ISO    string
	Count  int
	Status string // "Action needed" | "OK"
}

// CWERow is a CWE and how many findings reference it.
type CWERow struct {
	ID    string
	Count int
}

// Report is the full compliance roll-up.
type Report struct {
	OWASP      []OWASPRow
	Frameworks []FrameworkRow
	CWE        []CWERow
}

// Build rolls findings up into a compliance report.
func Build(issues []analyzer.Issue) *Report {
	byCode := map[string]int{}
	byCWE := map[string]int{}
	for _, is := range issues {
		owasp := is.OWASP
		if owasp == "" {
			owasp = analyzer.OWASPFor(is.RuleID)
		}
		if c := codeOf(owasp); c != "" {
			byCode[c]++
		}
		cwe := is.CWE
		if cwe == "" {
			cwe = analyzer.CWEFor(is.RuleID)
		}
		if cwe != "" {
			byCWE[cwe]++
		}
	}

	rep := &Report{}
	for _, cat := range owaspTop10 {
		row := OWASPRow{Code: cat.Code, Name: cat.Name, Count: byCode[cat.Code]}
		switch {
		case !cat.Assessable:
			row.Status = "Not assessed"
		case row.Count > 0:
			row.Status = "Issues found"
		default:
			row.Status = "No issues detected"
		}
		rep.OWASP = append(rep.OWASP, row)

		if fm, ok := owaspToFramework[cat.Code]; ok {
			fr := FrameworkRow{
				Area: fm.Area, OWASP: cat.Code, PCIDSS: fm.PCIDSS, ISO: fm.ISO, Count: byCode[cat.Code],
			}
			if fr.Count > 0 {
				fr.Status = "Action needed"
			} else {
				fr.Status = "OK"
			}
			rep.Frameworks = append(rep.Frameworks, fr)
		}
	}

	for id, n := range byCWE {
		rep.CWE = append(rep.CWE, CWERow{ID: id, Count: n})
	}
	sort.SliceStable(rep.CWE, func(i, j int) bool {
		if rep.CWE[i].Count != rep.CWE[j].Count {
			return rep.CWE[i].Count > rep.CWE[j].Count
		}
		return rep.CWE[i].ID < rep.CWE[j].ID
	})
	return rep
}

// codeOf extracts the OWASP code ("A03") from a tag like "A03:2021 Injection"
// or Semgrep's "A03:2021 - Injection".
func codeOf(owasp string) string {
	owasp = strings.TrimSpace(owasp)
	if owasp == "" {
		return ""
	}
	fields := strings.FieldsFunc(owasp, func(r rune) bool { return r == ':' || r == ' ' })
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
