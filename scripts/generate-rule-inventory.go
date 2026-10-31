// Command generate-rule-inventory documents built-in analyzer rule IDs from Go syntax.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type rule struct {
	ID, Severity, Title, Category, Scope, CWE, OWASP, Source, Group string
	Line                                                            int
}

func literal(n ast.Expr) string {
	switch v := n.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, _ := strconv.Unquote(v.Value)
			return s
		}
	case *ast.Ident:
		return v.Name
	}
	return ""
}
func fields(c *ast.CompositeLit) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	for _, e := range c.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			out[literal(kv.Key)] = kv.Value
		}
	}
	return out
}
func main() {
	root := flag.String("root", ".", "Community repository root")
	check := flag.Bool("check", false, "fail if the inventory needs regeneration")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(root string, check bool) error {
	fset := token.NewFileSet()
	meta := map[string][2]string{}
	af, err := parser.ParseFile(fset, filepath.Join(root, "internal/analyzer/analyzer.go"), nil, 0)
	if err != nil {
		return err
	}
	ast.Inspect(af, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if !ok || len(v.Names) != 1 || v.Names[0].Name != "ruleMeta" {
			return true
		}
		c, ok := v.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range c.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			vals, ok := kv.Value.(*ast.CompositeLit)
			if !ok || len(vals.Elts) != 2 {
				continue
			}
			meta[literal(kv.Key)] = [2]string{literal(vals.Elts[0]), literal(vals.Elts[1])}
		}
		return false
	})
	all := map[string]rule{}
	groups := map[string]int{}
	for _, file := range []string{"rules.go", "infra.go"} {
		source := "internal/analyzer/" + file
		parsed, err := parser.ParseFile(fset, filepath.Join(root, source), nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			c, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			fs := fields(c)
			id := literal(fs["id"])
			group := "Line rules"
			if id == "" {
				id = literal(fs["RuleID"])
				group = "Specialized checks"
			}
			if id == "" || id == "r.id" {
				return true
			}
			if _, ok := all[id]; ok {
				return true
			}
			// Only concrete identifiers emitted by rule definitions; ignore expression-derived IDs.
			if _, ok := fs["id"].(*ast.BasicLit); !ok {
				if _, ok := fs["RuleID"].(*ast.BasicLit); !ok {
					return true
				}
			}
			r := rule{ID: id, Source: source, Line: fset.Position(c.Pos()).Line, Group: group}
			r.Title = literal(fs["title"])
			if r.Title == "" {
				r.Title = literal(fs["Title"])
			}
			if r.Title == "" && id == "SEC_TOKEN" {
				r.Title = "Known credential/token patterns (multiple patterns share this ID)"
			}
			r.Severity = literal(fs["severity"])
			if r.Severity == "" {
				r.Severity = literal(fs["Severity"])
			}
			if r.Severity == "" {
				r.Severity = "Context-dependent"
			}
			r.Category = literal(fs["category"])
			if r.Category == "" {
				r.Category = literal(fs["Category"])
			}
			r.CWE = meta[id][0]
			r.OWASP = meta[id][1]
			r.Scope = "Applicable source files; see implementation"
			if ext, ok := fs["exts"].(*ast.CompositeLit); ok {
				names := []string{}
				for _, item := range ext.Elts {
					if kv, ok := item.(*ast.KeyValueExpr); ok {
						names = append(names, literal(kv.Key))
					}
				}
				sort.Strings(names)
				r.Scope = strings.Join(names, ", ")
			}
			if file == "infra.go" {
				r.Group = "Infrastructure rules"
				r.Category = "Infrastructure"
				r.CWE = literal(fs["cwe"])
				r.OWASP = literal(fs["owasp"])
				switch {
				case strings.HasPrefix(id, "DOCKER_"):
					r.Scope = "Dockerfile"
				case strings.HasPrefix(id, "COMPOSE_"):
					r.Scope = "Compose YAML"
				case strings.HasPrefix(id, "K8S_"):
					r.Scope = "Kubernetes YAML"
				case strings.HasPrefix(id, "ENV_"):
					r.Scope = "Environment files"
				default:
					r.Scope = "Web-server configuration"
				}
			}
			switch id {
			case "DB_RAW_SQL_CONCAT":
				r.Scope = "PHP, JS, TS, Python; limited concatenation pattern"
			case "XSS_REFLECTED", "NPE_NULLABLE_CHAIN":
				r.Scope = "PHP"
			case "ERR_EMPTY_CATCH":
				r.Scope = "PHP, JS, TS, Java"
			case "DEP_EOL_PHP":
				r.Scope = "Composer PHP requirement"
			case "DEP_UNPINNED":
				r.Scope = "Supported dependency manifest checks"
			}
			all[id] = r
			groups[r.Group]++
			return true
		})
	}
	ids := []string{}
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return err
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "# Community Built-in Rule Inventory\n\nGenerated from the Go syntax in internal/analyzer/rules.go and internal/analyzer/infra.go for version %s. Regenerate with go run ./scripts/generate-rule-inventory.go; use -check to detect drift.\n\n", strings.TrimSpace(string(version)))
	fmt.Fprintf(&out, "**%d distinct built-in analyzer rule IDs:** %d line rules, %d infrastructure rules, and %d specialized checks.\n\n", len(ids), groups["Line rules"], groups["Infrastructure rules"], groups["Specialized checks"])
	fmt.Fprintln(&out, "This counts distinct emitted rule IDs, not regex patterns, vulnerabilities, supported frameworks, or guaranteed detections. Multiple token patterns share SEC_TOKEN. OSV CVE findings, external engines, technology detection, log/runtime signals, and private Pro rules are excluded.\n\nA listed file type is eligible input, not full semantic coverage. Severity can vary with context. CWE and OWASP tags are mappings, not certification. See [rating methodology](RATING-METHODOLOGY.md) and the [DVWA reference run](benchmarks/DVWA-v0.8.2.md).\n\n| Rule ID | Check | Scope | Severity | Category | CWE | OWASP | Source |\n|---|---|---|---|---|---|---|---|")
	cell := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "/"), "\n", " ") }
	for _, id := range ids {
		r := all[id]
		fmt.Fprintf(&out, "| %s | %s | %s | %s | %s | %s | %s | [source](../%s#L%d) |\n", r.ID, cell(r.Title), cell(r.Scope), r.Severity, r.Category, r.CWE, r.OWASP, r.Source, r.Line)
	}
	path := filepath.Join(root, "docs/RULE-INVENTORY.md")
	if check {
		prev, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(bytes.ReplaceAll(prev, []byte("\r\n"), []byte("\n")), out.Bytes()) {
			return fmt.Errorf("rule inventory is stale; run go run ./scripts/generate-rule-inventory.go")
		}
		fmt.Println("Rule inventory is current.")
		return nil
	}
	if err := os.WriteFile(path, out.Bytes(), 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (%d rule IDs).\n", path, len(ids))
	return nil
}
