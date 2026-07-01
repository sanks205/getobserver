package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Vuln is a known vulnerability affecting a dependency.
type Vuln struct {
	ID        string
	Summary   string
	Severity  string // Critical | High | Medium | Low
	Package   string
	Version   string
	Ecosystem string
	Source    string // manifest filename
}

// Report is the outcome of a dependency vulnerability scan.
type Report struct {
	DepsScanned int
	Vulns       []Vuln
}

// Client queries the OSV.dev API. BaseURL is overridable (env OSV_BASE_URL) for
// testing against a mock server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client targeting OSV (or OSV_BASE_URL if set).
func NewClient() *Client {
	base := os.Getenv("OSV_BASE_URL")
	if base == "" {
		base = "https://api.osv.dev"
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 45 * time.Second}}
}

const maxVulnDetails = 100 // cap detail lookups to keep scans bounded

// Scan parses manifests under root and queries OSV for vulnerabilities.
func Scan(root string, c *Client) (*Report, error) {
	depList, err := Parse(root)
	if err != nil {
		return nil, err
	}
	rep := &Report{DepsScanned: len(depList)}
	if len(depList) == 0 {
		return rep, nil
	}
	vulns, err := c.query(context.Background(), depList)
	if err != nil {
		return nil, err
	}
	rep.Vulns = vulns
	return rep, nil
}

// --- OSV API types ---

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type batchResult struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}
type vulnDetail struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// query runs a batch lookup, then fetches details for each distinct vuln id.
func (c *Client) query(ctx context.Context, deps []Dep) ([]Vuln, error) {
	body := struct {
		Queries []osvQuery `json:"queries"`
	}{}
	for _, d := range deps {
		body.Queries = append(body.Queries, osvQuery{
			Version: d.Version,
			Package: osvPackage{Name: d.Name, Ecosystem: d.Ecosystem},
		})
	}
	var batch batchResult
	if err := c.postJSON(ctx, "/v1/querybatch", body, &batch); err != nil {
		return nil, err
	}

	var vulns []Vuln
	detailCache := map[string]vulnDetail{}
	lookups := 0
	for i, res := range batch.Results {
		if i >= len(deps) {
			break
		}
		for _, v := range res.Vulns {
			vd, ok := detailCache[v.ID]
			if !ok && lookups < maxVulnDetails {
				if d, err := c.fetchVuln(ctx, v.ID); err == nil {
					vd, detailCache[v.ID] = d, d
				}
				lookups++
			}
			summary := vd.Summary
			if summary == "" {
				summary = firstLine(vd.Details)
			}
			vulns = append(vulns, Vuln{
				ID:        v.ID,
				Summary:   summary,
				Severity:  mapSeverity(vd),
				Package:   deps[i].Name,
				Version:   deps[i].Version,
				Ecosystem: deps[i].Ecosystem,
				Source:    deps[i].Source,
			})
		}
	}
	return vulns, nil
}

func (c *Client) fetchVuln(ctx context.Context, id string) (vulnDetail, error) {
	var vd vulnDetail
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return vd, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return vd, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if resp.StatusCode != http.StatusOK {
		return vd, fmt.Errorf("osv: vuln %s status %d", id, resp.StatusCode)
	}
	return vd, json.Unmarshal(data, &vd)
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	buf, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s status %d", path, resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

// mapSeverity converts OSV severity hints into our scale; a vuln of unknown
// severity is treated as High (safer than understating).
func mapSeverity(vd vulnDetail) string {
	s := strings.ToUpper(vd.DatabaseSpecific.Severity)
	switch {
	case strings.Contains(s, "CRIT"):
		return "Critical"
	case strings.Contains(s, "HIGH"):
		return "High"
	case strings.Contains(s, "MOD"), strings.Contains(s, "MED"):
		return "Medium"
	case strings.Contains(s, "LOW"):
		return "Low"
	}
	// Fall back to a CVSS base score if present (e.g. "9.8" or a vector with it).
	for _, sev := range vd.Severity {
		if r := bucketCVSS(sev.Score); r != "" {
			return r
		}
	}
	return "High"
}

// bucketCVSS extracts a leading numeric CVSS base score and buckets it.
func bucketCVSS(score string) string {
	score = strings.TrimSpace(score)
	// Some entries store a bare number; vectors ("CVSS:3.1/...") have no leading number.
	var f float64
	if _, err := fmt.Sscanf(score, "%g", &f); err != nil || f == 0 {
		return ""
	}
	switch {
	case f >= 9.0:
		return "Critical"
	case f >= 7.0:
		return "High"
	case f >= 4.0:
		return "Medium"
	default:
		return "Low"
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
