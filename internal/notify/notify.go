// Package notify sends scan summaries to chat/webhook endpoints (Theme 2 polish).
//
// It supports Slack and Microsoft Teams incoming webhooks and generic webhooks.
// All are opt-in (a URL must be provided) and fail gracefully so a delivery
// problem never breaks a scan. No third-party SDKs — just net/http + JSON.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Summary is the data rendered into a notification message.
type Summary struct {
	Project       string
	SecurityScore int
	SecurityGrade string
	HealthScore   int
	HealthGrade   string
	Total         int
	Critical      int
	High          int
	Medium        int
	Low           int
	TopIssues     []string // e.g. "[Critical] Hardcoded key — c.php:7"
}

func (s Summary) headline() string {
	return fmt.Sprintf("Observer scan: %s — Security %d (%s), Code Health %d (%s)",
		s.Project, s.SecurityScore, s.SecurityGrade, s.HealthScore, s.HealthGrade)
}

func (s Summary) countsLine() string {
	return fmt.Sprintf("%d finding(s): %d critical, %d high, %d medium, %d low",
		s.Total, s.Critical, s.High, s.Medium, s.Low)
}

// SlackPayload builds a Slack incoming-webhook JSON body.
func SlackPayload(s Summary) []byte {
	var b strings.Builder
	b.WriteString("*" + s.headline() + "*\n")
	b.WriteString(s.countsLine())
	if len(s.TopIssues) > 0 {
		b.WriteString("\n*Top issues:*\n• " + strings.Join(s.TopIssues, "\n• "))
	}
	out, _ := json.Marshal(map[string]string{"text": b.String()})
	return out
}

// TeamsPayload builds a Microsoft Teams MessageCard JSON body.
func TeamsPayload(s Summary) []byte {
	text := s.countsLine()
	if len(s.TopIssues) > 0 {
		text += "<br/>**Top issues:**<br/>" + strings.Join(s.TopIssues, "<br/>")
	}
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": themeColor(s),
		"summary":    "Observer scan: " + s.Project,
		"title":      s.headline(),
		"text":       text,
	}
	out, _ := json.Marshal(card)
	return out
}

func themeColor(s Summary) string {
	switch {
	case s.Critical > 0:
		return "D7191C" // red
	case s.High > 0:
		return "FDAE61" // orange
	default:
		return "1A9641" // green
	}
}

// Post sends payload as application/json to url and verifies a 2xx response.
func Post(ctx context.Context, url string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
