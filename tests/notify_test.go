package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aipda/observer/internal/notify"
)

func sampleSummary() notify.Summary {
	return notify.Summary{
		Project: "ronspot", SecurityScore: 21, SecurityGrade: "F",
		HealthScore: 29, HealthGrade: "F",
		Total: 6553, Critical: 5, High: 639, Medium: 5848, Low: 61,
		TopIssues: []string{"[Critical] Hardcoded AWS access key — s3.php:36"},
	}
}

func TestSlackPayload(t *testing.T) {
	var m map[string]string
	if err := json.Unmarshal(notify.SlackPayload(sampleSummary()), &m); err != nil {
		t.Fatalf("slack payload not valid JSON: %v", err)
	}
	if !strings.Contains(m["text"], "ronspot") || !strings.Contains(m["text"], "Hardcoded AWS") {
		t.Errorf("slack text missing content: %q", m["text"])
	}
}

func TestTeamsPayload(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(notify.TeamsPayload(sampleSummary()), &m); err != nil {
		t.Fatalf("teams payload not valid JSON: %v", err)
	}
	if m["@type"] != "MessageCard" {
		t.Errorf("teams payload @type = %v, want MessageCard", m["@type"])
	}
	if m["themeColor"] != "D7191C" { // has criticals -> red
		t.Errorf("themeColor = %v, want red (criticals present)", m["themeColor"])
	}
}

func TestPostToMockWebhook(t *testing.T) {
	var got []byte
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		ct = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := notify.SlackPayload(sampleSummary())
	if err := notify.Post(context.Background(), srv.URL, payload); err != nil {
		t.Fatalf("post failed: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if len(got) == 0 || !strings.Contains(string(got), "ronspot") {
		t.Errorf("server did not receive payload: %q", string(got))
	}
}

func TestPostNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := notify.Post(context.Background(), srv.URL, []byte("{}")); err == nil {
		t.Error("expected error on 500 response")
	}
}
