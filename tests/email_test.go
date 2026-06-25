package tests

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aipda/observer/internal/email"
)

func testMessage() email.Message {
	return email.Message{
		Subject:  "Observer report: demo — 3 issue(s)",
		HTMLBody: "<h2>Summary</h2><p>3 issues found.</p>",
		Attachment: &email.Attachment{
			Filename: "report.html",
			Data:     []byte("<html><body>full report</body></html>"),
			MIME:     "text/html",
		},
	}
}

func TestParseRecipients(t *testing.T) {
	got := email.ParseRecipients("a@x.com, b@y.com ;c@z.com")
	if len(got) != 3 {
		t.Fatalf("parsed %d recipients, want 3: %v", len(got), got)
	}
}

func TestValidate(t *testing.T) {
	// No recipients -> error.
	if err := (email.Config{}).Validate(); err == nil {
		t.Error("expected error with no recipients")
	}
	// Non-dry-run without host -> error.
	if err := (email.Config{To: []string{"a@x.com"}}).Validate(); err == nil {
		t.Error("expected error when SMTP_HOST missing and not dry-run")
	}
	// Dry-run with recipients -> ok.
	if err := (email.Config{To: []string{"a@x.com"}, DryRun: true}).Validate(); err != nil {
		t.Errorf("dry-run with recipients should validate: %v", err)
	}
}

// TestSendDryRunProducesValidMIME verifies the composed message parses as a
// proper multipart email with the HTML body and the attachment intact.
func TestSendDryRunProducesValidMIME(t *testing.T) {
	out := filepath.Join(t.TempDir(), "msg.eml")
	cfg := email.Config{
		From:       "observer@example.com",
		To:         []string{"dev@example.com"},
		DryRun:     true,
		DryRunPath: out,
	}
	msg := testMessage()
	if err := email.Send(cfg, msg); err != nil {
		t.Fatalf("send (dry-run) failed: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading composed message: %v", err)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parsing message: %v", err)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if !strings.Contains(subj, "Observer report") {
		t.Errorf("decoded subject = %q", subj)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("content-type = %q (err %v)", mediaType, err)
	}

	mr := multipart.NewReader(parsed.Body, params["boundary"])
	var foundBody, foundAttachment bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading part: %v", err)
		}
		data, _ := io.ReadAll(part)
		// base64 transfer-encoding is decoded automatically? No — decode if needed.
		if part.Header.Get("Content-Transfer-Encoding") == "base64" {
			// multipart does not auto-decode; the body is base64 text.
			decoded := decodeBase64(t, string(data))
			data = decoded
		}
		if strings.Contains(part.Header.Get("Content-Type"), "text/html") &&
			part.Header.Get("Content-Disposition") == "" {
			if strings.Contains(string(data), "3 issues found") {
				foundBody = true
			}
		}
		if strings.Contains(part.Header.Get("Content-Disposition"), "attachment") {
			if strings.Contains(string(data), "full report") {
				foundAttachment = true
			}
		}
	}
	if !foundBody {
		t.Error("HTML body part not found / not decoded correctly")
	}
	if !foundAttachment {
		t.Error("attachment part not found / not decoded correctly")
	}
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return dec
}
