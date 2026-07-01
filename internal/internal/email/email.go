// Package email sends the generated report by email (Phase 8).
//
// SMTP settings come from environment variables; the report HTML is attached
// and a concise summary forms the body. A dry-run mode writes the composed
// message to disk instead of sending, so the feature is testable offline and
// configuration can be verified without a live mail server.
package email

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Attachment is a file attached to the message.
type Attachment struct {
	Filename string
	Data     []byte
	MIME     string // e.g. "text/html"
}

// Message is the email payload.
type Message struct {
	Subject    string
	HTMLBody   string
	Attachment *Attachment
}

// Config holds SMTP settings and recipients.
type Config struct {
	Host       string
	Port       string
	User       string
	Pass       string
	From       string
	To         []string
	DryRun     bool   // write the .eml instead of sending
	DryRunPath string // where to write it (dry-run)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ConfigFromEnv reads SMTP settings from the environment:
//
//	SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS, SMTP_FROM
//	OBSERVER_SMTP_DRYRUN=1 to compose without sending.
func ConfigFromEnv() Config {
	return Config{
		Host:   os.Getenv("SMTP_HOST"),
		Port:   envOr("SMTP_PORT", "587"),
		User:   os.Getenv("SMTP_USER"),
		Pass:   os.Getenv("SMTP_PASS"),
		From:   envOr("SMTP_FROM", os.Getenv("SMTP_USER")),
		DryRun: os.Getenv("OBSERVER_SMTP_DRYRUN") != "",
	}
}

// Validate checks the config is sufficient to compose and (unless dry-run) send.
func (c Config) Validate() error {
	if len(c.To) == 0 {
		return fmt.Errorf("no recipients (set --email)")
	}
	if !c.DryRun {
		if c.Host == "" {
			return fmt.Errorf("SMTP_HOST not set")
		}
		if c.From == "" {
			return fmt.Errorf("SMTP_FROM (or SMTP_USER) not set")
		}
	}
	return nil
}

// Send composes the message and either writes it (dry-run) or sends it via SMTP.
func Send(c Config, m Message) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw := build(c, m)

	if c.DryRun {
		path := c.DryRunPath
		if path == "" {
			path = "observer-email.eml"
		}
		return os.WriteFile(path, raw, 0o644)
	}

	addr := net.JoinHostPort(c.Host, c.Port)
	var auth smtp.Auth
	if c.User != "" {
		auth = smtp.PlainAuth("", c.User, c.Pass, c.Host)
	}
	if c.Port == "465" {
		return sendImplicitTLS(addr, c.Host, auth, c.From, c.To, raw)
	}
	// Port 587/25: smtp.SendMail upgrades to STARTTLS when the server offers it.
	return smtp.SendMail(addr, auth, c.From, c.To, raw)
}

// build composes the RFC 5322 / MIME multipart message bytes.
func build(c Config, m Message) []byte {
	from := c.From
	if from == "" {
		from = "observer@localhost"
	}
	boundary := fmt.Sprintf("observer_%d", time.Now().UnixNano())

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(c.To, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", m.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")

	// HTML body part.
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(wrap76(base64.StdEncoding.EncodeToString([]byte(m.HTMLBody))))
	b.WriteString("\r\n")

	// Attachment part.
	if m.Attachment != nil {
		mt := m.Attachment.MIME
		if mt == "" {
			mt = "application/octet-stream"
		}
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + mt + "; name=\"" + m.Attachment.Filename + "\"\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-Disposition: attachment; filename=\"" + m.Attachment.Filename + "\"\r\n\r\n")
		b.WriteString(wrap76(base64.StdEncoding.EncodeToString(m.Attachment.Data)))
		b.WriteString("\r\n")
	}

	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

// sendImplicitTLS sends over an implicit-TLS connection (typically port 465).
func sendImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// wrap76 wraps a string at 76 characters per line (RFC 2045 base64).
func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteString("\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

// ParseRecipients splits a comma/space separated recipient list.
func ParseRecipients(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	var out []string
	for _, f := range fields {
		if t := strings.TrimSpace(f); t != "" {
			out = append(out, t)
		}
	}
	return out
}
