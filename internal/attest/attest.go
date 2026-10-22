// Package attest writes a machine-readable local scan record: what was scanned,
// what was found, and whether the quality gate passed. It can support a review
// trail, but it is not third-party certification. Pro may add a local HMAC
// companion file for workflow integrity checks.
package attest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

// EngineOutcome records the result of an enabled scan engine or scan phase.
type EngineOutcome struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // completed | skipped | error
	Required bool   `json:"required,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Attestation is the record written by --attest.
type Attestation struct {
	Tool            string          `json:"tool"`
	Version         string          `json:"version"`
	GeneratedAt     string          `json:"generated_at"`
	Status          string          `json:"status"` // pass | fail | incomplete
	Scope           string          `json:"scope"`
	Target          string          `json:"target"`
	CommitSHA       string          `json:"commit_sha,omitempty"`
	Branch          string          `json:"branch,omitempty"`
	RepositoryDirty bool            `json:"repository_dirty"`
	OfflineAsserted bool            `json:"offline_asserted"`
	FilesChanged    int             `json:"files_changed,omitempty"`
	Engines         []EngineOutcome `json:"engines"`
	Findings        map[string]int  `json:"findings"`
	Total           int             `json:"total_findings"`
	Gate            *Gate           `json:"gate,omitempty"`
}

// Gate captures the final quality-gate outcome when --fail-on was used.
type Gate struct {
	Threshold string `json:"threshold"`
	FailCount int    `json:"fail_count"`
	Status    string `json:"status"` // pass | fail | incomplete
	Passed    bool   `json:"passed"`
	Complete  bool   `json:"complete"`
}

// Write marshals the attestation as indented JSON to path.
func Write(path string, a Attestation) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Sign returns HMAC-SHA256 hex of data using secret (integritySecret style).
func Sign(data []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// WriteSigned writes attestation JSON plus .sig HMAC file if secret != "".
func WriteSigned(path string, a Attestation, secret string) (string, string, error) {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return "", "", err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", "", err
	}
	if secret == "" {
		return path, "", nil
	}
	sig := Sign(b, secret)
	sigPath := path + ".sig"
	if err := os.WriteFile(sigPath, []byte(sig+"\n"), 0o644); err != nil {
		return path, "", err
	}
	return path, sigPath, nil
}

// VerifySig checks that sigHex equals HMAC of data with secret.
func VerifySig(data []byte, sigHex, secret string) bool {
	exp := Sign(data, secret)
	return hmac.Equal([]byte(exp), []byte(sigHex))
}
