package main

import "testing"

func TestValidateSeverityFlag(t *testing.T) {
	for _, value := range []string{"", "Low", "medium", "HIGH", " critical "} {
		if err := validateSeverityFlag("--fail-on", value); err != nil {
			t.Fatalf("expected %q to be valid: %v", value, err)
		}
	}
	if err := validateSeverityFlag("--fail-on", "urgent"); err == nil {
		t.Fatal("expected invalid severity to return an error")
	}
}

func TestRunAnalyzeRejectsInvalidSeverity(t *testing.T) {
	if code := runAnalyze([]string{t.TempDir(), "--fail-on", "urgent", "--out", ""}); code != exitError {
		t.Fatalf("invalid severity exit code = %d, want %d", code, exitError)
	}
}

func TestRunAnalyzeRejectsNetworkFlagsInOfflineMode(t *testing.T) {
	if code := runAnalyze([]string{t.TempDir(), "--assert-offline", "--cve", "--out", ""}); code != exitError {
		t.Fatalf("offline conflict exit code = %d, want %d", code, exitError)
	}
}

func TestExitCodesRemainStable(t *testing.T) {
	if exitOK != 0 || exitError != 1 || exitGate != 2 || exitIncomplete != 3 {
		t.Fatalf("unexpected exit codes: success=%d error=%d gate=%d incomplete=%d", exitOK, exitError, exitGate, exitIncomplete)
	}
}

func TestOfflineModeRequiresLocalSemgrepConfig(t *testing.T) {
	t.Setenv("SEMGREP_CONFIG", "")
	if code := runAnalyze([]string{t.TempDir(), "--assert-offline", "--semgrep", "--out", ""}); code != exitError {
		t.Fatalf("offline Semgrep without local config exit code = %d, want %d", code, exitError)
	}
	localRules := t.TempDir()
	t.Setenv("SEMGREP_CONFIG", localRules)
	if semgrepConfigNeedsNetwork(localRules) {
		t.Fatal("existing local Semgrep config must be accepted in offline mode")
	}
}

func TestSemgrepConfigNetworkClassification(t *testing.T) {
	for _, config := range []string{"", "auto", "p/security-audit", "r/custom", "https://example.invalid/rules.yml"} {
		if !semgrepConfigNeedsNetwork(config) {
			t.Errorf("expected %q to require network", config)
		}
	}
}

func TestOfflineModeRejectsNotificationEnvironment(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK", "https://example.invalid/slack")
	if code := runAnalyze([]string{t.TempDir(), "--assert-offline", "--out", ""}); code != exitError {
		t.Fatalf("offline environment conflict exit code = %d, want %d", code, exitError)
	}
	t.Setenv("SLACK_WEBHOOK", "")
	t.Setenv("TEAMS_WEBHOOK", "https://example.invalid/teams")
	if code := runAnalyze([]string{t.TempDir(), "--assert-offline", "--out", ""}); code != exitError {
		t.Fatalf("offline Teams environment conflict exit code = %d, want %d", code, exitError)
	}
}

func TestRequiredEngineUnavailableIsIncomplete(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if code := runAnalyze([]string{t.TempDir(), "--require-engine", "semgrep", "--out", ""}); code != exitIncomplete {
		t.Fatalf("required engine exit code = %d, want %d", code, exitIncomplete)
	}
}

func TestRejectsUnknownRequiredEngine(t *testing.T) {
	if code := runAnalyze([]string{t.TempDir(), "--require-engine", "unknown", "--out", ""}); code != exitError {
		t.Fatalf("unknown required engine exit code = %d, want %d", code, exitError)
	}
}
