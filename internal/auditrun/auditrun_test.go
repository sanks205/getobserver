package auditrun

import "testing"

func TestRequiredEngineMustComplete(t *testing.T) {
	required, err := ParseRequired("phpstan, semgrep")
	if err != nil {
		t.Fatal(err)
	}
	tracker := New(required)
	tracker.Record("phpstan", "completed", "0 findings")
	tracker.Record("semgrep", "skipped", "not installed")
	if !tracker.Incomplete() {
		t.Fatal("skipped required engine must make the audit incomplete")
	}
}

func TestOptionalEngineFailureDoesNotMakePolicyIncomplete(t *testing.T) {
	tracker := New(Required{})
	tracker.Record("eslint", "error", "configuration error")
	if tracker.Incomplete() {
		t.Fatal("an optional engine failure must be recorded without violating a required-engine policy")
	}
}

func TestMandatoryPhaseFailureIsIncomplete(t *testing.T) {
	tracker := New(Required{})
	tracker.RecordRequired("history", "error", "git failure")
	if !tracker.Incomplete() {
		t.Fatal("failed mandatory phase must make the audit incomplete")
	}
}
