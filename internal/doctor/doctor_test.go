package doctor

import (
	"bytes"
	"strings"
	"testing"
)

func TestInspectAndWriteText(t *testing.T) {
	report := Inspect("test-version", "Test")
	if !report.OfflineDefault {
		t.Fatal("Observer must report offline-by-default behavior")
	}
	var out bytes.Buffer
	WriteText(&out, report)
	text := out.String()
	for _, want := range []string{"test-version", "Test", "offline", "--assert-offline", "--cve", "Built-in analyzer"} {
		if !strings.Contains(text, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "OPENAI_API_KEY=") {
		t.Fatal("doctor output must not print environment secret values")
	}
}
