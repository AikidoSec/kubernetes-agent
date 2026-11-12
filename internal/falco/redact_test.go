package falco

import (
	"encoding/json"
	"strings"
	"testing"
)

// testSecret is a Slack bot token shape the betterleaks default config reliably
// detects, used to exercise the redaction path.
const testSecret = "xoxb-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX"

func newTestRedactor(t *testing.T) *Redactor {
	t.Helper()
	r, err := NewRedactor()
	if err != nil {
		t.Fatalf("NewRedactor() error = %v", err)
	}
	return r
}

func TestRedactText(t *testing.T) {
	r := newTestRedactor(t)

	t.Run("replaces detected secret with deterministic hash", func(t *testing.T) {
		input := "curl -H 'Authorization: Bearer " + testSecret + "'"
		got := r.RedactText(input)
		if strings.Contains(got, testSecret) {
			t.Errorf("secret not redacted: %q", got)
		}
		if !strings.Contains(got, "redacted-") {
			t.Errorf("expected redacted token in output: %q", got)
		}
		if got != r.RedactText(input) {
			t.Errorf("redaction not deterministic")
		}
	})

	t.Run("leaves text without secrets unchanged", func(t *testing.T) {
		input := "cat /etc/passwd"
		if got := r.RedactText(input); got != input {
			t.Errorf("RedactText(%q) = %q, want unchanged", input, got)
		}
	})
}

func TestRedactSecrets(t *testing.T) {
	r := newTestRedactor(t)

	t.Run("redacts output string", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output":"suspicious exec token=`+testSecret+`"}`)
		if err := redactSecrets(raw, r); err != nil {
			t.Fatalf("redactSecrets() error = %v", err)
		}
		assertStringRedacted(t, raw["output"])
	})

	t.Run("redacts allowlisted output_fields", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output_fields":{"proc.cmdline":"login --token `+testSecret+`","proc.name":"login"}}`)
		if err := redactSecrets(raw, r); err != nil {
			t.Fatalf("redactSecrets() error = %v", err)
		}
		fields := mustParseFields(t, raw)
		cmdline, _ := fields["proc.cmdline"].(string)
		if strings.Contains(cmdline, testSecret) {
			t.Errorf("secret not redacted in proc.cmdline: %q", cmdline)
		}
		if !strings.Contains(cmdline, "redacted-") {
			t.Errorf("expected redacted token in proc.cmdline: %q", cmdline)
		}
	})

	t.Run("redacts non-command-line output_fields", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output_fields":{"proc.pcmdline":"sh -c","proc.cwd":"/tmp/`+testSecret+`"}}`)
		if err := redactSecrets(raw, r); err != nil {
			t.Fatalf("redactSecrets() error = %v", err)
		}
		fields := mustParseFields(t, raw)
		cwd, _ := fields["proc.cwd"].(string)
		if strings.Contains(cwd, testSecret) {
			t.Errorf("secret not redacted in proc.cwd: %q", cwd)
		}
	})

	t.Run("payload without output or output_fields is a no-op", func(t *testing.T) {
		raw := mustParseRaw(t, `{"rule":"some rule","tags":["network"]}`)
		if err := redactSecrets(raw, r); err != nil {
			t.Fatalf("redactSecrets() error = %v", err)
		}
	})
}

func mustParseRaw(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	return raw
}

func mustParseFields(t *testing.T, raw map[string]json.RawMessage) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw["output_fields"], &fields); err != nil {
		t.Fatalf("unmarshal output_fields: %v", err)
	}
	return fields
}

func assertStringRedacted(t *testing.T, rawValue json.RawMessage) {
	t.Helper()
	var s string
	if err := json.Unmarshal(rawValue, &s); err != nil {
		t.Fatalf("unmarshal string field: %v", err)
	}
	if strings.Contains(s, testSecret) {
		t.Errorf("secret not redacted: %q", s)
	}
	if !strings.Contains(s, "redacted-") {
		t.Errorf("expected redacted token: %q", s)
	}
}
