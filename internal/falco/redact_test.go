package falco

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestRedactTextScanCap(t *testing.T) {
	r := newTestRedactor(t)

	t.Run("secret inside the cap is still redacted", func(t *testing.T) {
		input := strings.Repeat("a", maxScanBytes-len(testSecret)-10) + " " + testSecret
		got := r.RedactText(input)
		if strings.Contains(got, testSecret) {
			t.Errorf("secret within cap was not redacted")
		}
	})

	t.Run("oversized string is truncated so the tail cannot leak", func(t *testing.T) {
		input := strings.Repeat("a", maxScanBytes) + " " + testSecret
		got := r.RedactText(input)
		if strings.Contains(got, testSecret) {
			t.Errorf("secret beyond the cap leaked")
		}
		if !strings.HasSuffix(got, truncationMarker) {
			t.Errorf("expected truncation marker, got suffix %q", got[len(got)-20:])
		}
		if len(got) != maxScanBytes+len(truncationMarker) {
			t.Errorf("len = %d, want %d", len(got), maxScanBytes+len(truncationMarker))
		}
	})

	t.Run("a secret straddling the cap leaves no fragment behind", func(t *testing.T) {
		for _, offset := range []int{1, 5, 12, len(testSecret) - 1} {
			input := strings.Repeat("a ", maxScanBytes)[:maxScanBytes-offset] + testSecret + " tail"
			got := r.RedactText(input)
			if strings.Contains(got, "xoxb-") || strings.Contains(got, "1234567890123") {
				t.Errorf("offset %d: token fragment survived truncation: %q", offset, got[len(got)-60:])
			}
			if len(got) > maxScanBytes+len(truncationMarker) {
				t.Errorf("offset %d: result longer than cap: %d", offset, len(got))
			}
		}
	})

	t.Run("a multi-line secret cut mid-body leaves no fragment behind", func(t *testing.T) {
		// Newlines (and any other delimiter) inside a secret must not be treated as
		// a safe place to cut: the whole key is detected before the string is cut.
		rng := rand.New(rand.NewSource(1))
		var lines []string
		for i := 0; i < 26; i++ {
			buf := make([]byte, 48)
			rng.Read(buf)
			lines = append(lines, base64.StdEncoding.EncodeToString(buf))
		}
		key := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(lines, "\n") + "\n-----END RSA PRIVATE KEY-----"
		for _, cutInLine := range []int{3, 10, 20} {
			// Position the cut inside the chosen body line.
			before := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(lines[:cutInLine], "\n") + "\n" + lines[cutInLine][:10]
			input := strings.Repeat("a ", maxScanBytes)[:maxScanBytes-len(before)] + key + " tail"
			got := r.RedactText(input)
			for i, line := range lines {
				if strings.Contains(got, line[:20]) {
					t.Errorf("cut in line %d: key body line %d survived", cutInLine, i)
				}
			}
			if strings.Contains(got, "PRIVATE KEY") {
				t.Errorf("cut in line %d: key header survived: %q", cutInLine, got[len(got)-80:])
			}
		}
	})

	t.Run("string at exactly the cap is untouched", func(t *testing.T) {
		input := strings.Repeat("a", maxScanBytes)
		if got := r.RedactText(input); got != input {
			t.Errorf("string at the cap was modified")
		}
	})

	t.Run("truncation does not split a multi-byte rune", func(t *testing.T) {
		// "é" is 2 bytes; an odd offset would cut one in half.
		input := "a" + strings.Repeat("é", maxScanBytes)
		got := r.RedactText(input)
		if !utf8.ValidString(got) {
			t.Errorf("truncated output is not valid UTF-8")
		}
	})
}

func TestRedactEvent(t *testing.T) {
	r := newTestRedactor(t)

	t.Run("redacts output string", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output":"suspicious exec token=`+testSecret+`"}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		assertStringRedacted(t, raw["output"])
	})

	t.Run("redacts allowlisted output_fields", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output_fields":{"proc.cmdline":"login --token `+testSecret+`","proc.name":"login"}}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
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
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		fields := mustParseFields(t, raw)
		cwd, _ := fields["proc.cwd"].(string)
		if strings.Contains(cwd, testSecret) {
			t.Errorf("secret not redacted in proc.cwd: %q", cwd)
		}
	})

	t.Run("redacts strings nested in arrays and objects", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output_fields":{"evt.args":["res=0 data=`+testSecret+`",{"nested":["`+testSecret+`"]}],"proc.pid":42,"ok":true,"none":null}}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		got := string(raw["output_fields"])
		if strings.Contains(got, testSecret) {
			t.Errorf("secret left in nested value: %s", got)
		}
		for _, want := range []string{`"proc.pid":42`, `"ok":true`, `"none":null`, "redacted-"} {
			if !strings.Contains(got, want) {
				t.Errorf("expected %q in %s", want, got)
			}
		}
	})

	t.Run("redacts output_fields that is not an object", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output_fields":["`+testSecret+`"]}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		if strings.Contains(string(raw["output_fields"]), testSecret) {
			t.Errorf("secret left in array-valued output_fields: %s", raw["output_fields"])
		}
	})

	t.Run("redacts output that is not a string", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output":{"msg":"`+testSecret+`"}}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		if strings.Contains(string(raw["output"]), testSecret) {
			t.Errorf("secret left in object-valued output: %s", raw["output"])
		}
	})

	t.Run("replaces structures nested beyond the depth limit", func(t *testing.T) {
		deep := `"` + testSecret + `"`
		for i := 0; i < maxRedactDepth+4; i++ {
			deep = `{"a":` + deep + `}`
		}
		raw := mustParseRaw(t, `{"output_fields":`+deep+`}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		if strings.Contains(string(raw["output_fields"]), testSecret) {
			t.Errorf("secret survived beyond the depth limit")
		}
	})

	t.Run("nil redactor fails closed", func(t *testing.T) {
		raw := mustParseRaw(t, `{"output":"x"}`)
		if err := (*Redactor)(nil).RedactEvent(context.Background(), raw); err == nil {
			t.Errorf("expected error for nil redactor")
		}
	})

	t.Run("payload without output or output_fields is a no-op", func(t *testing.T) {
		raw := mustParseRaw(t, `{"rule":"some rule","tags":["network"]}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
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

func TestRedactEventWaitsForSlotAndHonorsContext(t *testing.T) {
	r := newTestRedactor(t)
	fillSlots(r)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	raw := mustParseRaw(t, `{"output":"`+testSecret+`"}`)
	err := r.RedactEvent(ctx, raw)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RedactEvent() error = %v, want context.Canceled", err)
	}
	if !strings.Contains(string(raw["output"]), testSecret) {
		t.Errorf("event must be left untouched when no scan ran")
	}

	// Once a slot frees up, the same call succeeds and releases it again.
	<-r.slots
	if err := r.RedactEvent(context.Background(), raw); err != nil {
		t.Fatalf("RedactEvent() error = %v", err)
	}
	if strings.Contains(string(raw["output"]), testSecret) {
		t.Errorf("secret not redacted")
	}
}
