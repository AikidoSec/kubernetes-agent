package falco

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"
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

func TestRedactTextMultipartSecrets(t *testing.T) {
	r := newTestRedactor(t)

	accessKeyID := "AKIAQYLPMN5HHHFPZAM2"
	secretKey := "jBq4xT9zLw2PvN7mRk1YcD8sGh3FuAe6Wo5Ij0Zt"

	for name, input := range map[string]string{
		"env vars": "AWS_ACCESS_KEY_ID=" + accessKeyID + " AWS_SECRET_ACCESS_KEY=" + secretKey + " aws s3 ls",
		"config":   "aws_access_key_id=" + accessKeyID + "\naws_secret_access_key=" + secretKey,
	} {
		t.Run(name, func(t *testing.T) {
			got := r.RedactText(input)
			if strings.Contains(got, accessKeyID) {
				t.Errorf("access key ID not redacted: %q", got)
			}
			if strings.Contains(got, secretKey) {
				t.Errorf("secret access key not redacted: %q", got)
			}
		})
	}
}

func TestRedactTextWorstCaseCandidateIsBounded(t *testing.T) {
	r := newTestRedactor(t)

	// One pseudo-random lowercase base36 candidate as long as the cap allows: the
	// shape that sends betterleaks' generic-key rule into its expensive dictionary
	// filter. Without the cap this would run for minutes.
	rng := rand.New(rand.NewSource(7))
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	const prefix = "api_key="
	candidate := make([]byte, maxScanBytes-len(prefix))
	for i := range candidate {
		candidate[i] = alphabet[rng.Intn(len(alphabet))]
	}

	start := time.Now()
	r.RedactText(prefix + string(candidate))
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("worst-case candidate took %v; the cap is too large for the dictionary filter", elapsed)
	}
}

func TestRedactTextIgnoresAllowComments(t *testing.T) {
	r := newTestRedactor(t)

	for _, directive := range []string{"betterleaks:allow", "gitleaks:allow"} {
		t.Run(directive, func(t *testing.T) {
			input := "curl -H 'Authorization: Bearer " + testSecret + "' # " + directive
			got := r.RedactText(input)
			if strings.Contains(got, testSecret) {
				t.Errorf("secret not redacted when %q is present: %q", directive, got)
			}
		})
	}
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

	t.Run("string at exactly the cap is untouched", func(t *testing.T) {
		input := strings.Repeat("a", maxScanBytes)
		if got := r.RedactText(input); got != input {
			t.Errorf("string at the cap was modified")
		}
	})

	// Scanning only a prefix could leave part of a secret that straddles the cut
	// undetected, so nothing of an oversized string may be forwarded.
	for name, input := range map[string]string{
		"secret in the tail":        strings.Repeat("a ", maxScanBytes/2) + testSecret,
		"secret at the start":       testSecret + strings.Repeat(" a", maxScanBytes),
		"secret straddling the cap": strings.Repeat("a ", maxScanBytes)[:maxScanBytes-12] + testSecret + " tail",
		"multi-byte text":           "a" + strings.Repeat("é", maxScanBytes),
	} {
		t.Run("oversized string is replaced by the marker: "+name, func(t *testing.T) {
			if got := r.RedactText(input); got != truncationMarker {
				t.Errorf("got %.60q (len %d), want only %q", got, len(got), truncationMarker)
			}
		})
	}
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

	t.Run("redacts the message property", func(t *testing.T) {
		// Falco adds "message" (the output text without timestamp and priority)
		// when json_include_message_property is enabled.
		raw := mustParseRaw(t, `{"output":"10:00:05 Warning exec token=`+testSecret+`","message":"Warning exec token=`+testSecret+`"}`)
		if err := r.RedactEvent(context.Background(), raw); err != nil {
			t.Fatalf("RedactEvent() error = %v", err)
		}
		assertStringRedacted(t, raw["message"])
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

func TestRedactEventKeepsNumbers(t *testing.T) {
	r := newTestRedactor(t)
	raw := mustParseRaw(t, `{"output_fields":{"proc.exe_ino.ctime":1700000000123456789,"proc.exe_ino.mtime":1700000000123456791,`+
		`"ratio":1.50,"big":12345678901234567890,"proc.cmdline":"login --token `+testSecret+`"}}`)
	if err := r.RedactEvent(context.Background(), raw); err != nil {
		t.Fatalf("RedactEvent() error = %v", err)
	}
	got := string(raw["output_fields"])
	if strings.Contains(got, testSecret) {
		t.Fatalf("secret not redacted: %s", got)
	}
	// Numbers must come back byte-for-byte, not rounded through float64.
	for _, want := range []string{`"proc.exe_ino.ctime":1700000000123456789`, `"proc.exe_ino.mtime":1700000000123456791`, `"ratio":1.50`, `"big":12345678901234567890`} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %s in %s", want, got)
		}
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
