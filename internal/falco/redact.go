package falco

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/detect"
)

// maxScanBytes caps how much of a single string is scanned. Real Falco values
// are far smaller (the longest observed was ~4 KiB, a Falco-captured command
// line), so legitimate events are never affected, while detection cost stays
// bounded for oversized input.
const maxScanBytes = 64 * 1024

// truncationMarker replaces the tail of a string longer than maxScanBytes. The
// tail is dropped rather than skipped, so an oversized value can never carry an
// unscanned secret out of the cluster.
const truncationMarker = "[TRUNCATED]"

// Redactor replaces secrets found in Falco event fields with a stable hash so
// plaintext never leaves the cluster.
type Redactor struct {
	detector *detect.Detector
	// slots bounds concurrent scans so a burst of requests (the listener is
	// unauthenticated) cannot starve the rest of the agent of CPU.
	slots chan struct{}
}

func NewRedactor() (*Redactor, error) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to create secrets detector: %w", err)
	}
	return &Redactor{detector: detector, slots: make(chan struct{}, max(1, runtime.NumCPU()/2))}, nil
}

// scanOverlapBytes is how far past maxScanBytes a string is still scanned. A
// secret that starts before the cap is therefore detected whole, and replaced,
// before the string is cut, as long as it is shorter than this (the largest
// common secrets, such as RSA private keys, are well under 8 KiB).
const scanOverlapBytes = 16 * 1024

// RedactText replaces every detected secret with its hash. Hashing is
// deterministic so the same secret always maps to the same token, which keeps
// downstream aggregate grouping stable.
//
// A string longer than maxScanBytes is scanned up to maxScanBytes+scanOverlapBytes,
// redacted, and only then cut back to maxScanBytes. Cutting after redaction means
// no guess is needed about where a secret ends (a secret can contain any
// delimiter), and the rest of the string is dropped, so an oversized value cannot
// carry an unscanned secret out of the cluster.
func (r *Redactor) RedactText(input string) string {
	truncated := len(input) > maxScanBytes
	if truncated {
		input = cutUTF8(input, maxScanBytes+scanOverlapBytes)
	}
	redacted := input
	for _, finding := range r.detector.DetectString(input) {
		if finding.Secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, finding.Secret, hashValue(finding.Secret))
	}
	if truncated {
		redacted = cutUTF8(redacted, maxScanBytes) + truncationMarker
	}
	return redacted
}

// cutUTF8 cuts s to at most n bytes without splitting a multi-byte rune.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// RedactEvent redacts the secrets in the "output" and "output_fields" of a
// Falco event in place. It waits for a free scan slot first and returns the
// context's error if ctx ends while waiting. Any other error means the event
// must not be forwarded.
func (r *Redactor) RedactEvent(ctx context.Context, raw map[string]json.RawMessage) error {
	if r == nil {
		return errors.New("no redactor configured")
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	for _, key := range []string{"output", "output_fields"} {
		if err := r.redactRawField(raw, key); err != nil {
			return err
		}
	}
	return nil
}

// maxRedactDepth bounds recursion into nested JSON. Anything deeper is replaced
// outright (fail closed) rather than walked, so a crafted payload can neither
// exhaust the stack nor carry a secret out unscanned.
// Real Falco events are flat (output_fields strings sit at depth 1), so 4 leaves
// ample headroom.
const maxRedactDepth = 4

// redactRawField redacts every string found anywhere inside raw[key] (strings,
// object values and array elements, at any depth). Secrets can appear in any
// field (proc.pcmdline, proc.exepath, fd.name, ...), not just command lines.
func (r *Redactor) redactRawField(raw map[string]json.RawMessage, key string) error {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	var value any
	if err := json.Unmarshal(v, &value); err != nil {
		return fmt.Errorf("unmarshal %s: %w", key, err)
	}
	redacted, changed := r.redactJSONValue(value, 0)
	if !changed {
		return nil
	}
	marshaled, err := json.Marshal(redacted)
	if err != nil {
		return fmt.Errorf("marshal redacted %s: %w", key, err)
	}
	raw[key] = marshaled
	return nil
}

func (r *Redactor) redactJSONValue(value any, depth int) (any, bool) {
	switch v := value.(type) {
	case string:
		if redacted := r.RedactText(v); redacted != v {
			return redacted, true
		}
		return v, false
	case map[string]any:
		if depth >= maxRedactDepth {
			return "[TRUNCATED]", true
		}
		changed := false
		for k, item := range v {
			if redacted, c := r.redactJSONValue(item, depth+1); c {
				v[k] = redacted
				changed = true
			}
		}
		return v, changed
	case []any:
		if depth >= maxRedactDepth {
			return "[TRUNCATED]", true
		}
		changed := false
		for i, item := range v {
			if redacted, c := r.redactJSONValue(item, depth+1); c {
				v[i] = redacted
				changed = true
			}
		}
		return v, changed
	default:
		return value, false
	}
}

func hashValue(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "redacted-" + hex.EncodeToString(hash[:])
}
