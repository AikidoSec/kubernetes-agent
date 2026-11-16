package falco

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
)

// maxScanBytes is the longest string that is scanned. Real Falco values are far
// smaller (the longest observed were ~5 KiB: a Falco-captured command line is
// limited to about 4 KiB, and the formatted output adds a little more), so
// legitimate events are never affected. A longer string is not scanned at all but
// replaced by truncationMarker: scanning only a prefix could leave part of a
// secret that straddles the cut undetected.
const maxScanBytes = 8 * 1024

// truncationMarker replaces a string longer than maxScanBytes, and any structure
// nested deeper than maxRedactDepth.
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
	detector.IgnoreGitleaksAllow = true
	return &Redactor{detector: detector, slots: make(chan struct{}, max(1, runtime.NumCPU()/2))}, nil
}

// RedactText replaces every detected secret with its hash. Hashing is
// deterministic so the same secret always maps to the same token, which keeps
// downstream aggregate grouping stable. A string longer than maxScanBytes is
// replaced by truncationMarker without being scanned.
func (r *Redactor) RedactText(input string) string {
	if len(input) > maxScanBytes {
		return truncationMarker
	}
	redacted := input
	for _, finding := range r.detector.DetectString(input) {
		for _, secret := range findingSecrets(finding) {
			redacted = strings.ReplaceAll(redacted, secret, hashValue(secret))
		}
	}
	return redacted
}

func findingSecrets(f report.Finding) []string {
	var secrets []string
	if f.Secret != "" {
		secrets = append(secrets, f.Secret)
	}
	for _, set := range f.RequiredSets {
		for _, component := range set.Components {
			if component != nil && component.Secret != "" {
				secrets = append(secrets, component.Secret)
			}
		}
	}
	return secrets
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
	decoder := json.NewDecoder(bytes.NewReader(v))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
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
			return truncationMarker, true
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
			return truncationMarker, true
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
