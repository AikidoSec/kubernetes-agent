package falco

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
}

func NewRedactor() (*Redactor, error) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to create secrets detector: %w", err)
	}
	return &Redactor{detector: detector}, nil
}

// RedactText replaces every detected secret with its hash. Hashing is
// deterministic so the same secret always maps to the same token, which keeps
// downstream aggregate grouping stable.
func (r *Redactor) RedactText(input string) string {
	if len(input) > maxScanBytes {
		input = truncateUTF8(input, maxScanBytes) + truncationMarker
	}
	redacted := input
	for _, finding := range r.detector.DetectString(input) {
		if finding.Secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, finding.Secret, hashValue(finding.Secret))
	}
	return redacted
}

// truncateUTF8 cuts s to at most n bytes without splitting a multi-byte rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func hashValue(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "redacted-" + hex.EncodeToString(hash[:])
}
