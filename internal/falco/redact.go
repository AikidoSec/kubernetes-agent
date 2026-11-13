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

func hashValue(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "redacted-" + hex.EncodeToString(hash[:])
}
