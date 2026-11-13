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
		input = truncateForScan(input, maxScanBytes) + truncationMarker
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

// truncateLookback is how far truncateForScan backs up to find a delimiter.
const truncateLookback = 1024

// truncateDelimiters separate tokens, so cutting right after one cannot split
// a secret in half.
const truncateDelimiters = " \t\r\n\"'`=:,;|&()[]{}<>"

// truncateForScan cuts s to at most n bytes without splitting a multi-byte rune
// or a token. A secret straddling the cut would otherwise survive as an
// undetectable prefix, so the cut backs up to the last delimiter within
// truncateLookback bytes (or drops the whole window if there is none).
func truncateForScan(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// The cut already falls on a delimiter: no token is split.
	if strings.IndexByte(truncateDelimiters, s[n]) >= 0 {
		return s[:n]
	}
	end := n
	if i := strings.LastIndexAny(s[max(0, n-truncateLookback):n], truncateDelimiters); i >= 0 {
		end = max(0, n-truncateLookback) + i + 1
	} else {
		end = max(0, n-truncateLookback)
	}
	for end > 0 && end < len(s) && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

func hashValue(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "redacted-" + hex.EncodeToString(hash[:])
}
