package falco

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/detect"
)

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
	redacted := input
	for _, finding := range r.detector.DetectString(input) {
		if finding.Secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, finding.Secret, hashValue(finding.Secret))
	}
	return redacted
}

func hashValue(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "redacted-" + hex.EncodeToString(hash[:])
}
