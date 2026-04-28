package models

import (
	"strings"
	"testing"
)

func TestHeartbeatResponseThreatDetectionExceptionsUnmarshal(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		expectNil   bool
		expectLen   int
	}{
		{
			name:      "null field unmarshals to nil — agent should keep current exceptions",
			json:      `{"threat_detection_exceptions": null}`,
			expectNil: true,
		},
		{
			name:      "empty array unmarshals to non-nil empty slice — agent should clear exceptions",
			json:      `{"threat_detection_exceptions": []}`,
			expectNil: false,
			expectLen: 0,
		},
		{
			name:      "omitted field unmarshals to nil — agent should keep current exceptions",
			json:      `{}`,
			expectNil: true,
		},
		{
			name:      "populated array unmarshals to non-nil slice",
			json:      `{"threat_detection_exceptions": [{"id": 1, "name": "test", "rule_names": ["Read sensitive file untrusted"], "conditions": [], "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"}]}`,
			expectNil: false,
			expectLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp HeartbeatResponse
			if err := resp.FromJSON(strings.NewReader(tt.json)); err != nil {
				t.Fatalf("FromJSON() error = %v", err)
			}
			if tt.expectNil && resp.ThreatDetectionExceptions != nil {
				t.Errorf("expected nil, got non-nil")
			}
			if !tt.expectNil {
				if resp.ThreatDetectionExceptions == nil {
					t.Errorf("expected non-nil, got nil")
				} else if len(*resp.ThreatDetectionExceptions) != tt.expectLen {
					t.Errorf("expected len %d, got %d", tt.expectLen, len(*resp.ThreatDetectionExceptions))
				}
			}
		})
	}
}
