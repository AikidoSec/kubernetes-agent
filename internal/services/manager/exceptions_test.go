package manager

import (
	"testing"

	"aikidoSec.kubernetesAgent/pkg/models"
)

func TestBuildExceptionsYAML(t *testing.T) {
	tests := []struct {
		name       string
		exceptions []models.ThreatDetectionException
		want       string
	}{
		{
			name:       "empty exceptions returns empty string",
			exceptions: []models.ThreatDetectionException{},
			want:       "",
		},
		{
			name: "single exception, single condition",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress myapp",
					RuleNames: []string{"Read sensitive file untrusted"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "myapp"},
					},
				},
			},
			want: `- rule: Read sensitive file untrusted
  exceptions:
    - name: Suppress myapp
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
  override:
    exceptions: append
`,
		},
		{
			name: "single exception, multiple conditions become a single tuple",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress myapp in default ns",
					RuleNames: []string{"Read sensitive file untrusted"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "myapp"},
						{Field: "k8s.ns.name", Operator: "=", Value: "default"},
					},
				},
			},
			want: `- rule: Read sensitive file untrusted
  exceptions:
    - name: Suppress myapp in default ns
      fields:
        - proc.name
        - k8s.ns.name
      comps:
        - =
        - =
      values:
        - [myapp, default]
  override:
    exceptions: append
`,
		},
		{
			name: "exception targeting multiple rules produces one block per rule",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress myapp",
					RuleNames: []string{"Read sensitive file untrusted", "Write below root"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "myapp"},
					},
				},
			},
			want: `- rule: Read sensitive file untrusted
  exceptions:
    - name: Suppress myapp
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
  override:
    exceptions: append
- rule: Write below root
  exceptions:
    - name: Suppress myapp
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
  override:
    exceptions: append
`,
		},
		{
			name: "multiple exceptions targeting the same rule are merged into one block",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress myapp",
					RuleNames: []string{"Read sensitive file untrusted"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "myapp"},
					},
				},
				{
					ID:        2,
					Name:      "Suppress production ns",
					RuleNames: []string{"Read sensitive file untrusted"},
					Conditions: []models.ExceptionCondition{
						{Field: "k8s.ns.name", Operator: "=", Value: "production"},
					},
				},
			},
			want: `- rule: Read sensitive file untrusted
  exceptions:
    - name: Suppress myapp
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
    - name: Suppress production ns
      fields:
        - k8s.ns.name
      comps:
        - =
      values:
        - [production]
  override:
    exceptions: append
`,
		},
		{
			name: "rule order follows first-seen order, not alphabetical",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress writes",
					RuleNames: []string{"Write below root"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "myapp"},
					},
				},
				{
					ID:        2,
					Name:      "Suppress reads",
					RuleNames: []string{"Read sensitive file untrusted"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "myapp"},
					},
				},
			},
			want: `- rule: Write below root
  exceptions:
    - name: Suppress writes
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
  override:
    exceptions: append
- rule: Read sensitive file untrusted
  exceptions:
    - name: Suppress reads
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
  override:
    exceptions: append
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildExceptionsYAML(tt.exceptions)
			if got != tt.want {
				t.Errorf("buildExceptionsYAML() mismatch\ngot:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}
