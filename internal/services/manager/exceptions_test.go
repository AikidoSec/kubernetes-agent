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
    - name: '1: Suppress myapp'
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
    - name: '1: Suppress myapp in default ns'
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
    - name: '1: Suppress myapp'
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
    - name: '1: Suppress myapp'
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
    - name: '1: Suppress myapp'
      fields:
        - proc.name
      comps:
        - =
      values:
        - [myapp]
    - name: '2: Suppress production ns'
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
			name: "in operator value is split into a nested list",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress cat on sensitive files",
					RuleNames: []string{"Read sensitive file untrusted"},
					Conditions: []models.ExceptionCondition{
						{Field: "proc.name", Operator: "=", Value: "cat"},
						{Field: "fd.name", Operator: "in", Value: "/etc/shadow, /etc/passwd"},
					},
				},
			},
			want: `- rule: Read sensitive file untrusted
  exceptions:
    - name: '1: Suppress cat on sensitive files'
      fields:
        - proc.name
        - fd.name
      comps:
        - =
        - in
      values:
        - [cat, [/etc/shadow, /etc/passwd]]
  override:
    exceptions: append
`,
		},
		{
			name: "exception is skipped entirely when in operator value contains only whitespace and commas",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "breaking",
					RuleNames: []string{"Clear Log Activities"},
					Conditions: []models.ExceptionCondition{
						{Field: "k8s.ns.name", Operator: "in", Value: " , , "},
					},
				},
			},
			want: "",
		},
		{
			name: "in operator value skips empty segments from consecutive or trailing commas",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress writes",
					RuleNames: []string{"Write below root"},
					Conditions: []models.ExceptionCondition{
						{Field: "fd.directory", Operator: "in", Value: "/tmp,,/var/tmp,"},
					},
				},
			},
			want: `- rule: Write below root
  exceptions:
    - name: '1: Suppress writes'
      fields:
        - fd.directory
      comps:
        - in
      values:
        - [[/tmp, /var/tmp]]
  override:
    exceptions: append
`,
		},
		{
			name: "in operator value is trimmed of whitespace around commas",
			exceptions: []models.ThreatDetectionException{
				{
					ID:        1,
					Name:      "Suppress writes",
					RuleNames: []string{"Write below root"},
					Conditions: []models.ExceptionCondition{
						{Field: "fd.directory", Operator: "in", Value: "/tmp , /var/tmp , /dev/shm"},
					},
				},
			},
			want: `- rule: Write below root
  exceptions:
    - name: '1: Suppress writes'
      fields:
        - fd.directory
      comps:
        - in
      values:
        - [[/tmp, /var/tmp, /dev/shm]]
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
    - name: '1: Suppress writes'
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
    - name: '2: Suppress reads'
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
