package manager

import (
	"testing"
)

func TestBuildRulesOverrideYAML(t *testing.T) {
	tests := []struct {
		name              string
		enabledRules      []string
		runtimeSCAEnabled bool
		want              string
	}{
		{
			name:         "no enabled rules produces only the global disable",
			enabledRules: []string{},
			want: `rules:
    - disable:
        rule: '*'
`,
		},
		{
			name:         "single enabled rule appends one enable entry after the global disable",
			enabledRules: []string{"Read sensitive file untrusted"},
			want: `rules:
    - disable:
        rule: '*'
    - enable:
        rule: Read sensitive file untrusted
`,
		},
		{
			name:         "multiple enabled rules preserve input order",
			enabledRules: []string{"Read sensitive file untrusted", "Write below root"},
			want: `rules:
    - disable:
        rule: '*'
    - enable:
        rule: Read sensitive file untrusted
    - enable:
        rule: Write below root
`,
		},
		{
			name:         "rule order is preserved as provided, not sorted",
			enabledRules: []string{"Write below root", "Read sensitive file untrusted"},
			want: `rules:
    - disable:
        rule: '*'
    - enable:
        rule: Write below root
    - enable:
        rule: Read sensitive file untrusted
`,
		},
		{
			name:              "runtime SCA enabled appends the SCA tag enable entry",
			enabledRules:      []string{"Read sensitive file untrusted"},
			runtimeSCAEnabled: true,
			want: `rules:
    - disable:
        rule: '*'
    - enable:
        rule: Read sensitive file untrusted
    - enable:
        tag: aikido:runtime-sca
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRulesOverrideYAML(tt.enabledRules, tt.runtimeSCAEnabled)
			if err != nil {
				t.Fatalf("buildRulesOverrideYAML() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("buildRulesOverrideYAML() mismatch\ngot:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}
