package models

import "testing"

func TestIsSBOMCollectorDisabledInCharts(t *testing.T) {
	enabled := true
	disabled := false

	tests := []struct {
		name                 string
		sbomCollectorEnabled *bool
		want                 bool
	}{
		{name: "flag not set by older charts", sbomCollectorEnabled: nil, want: false},
		{name: "collector enabled in charts", sbomCollectorEnabled: &enabled, want: false},
		{name: "collector disabled in charts", sbomCollectorEnabled: &disabled, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environmentConfig := EnvironmentConfig{SBOMCollectorEnabled: tt.sbomCollectorEnabled}

			if got := environmentConfig.IsSBOMCollectorDisabledInCharts(); got != tt.want {
				t.Errorf("IsSBOMCollectorDisabledInCharts() = %v, want %v", got, tt.want)
			}
		})
	}
}
