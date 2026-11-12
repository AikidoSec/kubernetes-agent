package models

import "testing"

func TestIsRuntimeDetectionAvailable(t *testing.T) {
	tests := []struct {
		name          string
		chartsEnabled bool
		setupFailed   bool
		want          bool
	}{
		{name: "charts disabled", chartsEnabled: false, setupFailed: false, want: false},
		{name: "charts enabled", chartsEnabled: true, setupFailed: false, want: true},
		{name: "charts enabled but proxy setup failed", chartsEnabled: true, setupFailed: true, want: false},
		{name: "charts disabled and proxy setup failed", chartsEnabled: false, setupFailed: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewEmptyAgentState()
			state.SetChartsRuntimeDetectionEnabled(tt.chartsEnabled)
			state.SetRuntimeDetectionSetupFailed(tt.setupFailed)

			if got := state.IsRuntimeDetectionAvailable(); got != tt.want {
				t.Errorf("IsRuntimeDetectionAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}
