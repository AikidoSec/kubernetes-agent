package config

import "testing"

func TestParseEnvironmentConfigsFalcoDaemonSetName(t *testing.T) {
	tests := []struct {
		name         string
		daemonSetEnv *string
		want         string
	}{
		{name: "defaults to agent name suffix", daemonSetEnv: nil, want: "my-agent-runtime-detection"},
		{name: "uses env override", daemonSetEnv: ptrTo("release-kubernetes-agent-runtime-detection"), want: "release-kubernetes-agent-runtime-detection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("POD_NAME", "my-agent-7d9c5b6f4-x2x9q")
			if tt.daemonSetEnv != nil {
				t.Setenv("FALCO_DAEMONSET_NAME", *tt.daemonSetEnv)
			}

			envConfig, err := ParseEnvironmentConfigs()
			if err != nil {
				t.Fatalf("ParseEnvironmentConfigs() error = %v", err)
			}
			if envConfig.FalcoDaemonSetName != tt.want {
				t.Errorf("FalcoDaemonSetName = %q, want %q", envConfig.FalcoDaemonSetName, tt.want)
			}
		})
	}
}

func ptrTo[T any](value T) *T { return &value }
