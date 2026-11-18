package config

import (
	"testing"

	"aikidoSec.kubernetesAgent/pkg/models"
)

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

func TestParseEnvironmentConfigsMetadataTransforms(t *testing.T) {
	tests := []struct {
		name    string
		env     *string
		wantErr bool
		check   func(t *testing.T, cfg models.MetadataTransforms)
	}{
		{name: "unset yields empty rules", env: nil, check: func(t *testing.T, cfg models.MetadataTransforms) {
			if !cfg.IsEmpty() {
				t.Errorf("expected empty rules, got %+v", cfg)
			}
		}},
		{
			name: "valid yaml",
			env:  ptrTo("labels:\n  team:\n    rename: owner\n    valueMap:\n      a: b\nannotations:\n  x/y:\n    drop: true\n"),
			check: func(t *testing.T, cfg models.MetadataTransforms) {
				rule := cfg.Labels["team"]
				if rule.Rename == nil || *rule.Rename != "owner" || rule.ValueMap["a"] != "b" {
					t.Errorf("unexpected label rule %+v", rule)
				}
				if !cfg.Annotations["x/y"].Drop {
					t.Errorf("expected annotation drop rule")
				}
			},
		},
		{
			name: "valid json",
			env:  ptrTo(`{"labels":{"team":{"valueMap":{"a":"b"}}}}`),
			check: func(t *testing.T, cfg models.MetadataTransforms) {
				if cfg.Labels["team"].ValueMap["a"] != "b" {
					t.Errorf("unexpected rules %+v", cfg)
				}
			},
		},
		{name: "drop with rename", env: ptrTo(`{"labels":{"team":{"drop":true,"rename":"owner"}}}`), wantErr: true},
		{name: "drop with valueMap", env: ptrTo(`{"labels":{"team":{"drop":true,"valueMap":{"a":"b"}}}}`), wantErr: true},
		{name: "empty rename target", env: ptrTo(`{"annotations":{"team":{"rename":""}}}`), wantErr: true},
		{name: "empty key", env: ptrTo(`{"labels":{"":{"drop":true}}}`), wantErr: true},
		{name: "malformed", env: ptrTo("labels: [unclosed"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("POD_NAME", "my-agent-7d9c5b6f4-x2x9q")
			if tt.env != nil {
				t.Setenv("METADATA_TRANSFORMS", *tt.env)
			}

			cfg, err := ParseEnvironmentConfigs()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnvironmentConfigs() error = %v", err)
			}
			tt.check(t, cfg.MetadataTransforms)
		})
	}
}
