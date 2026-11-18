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
			env:  ptrTo("labels:\n  team:\n    rename: owner\n    valueMap:\n      a: b\nannotations:\n  x/y:\n    redact: true\n"),
			check: func(t *testing.T, cfg models.MetadataTransforms) {
				rule := cfg.Labels["team"]
				if rule.Rename == nil || *rule.Rename != "owner" || rule.ValueMap["a"] != "b" {
					t.Errorf("unexpected label rule %+v", rule)
				}
				if !cfg.Annotations["x/y"].Redact {
					t.Errorf("expected annotation redact rule")
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
		{name: "redact with valueMap", env: ptrTo(`{"labels":{"team":{"redact":true,"valueMap":{"a":"b"}}}}`), wantErr: true},
		{name: "protected label key", env: ptrTo(`{"labels":{"kubernetes.io/service-name":{"redact":true}}}`), wantErr: true},
		{name: "protected annotation key", env: ptrTo(`{"annotations":{"kubernetes.io/ingress.class":{"valueMap":{"a":"b"}}}}`), wantErr: true},
		{name: "protected rename target", env: ptrTo(`{"annotations":{"ingress":{"rename":"getambassador.io/config"}}}`), wantErr: true},
		{
			name: "protected annotation key is allowed as a label",
			env:  ptrTo(`{"labels":{"kubernetes.io/ingress.class":{"redact":true}}}`),
			check: func(t *testing.T, cfg models.MetadataTransforms) {
				if !cfg.Labels["kubernetes.io/ingress.class"].Redact {
					t.Errorf("expected label redact rule, got %+v", cfg)
				}
			},
		},
		{name: "empty rename target", env: ptrTo(`{"annotations":{"team":{"rename":""}}}`), wantErr: true},
		{name: "empty key", env: ptrTo(`{"labels":{"":{"redact":true}}}`), wantErr: true},
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
