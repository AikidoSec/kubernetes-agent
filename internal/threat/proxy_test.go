package threat

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
)

func newTestProxy(agentNamespace string, excludedNamespaces, includedNamespaces, enabledRules []string) *Proxy {
	agentState := models.NewEmptyAgentState()
	agentState.SetAgentNamespace(agentNamespace)
	agentState.SetExcludedNamespaces(excludedNamespaces)
	agentState.SetIncludedNamespaces(includedNamespaces)
	agentState.SetEnabledThreatRules(enabledRules)

	return &Proxy{
		Service:    logger.NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		AgentState: agentState,
	}
}

func TestShouldFilterOutEvent(t *testing.T) {
	tests := []struct {
		name               string
		agentNamespace     string
		excludedNamespaces []string
		includedNamespaces []string
		enabledRules       []string
		body               string
		want               bool
	}{
		{
			name:           "event for a rule not in the enabled list is filtered out",
			agentNamespace: "aikido-system",
			enabledRules:   []string{"Terminal shell in container"},
			body:           `{"rule": "Write below etc", "output_fields": {"k8s.ns.name": "default"}}`,
			want:           true,
		},
		{
			name:           "event for an enabled rule passes through",
			agentNamespace: "aikido-system",
			enabledRules:   []string{"Write below etc"},
			body:           `{"rule": "Write below etc", "output_fields": {"k8s.ns.name": "default"}}`,
			want:           false,
		},
		{
			name:           "event is filtered out when enabled rules list is empty",
			agentNamespace: "aikido-system",
			enabledRules:   []string{},
			body:           `{"rule": "Write below etc", "output_fields": {"k8s.ns.name": "default"}}`,
			want:           true,
		},
		{
			name:           "invalid JSON is filtered out",
			agentNamespace: "aikido-system",
			body:           `not json`,
			want:           true,
		},
		{
			name:           "event with no namespace passes through",
			agentNamespace: "aikido-system",
			enabledRules:   []string{"Some Rule"},
			body:           `{"rule": "Some Rule", "output_fields": {"proc.name": "cat"}}`,
			want:           false,
		},
		{
			name:           "event from agent namespace is filtered out",
			agentNamespace: "aikido-system",
			enabledRules:   []string{"Some Rule"},
			body:           `{"rule": "Some Rule", "output_fields": {"k8s.ns.name": "aikido-system"}}`,
			want:           true,
		},
		{
			name:               "event from excluded namespace is filtered out",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"kube-system"},
			enabledRules:       []string{"Some Rule"},
			body:               `{"rule": "Some Rule", "output_fields": {"k8s.ns.name": "kube-system"}}`,
			want:               true,
		},
		{
			name:               "event from non-excluded namespace passes through",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"kube-system"},
			enabledRules:       []string{"Some Rule"},
			body:               `{"rule": "Some Rule", "output_fields": {"k8s.ns.name": "default"}}`,
			want:               false,
		},
		{
			name:               "event from namespace not in include list is filtered out",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production", "staging"},
			enabledRules:       []string{"Some Rule"},
			body:               `{"rule": "Some Rule", "output_fields": {"k8s.ns.name": "kube-system"}}`,
			want:               true,
		},
		{
			name:               "event from namespace in include list passes through",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production", "staging"},
			enabledRules:       []string{"Some Rule"},
			body:               `{"rule": "Some Rule", "output_fields": {"k8s.ns.name": "production"}}`,
			want:               false,
		},
		{
			name:               "event with no namespace passes through even with non-empty include list",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production"},
			enabledRules:       []string{"Some Rule"},
			body:               `{"rule": "Some Rule", "output_fields": {"proc.name": "cat"}}`,
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestProxy(tt.agentNamespace, tt.excludedNamespaces, tt.includedNamespaces, tt.enabledRules)
			got := proxy.ShouldFilterOutEvent(context.Background(), threatDetection(tt.body))
			if got != tt.want {
				t.Errorf("ShouldFilterOutEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}
