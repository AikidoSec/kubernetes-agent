package threat

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
)

func newTestProxy(agentNamespace string, excludedNamespaces, includedNamespaces, disabledRules []string) *Proxy {
	agentState := models.NewEmptyAgentState()
	agentState.SetAgentNamespace(agentNamespace)
	agentState.SetExcludedNamespaces(excludedNamespaces)
	agentState.SetIncludedNamespaces(includedNamespaces)
	agentState.SetDisabledThreatRules(disabledRules)

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
		disabledRules      []string
		body               string
		want               bool
	}{
		{
			name:           "event for a disabled rule is filtered out",
			agentNamespace: "aikido-system",
			disabledRules:  []string{"name:Write below etc"},
			body:           `{"rule": "Write below etc", "output_fields": {"k8smeta.ns.name": "default"}}`,
			want:           true,
		},
		{
			name:           "event for a non-disabled rule passes through",
			agentNamespace: "aikido-system",
			disabledRules:  []string{"name:Write below etc"},
			body:           `{"rule": "Terminal shell in container", "output_fields": {"k8smeta.ns.name": "default"}}`,
			want:           false,
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
			body:           `{"output_fields": {"proc.name": "cat"}}`,
			want:           false,
		},
		{
			name:           "event from agent namespace is filtered out",
			agentNamespace: "aikido-system",
			body:           `{"output_fields": {"k8smeta.ns.name": "aikido-system"}}`,
			want:           true,
		},
		{
			name:           "k8s.ns.name is used as fallback when k8smeta.ns.name is absent",
			agentNamespace: "aikido-system",
			body:           `{"output_fields": {"k8s.ns.name": "aikido-system"}}`,
			want:           true,
		},
		{
			name:               "k8smeta.ns.name takes precedence over k8s.ns.name",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"excluded-ns"},
			body:               `{"output_fields": {"k8smeta.ns.name": "excluded-ns", "k8s.ns.name": "default"}}`,
			want:               true,
		},
		{
			name:               "event from excluded namespace is filtered out",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"kube-system"},
			body:               `{"output_fields": {"k8smeta.ns.name": "kube-system"}}`,
			want:               true,
		},
		{
			name:               "event from non-excluded namespace passes through",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"kube-system"},
			body:               `{"output_fields": {"k8smeta.ns.name": "default"}}`,
			want:               false,
		},
		{
			name:               "event from namespace not in include list is filtered out",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production", "staging"},
			body:               `{"output_fields": {"k8smeta.ns.name": "kube-system"}}`,
			want:               true,
		},
		{
			name:               "event from namespace in include list passes through",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production", "staging"},
			body:               `{"output_fields": {"k8smeta.ns.name": "production"}}`,
			want:               false,
		},
		{
			name:               "event with no namespace passes through even with non-empty include list",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production"},
			body:               `{"output_fields": {"proc.name": "cat"}}`,
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestProxy(tt.agentNamespace, tt.excludedNamespaces, tt.includedNamespaces, tt.disabledRules)
			got := proxy.ShouldFilterOutEvent(context.Background(), threatDetection(tt.body))
			if got != tt.want {
				t.Errorf("ShouldFilterOutEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}
