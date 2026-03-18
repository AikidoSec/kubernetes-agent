package falco

import (
	"io"
	"log/slog"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
)

func newTestProxy(agentNamespace string, excludedNamespaces, includedNamespaces []string) *Proxy {
	agentState := models.NewEmptyAgentState()
	agentState.SetAgentNamespace(agentNamespace)
	agentState.SetExcludedNamespaces(excludedNamespaces)
	agentState.SetIncludedNamespaces(includedNamespaces)

	return &Proxy{
		Service:    logger.NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		AgentState: agentState,
	}
}

func TestHasAikidoTag(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want bool
	}{
		{"no tags", nil, false},
		{"empty tags", []string{}, false},
		{"unrelated tags only", []string{"network", "filesystem"}, false},
		{"aikido routing tag present", []string{"network", "aikido:threat-detection"}, true},
		{"multiple aikido tags", []string{"aikido:threat-detection", "aikido:sca"}, true},
		{"aikido prefix without colon not matched", []string{"aikido"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAikidoTag(tt.tags); got != tt.want {
				t.Errorf("hasAikidoTag(%v) = %v, want %v", tt.tags, got, tt.want)
			}
		})
	}
}

func TestParseAndFilter(t *testing.T) {
	tests := []struct {
		name               string
		agentNamespace     string
		excludedNamespaces []string
		includedNamespaces []string
		body               string
		wantDrop           bool
	}{
		{
			name:           "invalid JSON is dropped",
			agentNamespace: "aikido-system",
			body:           `not json`,
			wantDrop:       true,
		},
		{
			name:           "event with no namespace passes through",
			agentNamespace: "aikido-system",
			body:           `{"output_fields": {"proc.name": "cat"}}`,
			wantDrop:       false,
		},
		{
			name:           "event from agent namespace is dropped",
			agentNamespace: "aikido-system",
			body:           `{"output_fields": {"k8s.ns.name": "aikido-system"}}`,
			wantDrop:       true,
		},
		{
			name:               "event from excluded namespace is dropped",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"kube-system"},
			body:               `{"output_fields": {"k8s.ns.name": "kube-system"}}`,
			wantDrop:           true,
		},
		{
			name:               "event from non-excluded namespace passes through",
			agentNamespace:     "aikido-system",
			excludedNamespaces: []string{"kube-system"},
			body:               `{"output_fields": {"k8s.ns.name": "default"}}`,
			wantDrop:           false,
		},
		{
			name:               "event from namespace not in include list is dropped",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production", "staging"},
			body:               `{"output_fields": {"k8s.ns.name": "kube-system"}}`,
			wantDrop:           true,
		},
		{
			name:               "event from namespace in include list passes through",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production", "staging"},
			body:               `{"output_fields": {"k8s.ns.name": "production"}}`,
			wantDrop:           false,
		},
		{
			name:               "event with no namespace passes through even with non-empty include list",
			agentNamespace:     "aikido-system",
			includedNamespaces: []string{"production"},
			body:               `{"output_fields": {"proc.name": "cat"}}`,
			wantDrop:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestProxy(tt.agentNamespace, tt.excludedNamespaces, tt.includedNamespaces)
			_, drop := proxy.parseAndFilter([]byte(tt.body))
			if drop != tt.wantDrop {
				t.Errorf("parseAndFilter() drop = %v, want %v", drop, tt.wantDrop)
			}
		})
	}
}
