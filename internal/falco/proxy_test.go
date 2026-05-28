package falco

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
)

func newTestProxy(excludedNamespaces, includedNamespaces []string, ignoredImageRepositories []string) *Proxy {
	agentState := models.NewEmptyAgentState()
	agentState.SetExcludedNamespaces(excludedNamespaces)
	agentState.SetIncludedNamespaces(includedNamespaces)

	return &Proxy{
		Service:                   logger.NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		AgentState:                agentState,
		ignoredImageRepositories: ignoredImageRepositories,
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

func TestShouldDrop(t *testing.T) {
	tests := []struct {
		name                      string
		excludedNamespaces        []string
		includedNamespaces        []string
		ignoredImageRepositories []string
		body                      string
		wantDrop                  bool
	}{
		{
			name:     "invalid JSON is dropped",
			body:     `not json`,
			wantDrop: true,
		},
		{
			name:     "event with no namespace passes through",
			body:     `{"output_fields": {"proc.name": "cat"}}`,
			wantDrop: false,
		},
		{
			name:                      "event from agent image container is dropped",
			ignoredImageRepositories: []string{"public.ecr.aws/aikido-cloud/kubernetes-agent", "falcosecurity/falco"},
			body:                      `{"output_fields": {"container.image.repository": "public.ecr.aws/aikido-cloud/kubernetes-agent"}}`,
			wantDrop:                  true,
		},
		{
			name:                      "event from falco image container is dropped",
			ignoredImageRepositories: []string{"public.ecr.aws/aikido-cloud/kubernetes-agent", "falcosecurity/falco"},
			body:                      `{"output_fields": {"container.image.repository": "falcosecurity/falco"}}`,
			wantDrop:                  true,
		},
		{
			name:                      "event from other container in agent namespace passes through",
			ignoredImageRepositories: []string{"public.ecr.aws/aikido-cloud/kubernetes-agent", "falcosecurity/falco"},
			body:                      `{"output_fields": {"k8s.ns.name": "aikido-system", "container.image.repository": "nginx"}}`,
			wantDrop:                  false,
		},
		{
			name:                      "event with no image repository field passes through",
			ignoredImageRepositories: []string{"public.ecr.aws/aikido-cloud/kubernetes-agent", "falcosecurity/falco"},
			body:                      `{"output_fields": {"k8s.ns.name": "default"}}`,
			wantDrop:                  false,
		},
		{
			name:               "event from excluded namespace is dropped",
			excludedNamespaces: []string{"kube-system"},
			body:               `{"output_fields": {"k8s.ns.name": "kube-system"}}`,
			wantDrop:           true,
		},
		{
			name:               "event from non-excluded namespace passes through",
			excludedNamespaces: []string{"kube-system"},
			body:               `{"output_fields": {"k8s.ns.name": "default"}}`,
			wantDrop:           false,
		},
		{
			name:               "event from namespace not in include list is dropped",
			includedNamespaces: []string{"production", "staging"},
			body:               `{"output_fields": {"k8s.ns.name": "kube-system"}}`,
			wantDrop:           true,
		},
		{
			name:               "event from namespace in include list passes through",
			includedNamespaces: []string{"production", "staging"},
			body:               `{"output_fields": {"k8s.ns.name": "production"}}`,
			wantDrop:           false,
		},
		{
			name:               "event with no namespace passes through even with non-empty include list",
			includedNamespaces: []string{"production"},
			body:               `{"output_fields": {"proc.name": "cat"}}`,
			wantDrop:           false,
		},
		{
			name:     "wrong type for tags field is dropped",
			body:     `{"tags": 123}`,
			wantDrop: true,
		},
		{
			name:     "wrong type for output_fields is dropped",
			body:     `{"output_fields": "not-an-object"}`,
			wantDrop: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestProxy(tt.excludedNamespaces, tt.includedNamespaces, tt.ignoredImageRepositories)
			raw, event, err := parseEvent([]byte(tt.body))
			drop := err != nil || proxy.shouldDrop(event)
			_ = raw
			if drop != tt.wantDrop {
				t.Errorf("shouldDrop() = %v, want %v", drop, tt.wantDrop)
			}
		})
	}
}

func TestStripAikidoTags(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantTags []string
	}{
		{
			name:     "aikido tags are stripped",
			body:     `{"tags": ["network", "aikido:threat-detection", "filesystem"]}`,
			wantTags: []string{"network", "filesystem"},
		},
		{
			name:     "non-aikido tags are preserved",
			body:     `{"tags": ["network", "filesystem"]}`,
			wantTags: []string{"network", "filesystem"},
		},
		{
			name:     "all aikido tags produces empty array",
			body:     `{"tags": ["aikido:threat-detection", "aikido:sca"]}`,
			wantTags: []string{},
		},
		{
			name:     "no tags field produces empty array",
			body:     `{"rule": "some rule"}`,
			wantTags: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, event, err := parseEvent([]byte(tt.body))
			if err != nil {
				t.Fatalf("parseEvent() error = %v", err)
			}
			sanitized, err := stripAikidoTags(raw, event.Tags)
			if err != nil {
				t.Fatalf("stripAikidoTags() error = %v", err)
			}

			var result struct {
				Tags []string `json:"tags"`
			}
			if err := json.Unmarshal(sanitized, &result); err != nil {
				t.Fatalf("unmarshal result error = %v", err)
			}
			if len(result.Tags) != len(tt.wantTags) {
				t.Errorf("tags = %v, want %v", result.Tags, tt.wantTags)
				return
			}
			for i, tag := range result.Tags {
				if tag != tt.wantTags[i] {
					t.Errorf("tags[%d] = %q, want %q", i, tag, tt.wantTags[i])
				}
			}
		})
	}
}
