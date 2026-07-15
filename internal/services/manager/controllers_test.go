package manager

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestMergeMonitoredResources(t *testing.T) {
	networkPolicy := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	ingress := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}
	ingressClass := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "IngressClass"}
	pod := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}

	tests := []struct {
		name     string
		server   []schema.GroupVersionKind
		builtin  []schema.GroupVersionKind
		expected []schema.GroupVersionKind
	}{
		{
			name:     "server list still sends built-ins, no duplicates",
			server:   []schema.GroupVersionKind{pod, networkPolicy, ingress},
			builtin:  []schema.GroupVersionKind{networkPolicy, ingress, ingressClass},
			expected: []schema.GroupVersionKind{pod, networkPolicy, ingress, ingressClass},
		},
		{
			name:     "server trimmed built-ins, agent still covers them",
			server:   []schema.GroupVersionKind{pod},
			builtin:  []schema.GroupVersionKind{networkPolicy, ingress, ingressClass},
			expected: []schema.GroupVersionKind{pod, networkPolicy, ingress, ingressClass},
		},
		{
			name:     "empty server list falls back to built-ins",
			server:   nil,
			builtin:  []schema.GroupVersionKind{networkPolicy, ingress, ingressClass},
			expected: []schema.GroupVersionKind{networkPolicy, ingress, ingressClass},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeMonitoredResources(tt.server, tt.builtin)
			if len(got) != len(tt.expected) {
				t.Fatalf("mergeMonitoredResources() length = %d, want %d (%v)", len(got), len(tt.expected), got)
			}
			for i, gvk := range got {
				if gvk != tt.expected[i] {
					t.Errorf("mergeMonitoredResources()[%d] = %v, want %v", i, gvk, tt.expected[i])
				}
			}
		})
	}
}

func TestMergeMonitoredResourcesDoesNotMutateInput(t *testing.T) {
	server := []schema.GroupVersionKind{{Group: "", Version: "v1", Kind: "Pod"}}
	builtin := []schema.GroupVersionKind{{Group: "networking.k8s.io", Version: "v1", Kind: "IngressClass"}}

	mergeMonitoredResources(server, builtin)

	if len(server) != 1 {
		t.Errorf("server slice was mutated, length = %d, want 1", len(server))
	}
}
