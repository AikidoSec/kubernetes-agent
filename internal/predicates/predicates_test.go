package predicates

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type testLogger struct{}

func (l *testLogger) LogWarning(_ error, _ string, _ ...any) {}

func TestNamespaceFilterIsObjectExcluded(t *testing.T) {
	tests := []struct {
		name               string
		obj                *unstructured.Unstructured
		excludedNamespaces []string
		includedNamespaces []string
		want               bool
	}{
		{
			name: "namespace is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"kube-system", "kube-public"},
			want:               true,
		},
		{
			name: "namespace is not excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "default",
					},
				},
			},
			excludedNamespaces: []string{"kube-system", "kube-public"},
			want:               false,
		},
		{
			name: "empty namespace",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name": "test-resource",
					},
				},
			},
			excludedNamespaces: []string{"kube-system"},
			want:               false,
		},
		{
			name: "empty excluded list",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{},
			want:               false,
		},
		{
			name: "nil excluded list",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: nil,
			want:               false,
		},
		{
			name: "namespace is excluded with wildcard",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"kube-*"},
			want:               true,
		},
		{
			name: "namespace is excluded with wildcard (2)",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"*-system"},
			want:               true,
		},
		{
			name: "namespace list invalid pattern is ignored",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"[!-system*"},
			want:               false,
		},
		{
			name: "namespace list invalid pattern is ignored (2)",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"[!-system*", "kub**"},
			want:               true,
		},
		{
			name: "included namespace is not excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "app-ns",
					},
				},
			},
			includedNamespaces: []string{"app-ns", "web-ns"},
			want:               false,
		},
		{
			name: "namespace not in include list is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			includedNamespaces: []string{"app-ns", "web-ns"},
			want:               true,
		},
		{
			name: "included namespace with wildcard",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "app-staging",
					},
				},
			},
			includedNamespaces: []string{"app-*"},
			want:               false,
		},
		{
			name: "namespace not matching include wildcard is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			includedNamespaces: []string{"app-*"},
			want:               true,
		},
		{
			name: "empty namespace with include filter",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name": "test-resource",
					},
				},
			},
			includedNamespaces: []string{"app-ns"},
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNamespaceFilter(&testLogger{}, tt.excludedNamespaces, tt.includedNamespaces)
			got := n.IsObjectExcluded(tt.obj)
			if got != tt.want {
				t.Errorf("NamespaceFilter.IsObjectExcluded() = %v, want %v", got, tt.want)
			}
		})
	}
}
