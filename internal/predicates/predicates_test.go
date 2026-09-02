package predicates_test

import (
	"testing"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	swv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/controllers/argoproj"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
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
			n := predicates.NewNamespaceFilter(&testLogger{}, tt.excludedNamespaces, tt.includedNamespaces)
			got := n.IsObjectExcluded(tt.obj)
			if got != tt.want {
				t.Errorf("NamespaceFilter.IsObjectExcluded() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsSpecModifiedTypedObjects covers the typed objects controller-runtime hands to
// For(&Typed{}) vendor-CRD watches — the case that previously always returned false,
// leaving CRD spec edits un-enqueued until the scheduled requeue.
func TestIsSpecModifiedTypedObjects(t *testing.T) {
	ephemeralRunner := func(url string) client.Object {
		er := &ghv1alpha1.EphemeralRunner{}
		er.Spec.GitHubConfigUrl = url
		return er
	}

	// ArgoCD Application stores its spec as runtime.RawExtension.
	application := func(specJSON string) client.Object {
		return &argoproj.Application{Spec: runtime.RawExtension{Raw: []byte(specJSON)}}
	}

	runnerWithMTU := func(mtu int64) client.Object {
		r := &swv1alpha1.Runner{}
		r.Spec.DockerMTU = &mtu
		return r
	}

	tests := []struct {
		name     string
		old, new client.Object
		want     bool
	}{
		{
			name: "typed EphemeralRunner spec change enqueues",
			old:  ephemeralRunner("https://github.com/old"),
			new:  ephemeralRunner("https://github.com/new"),
			want: true,
		},
		{
			name: "typed EphemeralRunner unchanged spec is dropped",
			old:  ephemeralRunner("https://github.com/same"),
			new:  ephemeralRunner("https://github.com/same"),
			want: false,
		},
		{
			name: "RawExtension Application spec change enqueues",
			old:  application(`{"project":"default"}`),
			new:  application(`{"project":"prod"}`),
			want: true,
		},
		{
			name: "RawExtension Application unchanged spec is dropped",
			old:  application(`{"project":"default"}`),
			new:  application(`{"project":"default"}`),
			want: false,
		},
		{
			name: "int64 spec change above 2^53 is detected",
			old:  runnerWithMTU(1 << 53),
			new:  runnerWithMTU((1 << 53) + 2),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.new}
			if got := predicates.IsSpecModified(e); got != tt.want {
				t.Errorf("IsSpecModified() = %v, want %v", got, tt.want)
			}
		})
	}
}
