package predicates_test

import (
	"testing"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/controllers/argoproj"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

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
