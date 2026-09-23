package predicates_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/predicates"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestMetadataChanges(t *testing.T) {
	for _, representation := range []string{"typed", "unstructured"} {
		for _, field := range []string{"labels", "annotations"} {
			for _, tt := range []struct {
				name     string
				old, new map[string]string
				want     bool
			}{
				{name: "absent"},
				{name: "nil and empty are equivalent", new: map[string]string{}},
				{name: "added", new: map[string]string{"key": "value"}, want: true},
				{name: "removed", old: map[string]string{"key": "value"}, want: true},
				{name: "changed", old: map[string]string{"key": "old"}, new: map[string]string{"key": "new"}, want: true},
				{name: "unchanged", old: map[string]string{"a": "1", "b": "2"}, new: map[string]string{"b": "2", "a": "1"}},
			} {
				t.Run(representation+"/"+field+"/"+tt.name, func(t *testing.T) {
					var old, next client.Object = &corev1.ServiceAccount{}, &corev1.ServiceAccount{}
					if representation == "unstructured" {
						old, next = &unstructured.Unstructured{}, &unstructured.Unstructured{}
					}
					check := predicates.AreLabelsChanged
					if field == "labels" {
						old.SetLabels(tt.old)
						next.SetLabels(tt.new)
					} else {
						old.SetAnnotations(tt.old)
						next.SetAnnotations(tt.new)
						check = predicates.AreAnnotationsChanged
					}
					if got := check(event.UpdateEvent{ObjectOld: old, ObjectNew: next}); got != tt.want {
						t.Errorf("metadata changed = %v, want %v", got, tt.want)
					}
				})
			}
		}
	}
}

// Exercise dispatch as well as the predicates: only watchers that opt into
// metadata updates should enqueue them, and namespace filters take priority.
func TestWatcherMetadataUpdates(t *testing.T) {
	filter := predicates.NewNamespaceFilter(&testLogger{}, []string{"excluded"}, nil)
	for _, watcher := range []struct {
		gvk             string
		metadataUpdates bool
	}{
		{"apps/v1, Kind=Deployment", true},
		{"/v1, Kind=ServiceAccount", true},
		{"/v1, Kind=Pod", true},
		{"/v1, Kind=Service", false},
		{"networking.k8s.io/v1, Kind=Ingress", false},
		{"route.openshift.io/v1, Kind=Route", false},
		{"operator.openshift.io/v1, Kind=IngressController", false},
		{"gateway.networking.k8s.io/v1, Kind=Gateway", false},
		{"gateway.networking.k8s.io/v1, Kind=HTTPRoute", false},
	} {
		for _, tt := range []struct {
			name   string
			mutate func(*unstructured.Unstructured)
			want   bool
		}{
			{name: "unchanged", mutate: func(_ *unstructured.Unstructured) {}},
			{name: "resource version only", mutate: func(o *unstructured.Unstructured) { o.SetResourceVersion("2") }},
			{name: "label added", mutate: func(o *unstructured.Unstructured) { o.SetLabels(map[string]string{"team": "platform"}) }, want: true},
			{name: "annotation added", mutate: func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"owner": "platform"}) }, want: true},
		} {
			for _, namespace := range []string{"default", "excluded"} {
				t.Run(watcher.gvk+"/"+tt.name+"/"+namespace, func(t *testing.T) {
					old := &unstructured.Unstructured{Object: map[string]any{
						"spec":   map[string]any{},
						"status": map[string]any{"phase": "Running"},
					}}
					old.SetNamespace(namespace)
					next := old.DeepCopy()
					tt.mutate(next)
					want := tt.want && watcher.metadataUpdates && namespace != "excluded"
					if got := predicates.GetPredicatesForGVK(watcher.gvk, filter).Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}); got != want {
						t.Errorf("Update() = %v, want %v", got, want)
					}
				})
			}
		}
	}
}

func TestPodMetadataUpdatesRespectReadiness(t *testing.T) {
	filter := predicates.NewNamespaceFilter(&testLogger{}, nil, nil)
	for _, tt := range []struct {
		name, phase, imageID string
		want                 bool
	}{
		{name: "pending", phase: "Pending", imageID: "sha256:resolved"},
		{name: "unresolved image", phase: "Running"},
		{name: "running and resolved", phase: "Running", imageID: "sha256:resolved", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := &unstructured.Unstructured{Object: map[string]any{
				"spec":   map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:latest"}}},
				"status": map[string]any{"phase": tt.phase, "containerStatuses": []any{map[string]any{"name": "app", "imageID": tt.imageID}}},
			}}
			next := old.DeepCopy()
			next.SetLabels(map[string]string{"team": "platform"})
			if got := predicates.NewPodPredicate(filter).Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}); got != tt.want {
				t.Errorf("Update() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceAndGatewaySpecAndStatusUpdates(t *testing.T) {
	filter := predicates.NewNamespaceFilter(&testLogger{}, []string{"excluded"}, nil)
	for _, gvk := range []string{
		"/v1, Kind=Service", "networking.k8s.io/v1, Kind=Ingress",
		"route.openshift.io/v1, Kind=Route", "operator.openshift.io/v1, Kind=IngressController",
		"gateway.networking.k8s.io/v1, Kind=Gateway", "gateway.networking.k8s.io/v1, Kind=HTTPRoute",
	} {
		for _, field := range []string{"spec", "status"} {
			for _, namespace := range []string{"default", "excluded"} {
				t.Run(gvk+"/"+field+"/"+namespace, func(t *testing.T) {
					old := &unstructured.Unstructured{Object: map[string]any{
						"spec": map[string]any{}, "status": map[string]any{},
					}}
					old.SetNamespace(namespace)
					next := old.DeepCopy()
					next.Object[field] = map[string]any{"changed": "value"}
					want := namespace != "excluded"
					if got := predicates.GetPredicatesForGVK(gvk, filter).Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}); got != want {
						t.Errorf("Update() = %v, want %v", got, want)
					}
				})
			}
		}
	}
}
