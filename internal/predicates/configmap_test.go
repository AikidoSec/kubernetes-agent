package predicates_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/predicates"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestConfigMapPredicate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		exclude, include []string
		want             bool
	}{
		{name: "allowed", want: true},
		{name: "excluded", exclude: []string{"app-*"}},
		{name: "included", include: []string{"app-*"}, want: true},
		{name: "not included", include: []string{"other-*"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			filter := predicates.NewNamespaceFilter(&testLogger{}, tt.exclude, tt.include)
			p := predicates.GetPredicatesForGVK("/v1, Kind=ConfigMap", filter)
			old := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "app-prod"}, Data: map[string]string{"key": "old"}}
			if got := p.Create(event.CreateEvent{Object: old}); got != tt.want {
				t.Errorf("Create() = %v, want %v", got, tt.want)
			}
			if got := p.Delete(event.DeleteEvent{Object: old}); got != tt.want {
				t.Errorf("Delete() = %v, want %v", got, tt.want)
			}
			for _, update := range []struct {
				name   string
				mutate func(*corev1.ConfigMap)
			}{
				{name: "unchanged", mutate: func(_ *corev1.ConfigMap) {}},
				{name: "data changed", mutate: func(o *corev1.ConfigMap) { o.Data["key"] = "new" }},
				{name: "data removed", mutate: func(o *corev1.ConfigMap) { o.Data = nil }},
				{name: "binary data added", mutate: func(o *corev1.ConfigMap) { o.BinaryData = map[string][]byte{"key": {1, 2}} }},
				{name: "labels changed", mutate: func(o *corev1.ConfigMap) { o.Labels = map[string]string{"team": "platform"} }},
			} {
				t.Run(update.name, func(t *testing.T) {
					next := old.DeepCopy()
					update.mutate(next)
					if got := p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}); got != tt.want {
						t.Errorf("Update() = %v, want %v", got, tt.want)
					}
				})
			}
		})
	}
}
