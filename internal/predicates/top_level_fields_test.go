package predicates_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/predicates"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestSecurityConfigurationUpdates(t *testing.T) {
	rule := []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}}}
	subject := []any{map[string]any{"kind": "ServiceAccount", "name": "app", "namespace": "default"}}
	for _, resource := range []struct {
		gvk    string
		typed  func() client.Object
		fields map[string]any
	}{
		{"rbac.authorization.k8s.io/v1, Kind=Role", func() client.Object { return &rbacv1.Role{} }, map[string]any{"rules": rule}},
		{"rbac.authorization.k8s.io/v1, Kind=ClusterRole", func() client.Object { return &rbacv1.ClusterRole{} }, map[string]any{"rules": rule, "aggregationRule": map[string]any{"clusterRoleSelectors": []any{map[string]any{"matchLabels": map[string]any{"aggregate": "true"}}}}}},
		{"rbac.authorization.k8s.io/v1, Kind=RoleBinding", func() client.Object { return &rbacv1.RoleBinding{} }, map[string]any{"subjects": subject}},
		{"rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding", func() client.Object { return &rbacv1.ClusterRoleBinding{} }, map[string]any{"subjects": subject}},
		{"/v1, Kind=ServiceAccount", func() client.Object { return &corev1.ServiceAccount{} }, map[string]any{"automountServiceAccountToken": false, "imagePullSecrets": []any{map[string]any{"name": "registry"}}, "secrets": []any{map[string]any{"name": "token"}}}},
	} {
		for field, value := range resource.fields {
			for _, representation := range []string{"unstructured", "typed"} {
				t.Run(resource.gvk+"/"+field+"/"+representation, func(t *testing.T) {
					empty := &unstructured.Unstructured{Object: map[string]any{}}
					populated := empty.DeepCopy()
					populated.Object[field] = value
					changed := populated.DeepCopy()
					switch field {
					case "rules":
						changed.Object[field] = []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"*"}}}
					case "subjects":
						changed.Object[field] = []any{map[string]any{"kind": "ServiceAccount", "name": "other", "namespace": "default"}}
					case "aggregationRule":
						changed.Object[field] = map[string]any{"clusterRoleSelectors": []any{map[string]any{"matchLabels": map[string]any{"aggregate": "other"}}}}
					case "automountServiceAccountToken":
						changed.Object[field] = true
					default:
						changed.Object[field] = []any{map[string]any{"name": "other"}}
					}
					for _, update := range []struct {
						name      string
						old, next *unstructured.Unstructured
						want      bool
					}{
						{"added", empty, populated, true}, {"removed", populated, empty, true}, {"changed", populated, changed, true}, {"unchanged", populated, populated, false},
					} {
						for _, namespace := range []string{"default", "excluded"} {
							t.Run(update.name+"/"+namespace, func(t *testing.T) {
								old, next := update.old.DeepCopy(), update.next.DeepCopy()
								old.SetNamespace(namespace)
								next.SetNamespace(namespace)
								old.SetResourceVersion("1")
								next.SetResourceVersion("2")
								var a, b client.Object = old, next
								if representation == "typed" {
									a, b = resource.typed(), resource.typed()
									if err := runtime.DefaultUnstructuredConverter.FromUnstructured(old.Object, a); err != nil {
										t.Fatal(err)
									}
									if err := runtime.DefaultUnstructuredConverter.FromUnstructured(next.Object, b); err != nil {
										t.Fatal(err)
									}
								}
								filter := predicates.NewNamespaceFilter(&testLogger{}, []string{"excluded"}, nil)
								want := update.want && namespace != "excluded"
								if got := predicates.GetPredicatesForGVK(resource.gvk, filter).Update(event.UpdateEvent{ObjectOld: a, ObjectNew: b}); got != want {
									t.Errorf("Update() = %v, want %v", got, want)
								}
							})
						}
					}
				})
			}
		}
	}
}
