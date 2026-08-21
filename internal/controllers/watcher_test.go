package controllers

import (
	"fmt"
	"testing"

	traefikv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/traefik/v1alpha1"
	"aikidoSec.kubernetesAgent/pkg/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	if err := traefikv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering traefik types: %v", err)
	}
	return scheme
}

func watcherFor(t *testing.T, gvk schema.GroupVersionKind) *Watcher {
	t.Helper()
	return &Watcher{
		Scheme:  testScheme(t),
		Watched: models.WatcherSelector{GroupVersionKind: gvk},
	}
}

// TestGetTypedObjectRegisteredGVK covers the path that must not regress: a kind the
// scheme knows still decodes into its Go type, so its payload stays typed.
func TestGetTypedObjectRegisteredGVK(t *testing.T) {
	cases := []struct {
		name string
		gvk  schema.GroupVersionKind
		want any
	}{
		{"core", schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, &corev1.Pod{}},
		{"vendor CRD", traefikIngressRouteGVK, &traefikv1alpha1.IngressRoute{}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			obj, err := watcherFor(t, testCase.gvk).GetTypedObject()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, isUnstructured := obj.(*unstructured.Unstructured); isUnstructured {
				t.Fatalf("registered GVK fell back to unstructured, losing its typed payload")
			}
			if got, want := fmt.Sprintf("%T", obj), fmt.Sprintf("%T", testCase.want); got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}

// TestGetTypedObjectUnregisteredGVK covers the reported crash. The watched set is
// server-driven, so a GVK the scheme has never heard of is reachable in production; it
// used to panic asserting Scheme.New's nil result to client.Object.
func TestGetTypedObjectUnregisteredGVK(t *testing.T) {
	// A Kong kind the agent has no controller for, and an unrelated third-party CRD.
	for _, gvk := range []schema.GroupVersionKind{
		{Group: "configuration.konghq.com", Version: "v1alpha1", Kind: "KongPluginBinding"},
		{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"},
	} {
		t.Run(gvk.Kind, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("panicked on an unregistered GVK: %v", recovered)
				}
			}()

			obj, err := watcherFor(t, gvk).GetTypedObject()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			unstructuredObj, ok := obj.(*unstructured.Unstructured)
			if !ok {
				t.Fatalf("got %T, want *unstructured.Unstructured", obj)
			}
			if got := unstructuredObj.GroupVersionKind(); got != gvk {
				t.Errorf("fallback carries %s, want %s", got, gvk)
			}
		})
	}
}

var traefikIngressRouteGVK = schema.GroupVersionKind{
	Group:   traefikv1alpha1.GroupName,
	Version: "v1alpha1",
	Kind:    "IngressRoute",
}
