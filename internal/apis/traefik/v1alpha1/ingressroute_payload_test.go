package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/traefik/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const goldenPayload = "ingressroute_upstream_payload.json"

// TestPayloadMatchesUpstream guards the mirrored types. The golden file was produced
// by traefik's own types at v3.6.25 with every mirrored field populated, and the agent
// ships this payload verbatim as AssetPayload.Metadata, so a diff here changes what the
// backend receives.
//
// On a version bump regenerate the golden from the new upstream types, never from the
// mirror, or it stops being independent evidence.
func TestPayloadMatchesUpstream(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", goldenPayload))
	if err != nil {
		t.Fatalf("reading golden payload: %v", err)
	}

	var route v1alpha1.IngressRoute
	if err := json.Unmarshal(expected, &route); err != nil {
		t.Fatalf("decoding golden payload into mirrored type: %v", err)
	}

	actual, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("marshalling mirrored type: %v", err)
	}

	if string(expected) != string(actual) {
		t.Errorf("payload diverged from upstream\nwant: %s\ngot:  %s", expected, actual)
	}
}

// TestDeepCopyPreservesPayload guards the copied deepcopy functions: controller-runtime's
// cache hands the same object to every listener, so a shallow copy would let one
// reconcile mutate another's view.
func TestDeepCopyPreservesPayload(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", goldenPayload))
	if err != nil {
		t.Fatalf("reading golden payload: %v", err)
	}

	var route v1alpha1.IngressRoute
	if err := json.Unmarshal(expected, &route); err != nil {
		t.Fatalf("decoding golden payload: %v", err)
	}

	copied := route.DeepCopy()
	actual, err := json.Marshal(copied)
	if err != nil {
		t.Fatalf("marshalling copy: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
	}

	copied.Spec.Routes[0].Match = "Host(`mutated`)"
	copied.Spec.Routes[0].Services[0].Name = "mutated"
	copied.Spec.TLS.Domains[0].SANs[0] = "mutated"
	copied.Labels["app"] = "mutated"

	unchanged, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("re-marshalling original: %v", err)
	}
	if string(expected) != string(unchanged) {
		t.Errorf("mutating the copy reached the original\nwant: %s\ngot:  %s", expected, unchanged)
	}
}

// TestSchemeRegistration covers startup: a kind missing from the scheme fails the watch
// at runtime, not at compile time.
func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering traefik types: %v", err)
	}

	for _, object := range []runtime.Object{&v1alpha1.IngressRoute{}, &v1alpha1.IngressRouteList{}} {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if got := kinds[0].Group; got != v1alpha1.GroupName {
			t.Errorf("%T registered under group %q, want %q", object, got, v1alpha1.GroupName)
		}
		if got := kinds[0].Version; got != "v1alpha1" {
			t.Errorf("%T registered under version %q, want v1alpha1", object, got)
		}
	}

	// DeepCopyObject has to return the concrete type, not a nil-typed interface.
	original := &v1alpha1.IngressRoute{ObjectMeta: metav1.ObjectMeta{Name: "example"}}
	copied, ok := original.DeepCopyObject().(*v1alpha1.IngressRoute)
	if !ok {
		t.Fatal("DeepCopyObject did not return *IngressRoute")
	}
	if copied.Name != "example" {
		t.Errorf("DeepCopyObject lost the name, got %q", copied.Name)
	}
}
