package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/kong/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var kongKinds = []struct {
	name   string
	golden string
	object func() client.Object
}{
	{"KongRoute", "kongroute_upstream_payload.json", func() client.Object { return &v1alpha1.KongRoute{} }},
	{"KongService", "kongservice_upstream_payload.json", func() client.Object { return &v1alpha1.KongService{} }},
}

// TestPayloadMatchesUpstream guards the mirrored types. The golden files were produced
// by Kong's own types at kubernetes-configuration v2.0.1 and sdk-konnect-go v0.9.1 with
// every mirrored field populated, and the agent ships this payload verbatim as
// AssetPayload.Metadata, so a diff here changes what the backend receives.
//
// Two traps before "fixing" anything: the Kong API fields are snake_case, unlike the
// Kubernetes-side fields around them; and Destinations/Sources ip and port carry no
// omitempty, so they serialize as explicit nulls.
//
// On a version bump regenerate the goldens from the new upstream types, never from the
// mirror, or they stop being independent evidence.
func TestPayloadMatchesUpstream(t *testing.T) {
	for _, kind := range kongKinds {
		t.Run(kind.name, func(t *testing.T) {
			expected := readGolden(t, kind.golden)

			object := kind.object()
			if err := json.Unmarshal(expected, object); err != nil {
				t.Fatalf("decoding golden payload into mirrored type: %v", err)
			}

			actual, err := json.Marshal(object)
			if err != nil {
				t.Fatalf("marshalling mirrored type: %v", err)
			}

			if string(expected) != string(actual) {
				t.Errorf("payload diverged from upstream\nwant: %s\ngot:  %s", expected, actual)
			}
		})
	}
}

// TestDeepCopyPreservesPayload guards the copied deepcopy functions: controller-runtime's
// cache hands the same object to every listener, so a shallow copy would let one
// reconcile mutate another's view.
func TestDeepCopyPreservesPayload(t *testing.T) {
	for _, kind := range kongKinds {
		t.Run(kind.name, func(t *testing.T) {
			expected := readGolden(t, kind.golden)

			object := kind.object()
			if err := json.Unmarshal(expected, object); err != nil {
				t.Fatalf("decoding golden payload: %v", err)
			}

			copied, ok := object.DeepCopyObject().(client.Object)
			if !ok {
				t.Fatal("DeepCopyObject did not return a client.Object")
			}

			actual, err := json.Marshal(copied)
			if err != nil {
				t.Fatalf("marshalling copy: %v", err)
			}
			if string(expected) != string(actual) {
				t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
			}

			copied.SetLabels(map[string]string{"app": "mutated"})
			mutateSpec(t, copied)

			unchanged, err := json.Marshal(object)
			if err != nil {
				t.Fatalf("re-marshalling original: %v", err)
			}
			if string(expected) != string(unchanged) {
				t.Errorf("mutating the copy reached the original\nwant: %s\ngot:  %s", expected, unchanged)
			}
		})
	}
}

// mutateSpec touches the parts of each spec a shallow copy would share.
func mutateSpec(t *testing.T, object client.Object) {
	t.Helper()
	switch typed := object.(type) {
	case *v1alpha1.KongRoute:
		typed.Spec.Hosts[0] = "mutated"
		typed.Spec.Headers["x-tenant"][0] = "mutated"
		typed.Spec.Tags[0] = "mutated"
		typed.Spec.ControlPlaneRef.KonnectNamespacedRef.Name = "mutated"
		typed.Spec.ServiceRef.NamespacedRef.Name = "mutated"
		typed.Status.Konnect.ControlPlaneID = "mutated"
		typed.Status.Conditions[0].Reason = "Mutated"
	case *v1alpha1.KongService:
		typed.Spec.Tags[0] = "mutated"
		typed.Spec.ControlPlaneRef.KonnectNamespacedRef.Name = "mutated"
		typed.Status.Konnect.ControlPlaneID = "mutated"
		typed.Status.Conditions[0].Reason = "Mutated"
	default:
		t.Fatalf("unhandled type %T", object)
	}
}

// TestUnknownEnumValuesAreForwarded pins the deviation described in doc.go: upstream
// would fail the whole decode here.
func TestUnknownEnumValuesAreForwarded(t *testing.T) {
	var spec v1alpha1.KongRouteAPISpec
	if err := json.Unmarshal([]byte(`{"protocols":["http","grpc-web"],"path_handling":"v2"}`), &spec); err != nil {
		t.Fatalf("decoding unknown enum values: %v", err)
	}

	if len(spec.Protocols) != 2 || spec.Protocols[1] != "grpc-web" {
		t.Errorf("unknown protocol not forwarded, got %v", spec.Protocols)
	}
	if spec.PathHandling == nil || *spec.PathHandling != "v2" {
		t.Errorf("unknown path handling not forwarded, got %v", spec.PathHandling)
	}
}

// TestSchemeRegistration covers startup: a kind missing from the scheme fails the watch
// at runtime, not at compile time.
func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering Kong types: %v", err)
	}

	objects := []runtime.Object{
		&v1alpha1.KongRoute{}, &v1alpha1.KongRouteList{},
		&v1alpha1.KongService{}, &v1alpha1.KongServiceList{},
	}
	for _, object := range objects {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if got := kinds[0].GroupVersion(); got != v1alpha1.GroupVersion {
			t.Errorf("%T registered under %s, want %s", object, got, v1alpha1.GroupVersion)
		}
	}
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading golden payload: %v", err)
	}
	return payload
}
