package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/keda/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var scaledKinds = []struct {
	name   string
	golden string
	object func() client.Object
}{
	{"ScaledObject", "scaledobject_upstream_payload.json", func() client.Object { return &v1alpha1.ScaledObject{} }},
	{"ScaledJob", "scaledjob_upstream_payload.json", func() client.Object { return &v1alpha1.ScaledJob{} }},
}

// TestPayloadMatchesUpstream guards the mirrored types. The golden files were produced
// by KEDA's own types at v2.20.0 with every mirrored field populated, and the agent
// ships this payload verbatim as AssetPayload.Metadata, so a diff here changes what the
// backend receives.
//
// One trap before "fixing" anything: ScaledJobStatus.Paused really does serialize with
// a capital P upstream.
//
// On a version bump regenerate the goldens from the new upstream types, never from the
// mirror, or they stop being independent evidence.
func TestPayloadMatchesUpstream(t *testing.T) {
	for _, kind := range scaledKinds {
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
	for _, kind := range scaledKinds {
		t.Run(kind.name, func(t *testing.T) {
			expected := readGolden(t, kind.golden)

			object := kind.object()
			if err := json.Unmarshal(expected, object); err != nil {
				t.Fatalf("decoding golden payload: %v", err)
			}

			copied, ok := object.DeepCopyObject().(client.Object)
			if !ok {
				t.Fatalf("DeepCopyObject did not return a client.Object")
			}

			actual, err := json.Marshal(copied)
			if err != nil {
				t.Fatalf("marshalling copy: %v", err)
			}
			if string(expected) != string(actual) {
				t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
			}

			// Labels is a map, so a shallow copy would share its backing store.
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
	case *v1alpha1.ScaledObject:
		typed.Spec.Triggers[0].Type = "mutated"
		typed.Spec.Triggers[0].Metadata["topic"] = "mutated"
		typed.Status.Conditions[0].Reason = "mutated"
	case *v1alpha1.ScaledJob:
		typed.Spec.Triggers[0].Type = "mutated"
		typed.Spec.Triggers[0].Metadata["queueName"] = "mutated"
		typed.Spec.ScalingStrategy.PendingPodConditions[0] = "mutated"
	default:
		t.Fatalf("unhandled type %T", object)
	}
}

// TestSchemeRegistration covers startup: a kind missing from the scheme fails the watch
// at runtime, not at compile time.
func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering KEDA types: %v", err)
	}

	objects := []runtime.Object{
		&v1alpha1.ScaledObject{}, &v1alpha1.ScaledObjectList{},
		&v1alpha1.ScaledJob{}, &v1alpha1.ScaledJobList{},
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
