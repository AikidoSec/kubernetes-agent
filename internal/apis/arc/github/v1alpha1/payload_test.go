package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

// roundTrip guards a mirrored kind: the golden was produced by the upstream type
// at gha-runner-scale-set-0.14.2 and the agent ships it verbatim as
// AssetPayload.Metadata, so a diff here changes what the backend receives. On a
// failure fix the mirrored struct to match upstream; never edit the golden.
func roundTrip[T any](t *testing.T, golden string, obj *T) {
	t.Helper()
	expected := readGolden(t, golden)

	if err := json.Unmarshal(expected, obj); err != nil {
		t.Fatalf("decoding golden into mirrored type: %v", err)
	}
	actual, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshalling mirrored type: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("payload diverged from upstream\nwant: %s\ngot:  %s", expected, actual)
	}
}

func TestEphemeralRunnerPayloadMatchesUpstream(t *testing.T) {
	roundTrip(t, "ephemeralrunner_upstream_payload.json", &v1alpha1.EphemeralRunner{})
}

func TestAutoscalingListenerPayloadMatchesUpstream(t *testing.T) {
	roundTrip(t, "autoscalinglistener_upstream_payload.json", &v1alpha1.AutoscalingListener{})
}

// TestSchemeRegistration covers startup: a kind missing from the scheme fails the
// watch at runtime, not at compile time.
func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering arc github types: %v", err)
	}
	for _, object := range []runtime.Object{
		&v1alpha1.EphemeralRunner{}, &v1alpha1.EphemeralRunnerList{},
		&v1alpha1.AutoscalingListener{}, &v1alpha1.AutoscalingListenerList{},
	} {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if got := kinds[0].GroupVersion(); got != v1alpha1.SchemeGroupVersion {
			t.Errorf("%T registered under %s, want %s", object, got, v1alpha1.SchemeGroupVersion)
		}
	}
}

// TestDeepCopyPreservesPayload guards the copied deepcopy functions:
// controller-runtime's cache hands the same object to every listener, so a shallow
// copy would let one reconcile mutate another's view.
func TestDeepCopyPreservesPayload(t *testing.T) {
	expected := readGolden(t, "ephemeralrunner_upstream_payload.json")
	var er v1alpha1.EphemeralRunner
	if err := json.Unmarshal(expected, &er); err != nil {
		t.Fatalf("decoding golden: %v", err)
	}
	copied := er.DeepCopy()
	actual, err := json.Marshal(copied)
	if err != nil {
		t.Fatalf("marshalling copy: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
	}
	copied.Labels["mutated"] = "true"
	unchanged, err := json.Marshal(&er)
	if err != nil {
		t.Fatalf("re-marshalling original: %v", err)
	}
	if string(expected) != string(unchanged) {
		t.Errorf("mutating the copy reached the original\nwant: %s\ngot:  %s", expected, unchanged)
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
