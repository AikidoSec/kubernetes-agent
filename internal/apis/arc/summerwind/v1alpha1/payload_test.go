package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

const goldenPayload = "runner_upstream_payload.json"

// TestRunnerPayloadMatchesUpstream guards the mirrored Runner type. The golden was
// produced by the upstream type at gha-runner-scale-set-0.14.2, and the agent ships
// this payload verbatim as AssetPayload.Metadata, so a diff here changes what the
// backend receives. On a failure fix the mirrored struct; never edit the golden.
func TestRunnerPayloadMatchesUpstream(t *testing.T) {
	expected := readGolden(t)
	var runner v1alpha1.Runner
	if err := json.Unmarshal(expected, &runner); err != nil {
		t.Fatalf("decoding golden into mirrored type: %v", err)
	}
	actual, err := json.Marshal(runner)
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
	expected := readGolden(t)
	var runner v1alpha1.Runner
	if err := json.Unmarshal(expected, &runner); err != nil {
		t.Fatalf("decoding golden: %v", err)
	}
	copied := runner.DeepCopy()
	actual, err := json.Marshal(copied)
	if err != nil {
		t.Fatalf("marshalling copy: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
	}
	copied.Labels["mutated"] = "true"
	unchanged, err := json.Marshal(runner)
	if err != nil {
		t.Fatalf("re-marshalling original: %v", err)
	}
	if string(expected) != string(unchanged) {
		t.Errorf("mutating the copy reached the original\nwant: %s\ngot:  %s", expected, unchanged)
	}
}

// TestSchemeRegistration covers startup: a kind missing from the scheme fails the
// watch at runtime, not at compile time.
func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering runner types: %v", err)
	}
	for _, object := range []runtime.Object{&v1alpha1.Runner{}, &v1alpha1.RunnerList{}} {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if got := kinds[0].GroupVersion(); got != v1alpha1.SchemeGroupVersion {
			t.Errorf("%T registered under %s, want %s", object, got, v1alpha1.SchemeGroupVersion)
		}
	}
}

func readGolden(t *testing.T) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", goldenPayload))
	if err != nil {
		t.Fatalf("reading golden payload: %v", err)
	}
	return payload
}
