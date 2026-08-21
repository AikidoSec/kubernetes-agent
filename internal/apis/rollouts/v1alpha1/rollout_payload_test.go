package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/rollouts/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const goldenPayload = "rollout_upstream_payload.json"

// TestPayloadMatchesUpstream guards the mirrored types. The golden file was produced by
// argo-rollouts' own types at v1.9.0, filled from a fixed seed with nothing left nil so
// every mirrored field is present, and the agent ships this payload verbatim as
// AssetPayload.Metadata, so a diff here changes what the backend receives.
//
// On a version bump regenerate the golden from the new upstream types, never from the
// mirror, or it stops being independent evidence.
func TestPayloadMatchesUpstream(t *testing.T) {
	expected := readGolden(t)

	var rollout v1alpha1.Rollout
	if err := json.Unmarshal(expected, &rollout); err != nil {
		t.Fatalf("decoding golden payload into mirrored type: %v", err)
	}

	actual, err := json.Marshal(rollout)
	if err != nil {
		t.Fatalf("marshalling mirrored type: %v", err)
	}

	if string(expected) != string(actual) {
		t.Errorf("payload diverged from upstream\nwant: %s\ngot:  %s", expected, actual)
	}
}

// TestGoldenPayloadReachesTheFarCorners guards the golden file itself. It is generated
// rather than hand-written, so a future regeneration that quietly stops populating
// whole subtrees would leave the payload test passing against much weaker evidence.
func TestGoldenPayloadReachesTheFarCorners(t *testing.T) {
	payload := string(readGolden(t))

	// One key from each of the more remote branches of the Rollout closure.
	for _, key := range []string{
		`"traefik"`, `"apisix"`, `"appMesh"`, `"ambassador"`, `"alb"`, `"istio"`,
		`"smi"`, `"nginx"`, `"plugins"`, `"stickinessConfig"`, `"antiAffinity"`,
		`"setMirrorRoute"`, `"setHeaderRoute"`, `"managedRoutes"`, `"pingPong"`,
		`"analysis"`, `"experiment"`, `"rollbackWindow"`, `"blueGreen"`, `"canary"`,
		`"stepPluginStatuses"`, `"measurementRetention"`, `"valueFrom"`,
		// TemplateService serializes under "service", not its type name.
		`"service"`,
	} {
		if !strings.Contains(payload, key) {
			t.Errorf("golden payload never reaches %s; regenerate it with fuller coverage", key)
		}
	}
}

// TestDeepCopyPreservesPayload guards the copied deepcopy functions: controller-runtime's
// cache hands the same object to every listener, so a shallow copy would let one
// reconcile mutate another's view.
func TestDeepCopyPreservesPayload(t *testing.T) {
	expected := readGolden(t)

	var rollout v1alpha1.Rollout
	if err := json.Unmarshal(expected, &rollout); err != nil {
		t.Fatalf("decoding golden payload: %v", err)
	}

	copied := rollout.DeepCopy()
	actual, err := json.Marshal(copied)
	if err != nil {
		t.Fatalf("marshalling copy: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
	}

	copied.Labels["app"] = "mutated"
	copied.Spec.Template.Spec.Containers[0].Image = "mutated"
	if copied.Spec.Strategy.Canary != nil {
		copied.Spec.Strategy.Canary.CanaryService = "mutated"
		if len(copied.Spec.Strategy.Canary.Steps) > 0 {
			copied.Spec.Strategy.Canary.Steps[0].SetWeight = nil
		}
	}
	if len(copied.Status.Conditions) > 0 {
		copied.Status.Conditions[0].Reason = "Mutated"
	}

	unchanged, err := json.Marshal(rollout)
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
		t.Fatalf("registering rollout types: %v", err)
	}

	for _, object := range []runtime.Object{&v1alpha1.Rollout{}, &v1alpha1.RolloutList{}} {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if got := kinds[0].GroupVersion(); got != v1alpha1.SchemeGroupVersion {
			t.Errorf("%T registered under %s, want %s", object, got, v1alpha1.SchemeGroupVersion)
		}
	}

	original := &v1alpha1.Rollout{ObjectMeta: metav1.ObjectMeta{Name: "example"}}
	copied, ok := original.DeepCopyObject().(*v1alpha1.Rollout)
	if !ok {
		t.Fatal("DeepCopyObject did not return *Rollout")
	}
	if copied.Name != "example" {
		t.Errorf("DeepCopyObject lost the name, got %q", copied.Name)
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
